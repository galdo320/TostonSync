#!/usr/bin/env python3
"""Audit x86-64 ELF syscall successors using LLVM disassembly, without execution.

Each direct jump target starts another basic block, carrying the still-undefined
bits into that block. Resetting them at a target would miss the success branch.
Calls/returns end a path; this is not an interprocedural or spill-taint analysis.
Unknown instructions fail closed. RDX is conservatively checked even when an
inline source declaration names it as output; no per-number exemption is safe.
"""
import argparse
from collections import deque
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WATCH = ('r8', 'r9', 'r10', 'rdx')
FULL = (1 << 64) - 1
ALIASES = {}
for base in WATCH:
    for suffix, bits in (('', 64), ('d', 32), ('w', 16), ('b', 8)):
        name = base + suffix if base != 'rdx' else {64:'rdx',32:'edx',16:'dx',8:'dl'}[bits]
        ALIASES[name] = (base, (1 << bits) - 1, FULL if bits >= 32 else (1 << bits) - 1)
ALIASES['dh'] = ('rdx', 0xff00, 0xff00)
REG = re.compile(r'\b(?:' + '|'.join(ALIASES) + r')\b')

@dataclass(frozen=True)
class Instruction:
    address: int
    function: str
    mnemonic: str
    operands: str


def parse(text):
    instructions = {}; function = None
    for line in text.splitlines():
        symbol = re.match(r'^([0-9a-fA-F]+) <(.+)>:$', line)
        if symbol:
            function = symbol[2]; continue
        match = re.match(r'^\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*?)\s*$', line)
        if not match or function is None:
            continue
        mnemonic, operands = match[2], match[3].split('#', 1)[0].strip()
        while mnemonic in ('addr32','data16','lock','rep','repz','repnz'):
            parts = operands.split(None, 1)
            if not parts: break
            mnemonic, operands = parts[0], parts[1] if len(parts) > 1 else ''
        address = int(match[1], 16)
        if address in instructions:
            raise ValueError('duplicate instruction address')
        instructions[address] = Instruction(address, function, mnemonic, operands)
    if not instructions:
        raise ValueError('empty or unrecognized LLVM disassembly')
    return instructions


def accesses(ins):
    """Return read/write bit masks only for the four watched register families."""
    reads, writes = {}, {}
    operands = [p.strip() for p in ins.operands.split(',')] if ins.operands else []
    op = ins.mnemonic
    def read(value):
        for name in REG.findall(value):
            base, mask, _ = ALIASES[name]; reads[base] = reads.get(base, 0) | mask
    def write(value):
        if value in ALIASES:
            base, _, mask = ALIASES[value]; writes[base] = writes.get(base, 0) | mask
        else:
            read(value)  # Store address, never a definition of its base register.
    if op in ('cdq','cqo','cwd'):
        write({'cdq':'edx','cqo':'rdx','cwd':'dx'}[op])
    elif op in ('mul','div','idiv') or (op == 'imul' and len(operands) == 1):
        for value in operands: read(value)
        value = operands[0] if operands else ''
        width = 8 if re.search(r'\bbyte ptr\b|^(?:[abcd]l|[abcd]h|sil|dil|spl|bpl|r\d+b)$',value) else 16 if re.search(r'(?<!d)(?<!q)\bword ptr\b|^(?:[abcd]x|si|di|sp|bp|r\d+w)$',value) else 32 if re.search(r'\bdword ptr\b|^(?:e[a-z]{2}|r\d+d)$',value) else 64
        if width >= 16:
            pair = {16:'dx',32:'edx',64:'rdx'}[width]
            if op in ('div','idiv'): read(pair)
            write(pair)
    elif op == 'imul' and len(operands) == 3:
        write(operands[0])
        for value in operands[1:]: read(value)
    elif op in ('cmpxchg8b','cmpxchg16b'):
        pair = 'edx' if op == 'cmpxchg8b' else 'rdx'
        read(pair); write(pair)
        for value in operands: read(value)
    elif op.startswith(('xsave','xrstor')) or op == 'xsetbv':
        read('edx')
        for value in operands: read(value)
    elif op in ('rdtsc','rdtscp','cpuid','xgetbv'):
        write('edx')
    elif op in ('vpxor','vxorps','vpor','vptest','vpcmpeqd','vpmovsxdq'):
        for value in operands: read(value)
    elif op in ('mov','movabs','movbe','movsx','movsxd','movzx','lea',
                'vmovapd','vmovaps','vmovd','vmovddup','vmovdqa','vmovdqu',
                'vmovlpd','vmovlps','vmovmskpd','vmovmskps','vmovq','vmovsd',
                'vmovss','vmovupd','vmovups'):
        if operands:
            write(operands[0])
            for value in operands[1:]: read(value)
    elif op.startswith('set') or op == 'pop':
        for value in operands: write(value)
    elif op.startswith('cmov'):
        # A conditional definition cannot kill a value on the untaken path.
        for value in operands[1:]: read(value)
        if operands and operands[0] not in ALIASES: read(operands[0])
    elif op in ('xor','sub') and len(operands) == 2 and operands[0] == operands[1] and operands[0] in ALIASES:
        write(operands[0])
    elif op in ('add','adc','sub','sbb','and','or','xor','shl','shr','sar','sal','rol','ror','rcl','rcr','inc','dec','neg','not','bswap','bts','btr','btc','xchg','xadd') or op == 'imul':
        for value in operands: read(value)
        if operands: write(operands[0])
        if op in ('xchg','xadd') and len(operands) > 1: write(operands[1])
    elif op in ('cmp','test','bt','push') or op.startswith(('j','call','loop')):
        for value in operands: read(value)
    elif op.startswith(('nop','ret')) or op in ('syscall','vzeroupper','int3','ud2','endbr64','clc','stc','cld','std','leave','cbw','cwde','cdqe','lahf'):
        pass
    else:
        raise ValueError(f'unsupported instruction at {ins.address:#x}: {op} {ins.operands}')
    return reads, writes


def syscall_number(instructions, index, addresses, targets):
    """Only accept a local immediate RAX definition; otherwise report unknown."""
    ins = instructions[addresses[index]]
    if ins.address in targets: return None
    for address in reversed(addresses[max(0,index-16):index]):
        prev = instructions[address]
        if prev.function != ins.function or prev.mnemonic.startswith(('call','ret','j')) or prev.mnemonic == 'syscall':
            return None
        if re.search(r'\b(?:rax|eax|ax|al|ah)\b', prev.operands):
            found = re.fullmatch(r'(?:rax|eax), (0x[0-9a-f]+|[0-9]+)', prev.operands)
            return int(found[1],0) if prev.mnemonic in ('mov','movabs') and found else None
        if address in targets or prev.mnemonic in ('cbw','cwde','cdqe','lahf','mul','imul','div','idiv','cpuid','rdtsc','rdtscp','xgetbv','cmpxchg','cmpxchg8b','cmpxchg16b','lods','lodsb','lodsw','lodsd','lodsq'):
            return None
    return None


def audit(instructions):
    addresses = sorted(instructions); following = dict(zip(addresses, addresses[1:])); sites = []; errors = []
    targets = {int(m[1],16) for ins in instructions.values() if ins.mnemonic.startswith(('j','loop'))
               for m in [re.match(r'0x([0-9a-f]+)(?:\s|$)',ins.operands)] if m}
    for index, address in enumerate(addresses):
        ins = instructions[address]
        if ins.mnemonic != 'syscall': continue
        number = syscall_number(instructions,index,addresses,targets)
        initial = (FULL,) * len(WATCH)
        queue = deque([(following.get(address), initial)]); seen = set(); findings = set(); boundaries = set()
        while queue:
            pc, masks = queue.popleft()
            if pc is None or (pc,masks) in seen or not any(masks): continue
            seen.add((pc,masks)); current = instructions[pc]
            if current.function != ins.function:
                errors.append(f'cross-symbol syscall successor {pc:#x} from {address:#x}'); continue
            try: reads,writes = accesses(current)
            except ValueError as error:
                errors.append(str(error)); continue
            for reg,mask in zip(WATCH,masks):
                if mask & reads.get(reg,0): findings.add((reg,pc,current.mnemonic+' '+current.operands))
            masks = tuple(mask & ~writes.get(reg,0) for reg,mask in zip(WATCH,masks))
            op = current.mnemonic
            if op.startswith(('call','ret')) or op in ('syscall','int3','ud2'):
                boundaries.add(pc); continue
            target = re.match(r'0x([0-9a-f]+)(?:\s|$)',current.operands)
            if op.startswith(('j','loop')):
                if target:
                    dest = int(target[1],16)
                    if dest in instructions: queue.append((dest,masks))
                    else: errors.append(f'unresolved direct jump target {dest:#x}')
                else: errors.append(f'unresolved branch {pc:#x}')
                if op == 'jmp': continue
            queue.append((following.get(pc),masks))
        sites.append({'syscall':hex(address),'function':ins.function,'number':number,
                      'reads':[{'register':reg,'address':hex(pc),'instruction':text} for reg,pc,text in sorted(findings)],
                      'boundary_count':len(boundaries)})
    if not sites: errors.append('ELF contains no syscall instructions')
    bad = [site for site in sites if site['reads']]
    return {'result':'FAIL' if bad or errors else 'PASS','syscall_count':len(sites),'flagged_site_count':len(bad),
            'flagged_sites':bad,'sites':sites,'errors':sorted(set(errors)),
            'scope':'Direct branch successors and joins until call/ret/next syscall; RDX always checked, no source-declaration exemptions; no interprocedural or spill-taint claim'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf',type=Path); parser.add_argument('--objdump')
    parser.add_argument('--report',type=Path)
    args = parser.parse_args()
    tool = args.objdump or shutil.which('llvm-objdump')
    if not tool: tool = subprocess.check_output(['xcrun','--find','llvm-objdump'],text=True).strip()
    data = args.elf.read_bytes()
    if data[:5] != b'\x7fELF\x02' or data[18:20] != b'\x3e\x00': raise ValueError('expected x86-64 ELF')
    text = subprocess.check_output([tool,'-d','--no-show-raw-insn','--x86-asm-syntax=intel',str(args.elf)],text=True)
    report = audit(parse(text))
    report.update(elf={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()},
                  disassembly_sha256=hashlib.sha256(text.encode()).hexdigest())
    if args.report:
        with args.report.open('x') as file: json.dump(report,file,indent=2);file.write('\n')
    print(json.dumps({key:report[key] for key in ('result','syscall_count','flagged_site_count','flagged_sites','errors')},indent=2))
    return 1 if report['result'] != 'PASS' else 0

if __name__ == '__main__':
    raise SystemExit(main())
