#!/usr/bin/env python3
"""Control-flow and subregister regressions for the offline LLVM ELF guard."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from check_syscall_registers import audit, parse


def report(body):
    return audit(parse('0000000000000100 <sample>:\n'+body))


def reads(result):
    return {(r['register'],r['address']) for site in result['flagged_sites'] for r in site['reads']}


class SyscallRegisterGuard(unittest.TestCase):
    def test_all_registers_and_widths(self):
        for reg in ('r8','r8d','r8w','r8b','r9','r10','rdx','edx','dx','dl','dh'):
            with self.subTest(reg=reg):self.assertTrue(report(f'100: syscall\n102: test {reg}, {reg}\n105: ret')['flagged_sites'])

    def test_full_definitions_kill(self):
        for reg in ('r8','r8d','r9d','r10d','edx'):
            family='rdx' if reg=='edx' else reg.rstrip('d')
            with self.subTest(reg=reg):self.assertEqual(report(f'100: syscall\n102: mov {reg}, 1\n108: test {family}, {family}\n10c: ret')['result'],'PASS')

    def test_partial_definition_does_not_kill_high_bits(self):
        self.assertIn(('rdx','0x108'),reads(report('100: syscall\n102: setae dl\n105: test dl, dl\n108: test rdx, rdx\n10b: ret')))
        self.assertNotIn(('rdx','0x105'),reads(report('100: syscall\n102: setae dl\n105: test dl, dl\n108: ret')))

    def test_zero_idiom(self):
        for op in ('xor','sub'):
            self.assertEqual(report(f'100: syscall\n102: {op} r8d, r8d\n106: test r8, r8\n109: ret')['result'],'PASS')

    def test_memory_and_store_addresses_are_reads(self):
        for text in ('mov eax, dword ptr [r8 + r9*4]','mov dword ptr [r8], eax','lea rax, [r8 + 1]'):
            self.assertIn(('r8','0x102'),reads(report('100: syscall\n102: '+text+'\n109: ret')))

    def test_read_modify_write(self):
        self.assertIn(('r10','0x102'),reads(report('100: syscall\n102: inc r10\n105: ret')))

    def test_conditional_definition_cannot_kill(self):
        self.assertIn(('r8','0x106'),reads(report('100: syscall\n102: cmove r8, rax\n106: test r8, r8\n109: ret')))

    def test_branch_success_does_not_reset_live_registers(self):
        body='''79a0: mov eax, 0xbd
79a2: syscall
79a4: mov r13, rax
79a7: jae 0x79bd <sample+0x1d>
79a9: mov r15d, r9d
79af: call rax
79b5: mov r9d, r15d
79bb: jmp 0x7a02 <sample+0x62>
79bd: test r13d, r13d
79c0: jne 0x7a02 <sample+0x62>
79c2: mov rax, qword ptr [rbp - 0x150]
79c9: cmp rax, r10
7a02: ret'''
        self.assertIn(('r10','0x79c9'),reads(report(body)))
        self.assertIn(('r9','0x79a9'),reads(report(body)))

    def test_join_preserves_undefined_path(self):
        body='100: syscall\n102: je 0x110 <sample+0x10>\n104: mov r8d, 0\n109: jmp 0x114 <sample+0x14>\n110: nop\n114: test r8, r8\n117: ret'
        self.assertIn(('r8','0x114'),reads(report(body)))

    def test_loop_terminates(self):
        x=report('100: syscall\n102: test r8, r8\n106: jne 0x102 <sample+2>\n108: ret')
        self.assertEqual(len(x['flagged_sites'][0]['reads']),1)

    def test_call_and_return_boundaries(self):
        for boundary in ('call 0x200 <external>','ret'):
            self.assertEqual(report('100: syscall\n102: '+boundary+'\n107: test r8, r8\n10a: ret')['result'],'PASS')
        self.assertIn(('r8','0x102'),reads(report('100: syscall\n102: call r8\n105: ret')))

    def test_rdx_is_always_checked(self):
        body='100: mov eax, 0xbd\n105: syscall\n107: mov rax, rdx\n10b: ret'
        self.assertEqual(report(body)['result'],'FAIL')

    def test_implicit_rdx_reads(self):
        for op in ('cmpxchg16b xmmword ptr [rdi]','cmpxchg8b qword ptr [rdi]','xsave ptr [rdi]','xrstor ptr [rdi]','xsetbv'):
            with self.subTest(op=op):self.assertIn(('rdx','0x102'),reads(report('100: syscall\n102: '+op+'\n108: ret')))

    def test_multiply_does_not_read_high_accumulator(self):
        for op in ('mul rcx','imul rcx','imul r8, rcx, 3'):
            with self.subTest(op=op):self.assertEqual(report('100: syscall\n102: '+op+'\n108: ret')['result'],'PASS')

    def test_partial_multiply_keeps_upper_rdx_undefined(self):
        for reg in ('al','ah','bl','bh','cl','ch','dl','dh','sil','dil','spl','bpl','r8b',
                    'ax','bx','cx','dx','si','di','sp','bp','r8w'):
            with self.subTest(reg=reg):
                self.assertIn(('rdx','0x108'),reads(report('100: syscall\n102: mul '+reg+'\n108: mov rax, rdx\n10b: ret')))

    def test_byte_division_does_not_read_rdx(self):
        self.assertEqual(report('100: syscall\n102: div cl\n108: ret')['result'],'PASS')

    def test_vector_memory_address_is_read(self):
        for op in ('vpxor','vpor'):
            self.assertIn(('r8','0x102'),reads(report('100: syscall\n102: '+op+' ymm0, ymm1, ymmword ptr [r8]\n108: ret')))

    def test_vector_compare_preserves_gpr_taint(self):
        self.assertEqual(report('100: syscall\n102: vpcmpeqd xmm0, xmm0, xmm1\n108: ret')['result'],'PASS')
        self.assertIn(('r10','0x108'),reads(report('100: syscall\n102: vpcmpeqd xmm0, xmm0, xmm1\n108: test r10, r10\n10c: ret')))
        self.assertIn(('r8','0x102'),reads(report('100: syscall\n102: vpcmpeqd xmm0, xmm1, xmmword ptr [r8]\n108: ret')))
        self.assertEqual(report('100: syscall\n102: vpmovsxdq xmm0, xmm0\n108: ret')['result'],'PASS')
        self.assertIn(('r9','0x102'),reads(report('100: syscall\n102: vpmovsxdq xmm0, qword ptr [r9]\n108: ret')))

    def test_unproven_syscall_number_does_not_exempt(self):
        for body in ('100: mov eax, 0xbd\n105: mov ah, 1\n107: syscall\n109: mov rax, rdx\n10c: ret',
                     '100: mov eax, 0xbd\n105: xchg ecx, eax\n107: syscall\n109: mov rax, rdx\n10c: ret',
                     '100: mov eax, 1\n105: jmp 0x10c <sample+0xc>\n107: mov eax, 0xbd\n10c: syscall\n10e: mov rax, rdx\n112: ret'):
            x=report(body);self.assertEqual(x['result'],'FAIL');self.assertIsNone(x['sites'][0]['number'])

    def test_rax_only_conversion_preserves_watched_taint(self):
        for op in ('cbw','cwde','cdqe','lahf'):
            x=report('100: syscall\n102: '+op+'\n104: mov rax, r8\n108: ret')
            self.assertFalse(x['errors']);self.assertIn(('r8','0x104'),reads(x))

    def test_implicit_rax_conversion_invalidates_number(self):
        for op in ('cbw','cwde','cdqe','lahf'):
            self.assertIsNone(report('100: mov eax, 0xbd\n105: '+op+'\n107: syscall\n109: ret')['sites'][0]['number'])

    def test_implicit_pair(self):
        self.assertIn(('rdx','0x102'),reads(report('100: syscall\n102: div rbx\n105: ret')))
        self.assertEqual(report('100: syscall\n102: cqo\n104: test rdx, rdx\n107: ret')['result'],'PASS')

    def test_unsupported_watched_instruction_fails_closed(self):
        x=report('100: syscall\n102: unknown_opcode r8\n106: ret')
        self.assertEqual(x['result'],'FAIL');self.assertTrue(x['errors'])
        self.assertTrue(report('100: syscall\n102: unknown_opcode [rdi]\n106: ret')['errors'])

    def test_unknown_move_is_not_a_definition(self):
        x=report('100: syscall\n102: movdir64b r8, [rdi]\n108: ret')
        self.assertEqual(x['result'],'FAIL');self.assertTrue(x['errors'])

    def test_unresolved_and_cross_symbol_branches_fail_closed(self):
        self.assertTrue(report('100: syscall\n102: jmp rax')['errors'])
        x=report('100: syscall\n102: jmp 0x200 <other>\n0000000000000200 <other>:\n200: test r8, r8\n203: ret')
        self.assertEqual(x['result'],'FAIL');self.assertTrue(x['errors'])

    def test_standalone_llvm_prefix(self):
        self.assertEqual(report('100: syscall\n102: ret\n103: data16')['result'],'PASS')

if __name__=='__main__':unittest.main()
