#!/usr/bin/env python3
"""Limited, self-contained public tests. This is not the private release gate suite."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
for name,args in (("check_security272.py",["--mutants"]),("check_support272.py",["--mutants"]),("check_config_persistence.py",[]),("check_payload_runtime.py",[]),("test_syscall_registers.py",[])):
    subprocess.run([sys.executable,str(ROOT/"tests"/name),*args],cwd=ROOT,check=True)
print("PASS public test subset; no physical or full-release gate claim")
