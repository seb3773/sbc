#!/usr/bin/env python3
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import rdis

data = rdis.data
md = Cs(CS_ARCH_X86, CS_MODE_32)

targets = {}
for a in sys.argv[1:]:
    targets[int(a, 16)] = []

name, sva, vsz, raw, rsz = rdis.secs[0]
text = data[raw:raw+rsz]
for ins in md.disasm(text, sva):
    if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
        try:
            t = int(ins.op_str, 16)
        except ValueError:
            continue
        if t in targets:
            targets[t].append(ins.address)

for t, cs in targets.items():
    print("0x%08x <- %s" % (t, " ".join("0x%08x" % c for c in cs)))
