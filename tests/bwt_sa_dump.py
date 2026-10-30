#!/usr/bin/env python3
"""Dump the vendor's suffix array from inside its BWT sort.

The vendor's sorter (`sbc.exe`, `0x4225c0` -> `0x421ac0` -> `0x423010`) is not
a canonical rotation sort: it skips any segment whose elements all share the
same *preceding* byte (the BWT column cannot change), so its SA is only
"L-equivalent", not unique.  The primary, however, is a slot in that SA, so
reproducing the tie order means reproducing the sort -- and that needs ground
truth, not guesses.

This tool runs the vendor encoder under ``winedbg`` with two breakpoints:

* ``0x4225c0`` -- records the sorter's buffer and SA pointer;
* ``0x41fb23`` -- the instruction after its single call site: dumps the final
  SA (``<out>/sa.bin``, little-endian u32) and the exact buffer that was sorted
  (``<out>/in.bin``; it is the raw file for unfiltered inputs).

It then prints the bucket layout and, if rotation 0 has an equal class, the
offsets the vendor left its members at -- the numbers the encoder has to match.

Usage: python3 tools/bwt_sa_dump.py FILE [--level m1] [--out DIR] [--keep]
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "sbc.exe")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

GDB = """\
set pagination off
set confirm off
set height 0
set width 0
break *0x4225c0
commands
silent
set $buf = *(unsigned int*)($esp+4)
set $sa  = *(unsigned int*)($esp+8)
set $n   = *(unsigned int*)($esp+12)
printf "SORT buf=%p sa=%p n=%u\\n", $buf, $sa, $n
continue
end
break *0x41fb23
commands
silent
dump binary memory @SA@ $sa $sa+4*$n
dump binary memory @IN@ $buf $buf+$n
printf "DUMPED n=%u\\n", $n
continue
end
continue
"""

WRAPPER = """\
#!/bin/sh
tmp=""; prev=""
for a in "$@"; do
  [ "$prev" = "-x" ] && tmp="$a"
  prev="$a"
done
out=@CMD@
: > "$out"
[ -n "$tmp" ] && [ -f "$tmp" ] && cat "$tmp" >> "$out"
cat @SCRIPT@ >> "$out"
exec /usr/bin/gdb -q -x "$out"
"""


def winpath(path):
    return "Z:" + os.path.abspath(path).replace("/", "\\")


def dump(src, level, work):
    sa = os.path.join(work, "sa.bin")
    ib = os.path.join(work, "in.bin")
    script = os.path.join(work, "t.gdb")
    with open(script, "w") as f:
        f.write(GDB.replace("@SA@", sa).replace("@IN@", ib))
    wrap = os.path.join(work, "wrap")
    os.makedirs(wrap, exist_ok=True)
    gdb = os.path.join(wrap, "gdb")
    with open(gdb, "w") as f:
        f.write(WRAPPER.replace("@CMD@", os.path.join(work, "cmd.txt"))
                .replace("@SCRIPT@", script))
    os.chmod(gdb, 0o755)
    name = os.path.basename(src)
    dst = os.path.join(work, name)
    if os.path.abspath(src) != os.path.abspath(dst):
        shutil.copy(src, dst)
    env = dict(os.environ, WINEPREFIX=WINEPREFIX, WINEDEBUG="-all",
               PATH=wrap + ":" + os.environ.get("PATH", ""))
    arc = os.path.join(work, "o.sbc")
    if os.path.exists(arc):
        os.remove(arc)
    try:
        run = subprocess.run(
            ["winedbg", "--gdb", VENDOR, "c", winpath(arc), "-m" + level,
             winpath(dst)],
            cwd=work, env=env, capture_output=True, stdin=subprocess.DEVNULL,
            timeout=240)
    except subprocess.TimeoutExpired:
        print("vendor run timed out")
        return None
    out = (run.stdout or b"").decode(errors="replace")
    if not (os.path.exists(sa) and os.path.exists(ib)):
        sys.stdout.write(out[-2000:])
        return None
    return open(ib, "rb").read(), open(sa, "rb").read()


def report(buf, raw):
    n = len(buf)
    sa = list(struct.unpack("<%dI" % n, raw[:4 * n]))

    def key(p, d):
        return buf[(p + d) % n]

    cls = [p for p in range(n) if all(key(p, k) == key(0, k) for k in range(n))]
    rank0 = sa.index(0)
    base = min(sa.index(p) for p in cls)
    print("n=%d  sa=%d entries  rank(0)=%d  class=%d at %d..%d  offset=%d"
          % (n, len(sa), rank0, len(cls), base, base + len(cls) - 1,
             rank0 - base))
    runs = []
    i = 0
    while i < n:
        j = i + 1
        while j < n and buf[sa[j]] == buf[sa[i]]:
            j += 1
        runs.append((buf[sa[i]], i, j - i))
        i = j
    print("buckets (byte, start, size):")
    for c, start, size in runs:
        print("  %3d %-6r start=%3d size=%3d" %
              (c, chr(c) if 32 <= c < 127 else ".", start, size))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--level", default="1")
    ap.add_argument("--out", default="")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(VENDOR):
        print("sbc.exe not found")
        return 2
    work = a.out or tempfile.mkdtemp(prefix="bwtsa-")
    os.makedirs(work, exist_ok=True)
    try:
        got = dump(a.file, a.level, work)
        if got is None:
            print("dump failed")
            return 1
        buf, raw = got
        report(buf, raw)
        if a.out or a.keep:
            print("work dir:", work)
        return 0
    finally:
        if not (a.out or a.keep):
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
