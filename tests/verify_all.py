#!/usr/bin/env python3
"""Extract every packed_corpus/*.sbc with the C decoder and diff against corpus/.

Usage: python3 tools/verify_all.py [path/to/decoder]
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "sbc"
PACKED = ROOT / "packed_corpus"
CORPUS = ROOT / "corpus"


def expected_files(stem):
    """Return {relpath: bytes} expected for an archive, read from corpus/."""
    src = stem.split("-m")[0]
    if src == "nested":
        base = CORPUS / "nested"
        out = {}
        for p in sorted(base.rglob("*")):
            if p.is_file():
                # nested archives store the root directory name in the entries
                out["nested/" + str(p.relative_to(base))] = p.read_bytes()
        return out
    names = {
        "hello": "hello.txt",
        "empty": "empty.dat",
        "pattern": "pattern.bin",
        "records": "records.bin",
        "image": "image.raw",
        "image24": "image24.raw",
        "image7": "image7.raw",
        "biased": "biased.bin",
        "zeros": "zeros.bin",
        "code": "code.c",
        "random": "random.bin",
        "mixed": "mixed.bin",
        "eng": "eng.txt",
    }
    return {names[src]: (CORPUS / names[src]).read_bytes()}


def main():
    ok = bad = skip = 0
    for arc in sorted(PACKED.glob("*.sbc")):
        stem = arc.stem
        want = expected_files(stem)
        tmp = Path(tempfile.mkdtemp(prefix="sbcx-"))
        try:
            r = subprocess.run([str(BIN), str(arc), str(tmp)],
                               capture_output=True)
            got = {}
            for p in tmp.rglob("*"):
                if p.is_file():
                    got[str(p.relative_to(tmp))] = p.read_bytes()
            okc = r.returncode == 0 and got == want
            detail = ""
            if not okc:
                if r.returncode != 0:
                    detail = "exit=%d" % r.returncode
                else:
                    missing = sorted(set(want) - set(got))
                    extra = sorted(set(got) - set(want))
                    diffs = [k for k in want if k in got and want[k] != got[k]]
                    detail = "missing=%s extra=%s diff=%s" % (
                        missing, extra, [(k, len(want[k]), len(got[k]))
                                         for k in diffs])
            if okc:
                ok += 1
                print("OK    %-22s %d file(s)" % (arc.name, len(want)))
            else:
                bad += 1
                print("FAIL  %-22s %s" % (arc.name, detail))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d OK, %d FAIL, %d skipped" % (ok, bad, skip))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
