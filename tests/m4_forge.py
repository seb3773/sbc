#!/usr/bin/env python3
"""Forged mode-4 records: drive every branch of unsbc.exe 0x406940.

The vendor's chooser only ever writes three control words (0xAC, 0x8C, 0x0C,
plus the larger-block 0xA4), all with the map and capital bits and with the
fixed 0xFF/0xFE markers.  0x406940 implements much more, and our decoder now
does too; this tool builds the shapes no vendor archive carries, packs them
with our encoder (``SBC_POLICY=1`` plus a forced ``SBC_M4CTRL``), and requires
both decoders to reproduce the source byte for byte:

  salt        ctrl 0x00AE   bit 0 of the vendor word set, salt 0
                            (markers stay 0xFF/0xFE) on text holding 0xFE
  salt-custom ctrl 0x100AE  salt 0x80/0x00: capital 0x7F, escape 0x7E, and
                            the text carries '~' so the escape is used
  no-capital  ctrl 0x0086   the capital pass is off, so 0xFF and 0xFE are
                            ordinary bytes; only 0xFE needs the escape
  no-map      ctrl 0x008A   the 0x4079d0 byte map is off (vendor bit 0x02)
  token-fd    ctrl 0x00AE   our tokenizer is allowed to emit the
                            decompressor's 126th code, 0xFD = `wh`
  salt-line   ctrl 0x00FE   salted word *and* the prose pass, so the fold is
                            the appending 0x406b68 form, not 0x407a50
  esc-tokens  ctrl 0x0086   literals in 0x80..0xFD, which 0x406f20 would
                            expand: the encoder escapes them with 0xFE

Every case also checks the record dump (`SBC_DBG2=1`) for ``mode=4`` and the
control word, so a case cannot silently fall back to a stored block.

Usage: python3 tools/m4_forge.py [--keep DIR]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
UNSBC = os.path.join(ROOT, "unsbc.exe")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")
CORPUS = os.path.join(ROOT, "corpus")


def eng():
    return open(os.path.join(CORPUS, "eng.txt"), "rb").read()


def fixtures():
    """name -> (data, header ctrl, extra env, why)"""
    text = eng()

    with_ff = bytearray(text)
    for i in range(0, len(with_ff), 500):
        with_ff[i:i] = b"the quick\xfebrown fox and then some more words here\n"

    tilde = bytearray(text)
    for i in range(0, len(tilde), 700):
        tilde[i:i] = b"The~quick~brown fox jumps over the lazy dog\n"

    lower = bytearray()
    for i, line in enumerate(text.split(b"\n")):
        lower += line.lower() + b"\n"
        if i % 7 == 0:
            lower += b"the\xfequick\xffbrown fox jumps over the lazy dog\n"

    toks = bytearray()
    for i, line in enumerate(text.split(b"\n")):
        toks += line.lower() + b"\n"
        if i % 5 == 0:
            toks += b"the\x80quick\xc3brown\xfdfox jumps over\x9e the dog\n"

    wh = []
    for i, line in enumerate(text.decode("latin1").split("\n")):
        wh.append(line)
        if i % 3 == 0:
            wh.append("why whom which what when where the fox and the dog")

    # CRLF prose with 10 spaces per line: every break folds into the line
    # model, so the decoder runs 0x408060 and then the appending fold.
    words = ("the quick brown fox jumps over a lazy dog while several "
             "other animals watch").split()
    rng = __import__("random").Random(3)
    crlf = []
    for _ in range(300):
        crlf.append(" ".join(rng.choice(words) for _ in range(11)))
    crlf = ("\r\n".join(crlf) + "\r\n").encode()

    return [
        ("salt", bytes(with_ff), 0x00AE, {}, "salted bit0, fixed markers"),
        ("salt-custom", bytes(tilde), 0x100AE, {}, "salt 0x80: markers 0x7f/0x7e"),
        ("no-capital", bytes(lower), 0x0086, {}, "0x406ed0 skipped"),
        ("esc-tokens", bytes(toks), 0x0086, {}, "0x80..0xFD literals"),
        ("no-map", text, 0x008A, {}, "0x4079d0 skipped"),
        ("token-fd", "\n".join(wh).encode("latin1"), 0x00AE,
         {"SBC_M4TOK126": "1"}, "0xFD = wh"),
        ("salt-line", crlf, 0x00FE, {}, "prose pass + 0x406b68 fold"),
    ]


def wine(args, cwd):
    env = dict(os.environ)
    env["WINEPREFIX"] = WINEPREFIX
    env["WINEDEBUG"] = "-all"
    return subprocess.run(["wine", UNSBC] + args, cwd=cwd, env=env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=900)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", help="keep the work directory here")
    a = ap.parse_args()
    work = a.keep or tempfile.mkdtemp(prefix="m4forge-")
    os.makedirs(work, exist_ok=True)
    ok = bad = 0
    try:
        for name, data, ctrl, extra, why in fixtures():
            d = os.path.join(work, name)
            for sub in ("src", "x", "v"):
                os.makedirs(os.path.join(d, sub), exist_ok=True)
            src = os.path.join(d, "src", "f.bin")
            open(src, "wb").write(data)
            arc = os.path.join(d, "o.sbc")
            env = dict(os.environ, SBC_POLICY="1", SBC_M4CTRL="%x" % ctrl)
            env.update(extra)
            r = subprocess.run([OURS, "c", arc, "-m1", "f.bin"],
                               cwd=os.path.join(d, "src"), env=env,
                               capture_output=True)
            tag = "%-11s ctrl=%06x %s" % (name, ctrl, why)
            if r.returncode != 0 or not os.path.exists(arc):
                print("FAIL  %-60s encoder failed" % tag)
                bad += 1
                continue
            # 1. the record really is a mode-4 record with that control word
            dump = subprocess.run([OURS, arc, os.path.join(d, "x")],
                                  env=dict(os.environ, SBC_DBG2="1"),
                                  capture_output=True, text=True)
            m = re.search(r"mode=4 ctrl=([0-9a-f]+)", dump.stderr)
            shaped = m is not None and int(m.group(1), 16) == ctrl
            # 2. our decoder
            ours = d + "/x/f.bin"
            ours_ok = (dump.returncode == 0 and os.path.exists(ours) and
                       open(ours, "rb").read() == data)
            # 3. the vendor's decompressor
            shutil.copy2(arc, os.path.join(d, "v", "o.sbc"))
            rx = wine(["x", "o.sbc"], os.path.join(d, "v"))
            vend = os.path.join(d, "v", "f.bin")
            vend_ok = (rx.returncode == 0 and os.path.exists(vend) and
                       open(vend, "rb").read() == data)
            if shaped and ours_ok and vend_ok:
                ok += 1
                print("OK    %-60s %d B" % (tag, len(data)))
            else:
                bad += 1
                print("FAIL  %-60s shaped=%s ours=%s vendor=%s" %
                      (tag, shaped, ours_ok, vend_ok))
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    print("\n%d OK, %d FAIL" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
