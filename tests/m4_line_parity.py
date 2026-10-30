#!/usr/bin/env python3
"""Mode-4 line-code parity: rebuild the vendor's `e2` from the text geometry.

The decoder (sbc mode4) can dump, for every block that uses the prose pass
(0x408060), the pass's input stream and the vendor's `e2` code
(`SBC_LINEDUMP=<dir> sbc <archive> <out>`).  The input is the tokenized text in
the mapped domain (space 0x20, line break 0x0a/0x0d, tokens >= 0x80) with the
*folded* breaks already turned into marker spaces, so the original line
geometry comes from replaying the code or from the sample's own source text.

Encoder rule (measured, byte-exact on every real block and on the geometry
samples): a line with `k` internal spaces is folded when `7 <= k <= 24` and it
is followed by a line break; the fold replaces that break with a marker space
and codes `k - 7`.  Lines with fewer spaces stay literal (no symbol reaches
them, since `thr >= 7`), and a line with more than 24 spaces cannot be folded
at all (the threshold caps at 24, so the break would land inside the line).
After the last fold the tail may still hold a space; it takes the `0x12`
"never break" symbol, because the next space always fetches one.

The coder mirrors 0x408060 exactly.  The decoder walks the code backwards: the
last four bytes form its initial code word and every renormalisation pulls the
preceding byte.  The encoder therefore stores `le32(low)` and then its
renormalisation bytes in reverse emission order, which is `reverse(renorm +
be32(low))`.

Usage: python3 tools/m4_line_parity.py <dumpdir>
"""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "_work"))
from m4_line_model import M32, INC, MAXFREQ, MAXTOTAL, AdaptiveModel  # noqa: E402
from m4_line_model import RangeDecoder  # noqa: E402

LINE_MIN = 7
NOBREAK = 0x12
PENDING = 0x13
MAXTHR = 0x18
MAXLINE = MAXTHR          # a folded line may not exceed the 24-space threshold


class RangeEncoder:
    def __init__(self):
        self.low = 0
        self.range = M32
        self.bytes = []

    def _renorm(self):
        while True:
            if (((self.low + self.range) & M32) ^ self.low) <= 0xFFFFFF:
                pass
            elif self.range <= 0x3FFF:
                self.range = (-self.low) & 0x3FFF
            else:
                return
            self.bytes.append((self.low >> 24) & 0xFF)
            self.low = (self.low << 8) & M32
            self.range = (self.range << 8) & M32

    def encode(self, unit, cum, freq):
        self.low = (self.low + unit * cum) & M32
        self.range = (unit * freq) & M32
        self._renorm()

    def data(self):
        le = bytes((self.low >> s) & 0xFF for s in (0, 8, 16, 24))
        return le + bytes(reversed(self.bytes))


def encode_symbols(syms):
    enc = RangeEncoder()
    model = AdaptiveModel()
    for sym in syms:
        if model.total > MAXTOTAL:
            model.rescale()
        cum = sum(model.freq[:sym])
        enc.encode(enc.range // model.total, cum, model.freq[sym])
        model.freq[sym] += INC
        model.total += INC
        if model.freq[sym] > MAXFREQ:
            model.rescale()
    return enc.data() if syms else b""


def replay(raw, dec, target):
    """0x408060 with symbols pulled from the decoder on demand."""
    out = bytearray()
    i = 0
    n = len(raw)
    cnt = 0
    edx = PENDING

    def space():
        nonlocal cnt, edx
        if edx == PENDING:
            edx = dec.decode()
        thr = min(edx + 7, MAXTHR)
        if cnt >= thr:
            if edx != NOBREAK:
                out[-1] = target
            edx = PENDING
            cnt = 0
        else:
            cnt += 1

    while i < n:
        c = raw[i]
        i += 1
        out.append(c)
        while True:
            if c == 0x20:
                space()
                break
            if c == target:
                cnt = 0
                if i >= n:
                    break
                nb = raw[i]
                i += 1
                if nb == 0x20:
                    break
                out.append(nb)
                c = nb
                continue
            break
    return bytes(out)


def _decoder(data):
    rd = RangeDecoder(data)
    model = AdaptiveModel()
    dec = type("D", (), {})()
    dec.decode = lambda: model.decode(rd)
    return dec


def plan_symbols(text, target):
    """Symbol sequence for the folded geometry of `text`.

    The encoder walks the lines in order, simulating the decoder.  A symbol is
    fetched at the first space of a line (after a break or a real line break)
    or at the space that follows a harmless NOBREAK fire inside a long line.
    At a fetch the encoder scans the upcoming lines for the first one with at
    least seven spaces: 7..24 gives `k - 7` (the fire lands on that line's
    marker space), a longer line gives 0x12 (fire nothing, re-arm), and running
    past the last break also gives 0x12.
    """
    lines = text.split(bytes([target]))
    ks = [line.count(0x20) for line in lines]
    last = len(lines) - 1              # the target-free tail is never folded
    syms = []
    sym = PENDING
    cnt = 0

    def choose(start):
        for j in range(start, last):
            k = ks[j]
            if k > MAXLINE:
                return NOBREAK
            if k >= LINE_MIN:
                return k - LINE_MIN
        return NOBREAK

    for i, k in enumerate(ks):
        fold = i < last and LINE_MIN <= k <= MAXLINE
        first = True
        for _ in range(k):
            if sym == PENDING:
                sym = choose(i if first else i + 1)
                syms.append(sym)
            if cnt >= min(sym + 7, MAXTHR):
                sym, cnt = PENDING, 0
            else:
                cnt += 1
            first = False
        if fold:
            if sym == PENDING:
                sym = choose(i if first else i + 1)
                syms.append(sym)
            if cnt >= min(sym + 7, MAXTHR):
                sym, cnt = PENDING, 0
            else:
                raise RuntimeError("fold did not fire on line %d" % i)
        else:
            cnt = 0
    return syms


def check(dumpdir):
    ok = bad = 0
    dumps = sorted(glob.glob(os.path.join(dumpdir, "**", "*_e2.bin"),
                             recursive=True))
    for path in dumps:
        stem = path[:-len("_e2.bin")]
        raw = open(stem + "_in.bin", "rb").read()
        want = open(path, "rb").read()
        tag = open(stem + "_tag.txt").read().strip()
        target = int(tag.split()[1].split("=")[1]) if " " in tag else 0x0A
        if target not in (0x0A, 0x0D):
            target = 0x0A
        sub = os.path.dirname(stem)
        src = os.path.join(sub, "src.bin")
        single = len(glob.glob(os.path.join(sub, "*_e2.bin"))) == 1
        if os.path.exists(src) and single:
            # single-block sample: the source text is the true line geometry
            text = open(src, "rb").read()
            if target == 0x0A and b"\r\n" in text:
                text = text.replace(b"\r\n", b"\n")
        else:
            text = replay(raw, _decoder(want), target)
        got = encode_symbols(plan_symbols(text, target))
        if got == want:
            ok += 1
        else:
            bad += 1
            first = next((i for i, (a, b) in enumerate(zip(got, want)) if a != b),
                         min(len(got), len(want)))
            print("%s DIFF %d/%d bytes got=%d want=%d first=%d"
                  % (os.path.basename(stem), ok, ok + bad, len(got), len(want),
                     first))
    print("mode-4 line code: %d identical, %d different" % (ok, bad))
    return bad == 0


if __name__ == "__main__":
    sys.exit(0 if check(sys.argv[1] if len(sys.argv) > 1 else "/tmp/linedump")
                    else 1)
