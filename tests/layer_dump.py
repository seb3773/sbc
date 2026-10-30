#!/usr/bin/env python3
"""Dump every encoder-stage buffer of an archive and summarise it.

The C decoder walks the encoder pipeline backwards and, with ``SBC_DUMP``
set, writes each intermediate buffer of every block:

    00_payload.bin  bytes stored in the archive (stage1/stage2 output)
    01_bwt.bin      BWT string        = stage2 output, or the payload itself
    02_lzp.bin      LZP output        = input of the BWT
    03_filter.bin   filter output     = input of the LZP
    04_block.bin    decoded block     = input of the filter chain
    hdr.txt         block header fields, record bits in hex
    recs.txt        parsed filter records
    arc.txt         archive header (method, csum, extra3, file table)

Layers are numbered by the encoder stage that *produces* them, so an
encoder-side dump of the same stage diffs directly against these files.

This tool runs the decoder once per archive, then prints one line per block
and checks the invariants that must hold between consecutive layers.

Usage: python3 tools/layer_dump.py [-o DIR] [--bin PATH] [archive...]
       (default: every packed_corpus/*.sbc, output in _work/layers)

Exit status is non-zero if an invariant fails.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYERS = ("00_payload", "01_bwt", "02_lzp", "03_filter", "04_block")


def parse_kv(path):
    """Parse 'k=v k=v ...' plus an optional 'bits=<hex>' tail."""
    txt = path.read_text()
    out = {}
    for tok in txt.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        try:
            out[k] = int(v, 10)
        except ValueError:
            try:
                out[k] = int(v, 16) if k == "bits" else v
            except ValueError:
                out[k] = v
    return out


def parse_arc(path):
    out = {"files": []}
    for line in path.read_text().splitlines():
        if line.startswith("file "):
            f = {}
            for tok in line.split()[2:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    f[k] = v
            out["files"].append(f)
        elif "=" in line:
            for tok in line.split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    out[k] = int(v) if v.isdigit() else v
    return out


def parse_recs(path):
    recs = []
    for line in path.read_text().splitlines():
        if not line or line.startswith("nrec="):
            continue
        r = {}
        for tok in line.split():
            k, v = tok.split("=", 1)
            r[k] = int(v, 16) if k == "ctrl" else int(v)
        recs.append(r)
    return recs


def dump_archive(bin_path, arc, outdir):
    d = Path(outdir) / arc.stem
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True)
    env = dict(os.environ)
    env["SBC_DUMP"] = str(d)
    tmp = Path(tempfile.mkdtemp(prefix="sbcx-"))
    try:
        r = subprocess.run([bin_path, str(arc), str(tmp)], env=env,
                           capture_output=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return d, r


def load_blocks(d):
    blocks = []
    for hdr in sorted(d.glob("blk*_hdr.txt")):
        idx = int(hdr.name[3:6])
        info = parse_kv(hdr)
        sizes = {}
        for name in LAYERS:
            p = d / ("blk%03d_%s.bin" % (idx, name))
            sizes[name] = p.stat().st_size if p.exists() else -1
        recs = []
        rp = d / ("blk%03d_recs.txt" % idx)
        if rp.exists():
            recs = parse_recs(rp)
        blocks.append({"idx": idx, "info": info, "sizes": sizes,
                       "recs": recs})
    return blocks


def check(arc, blk):
    """Return a list of invariant violations for one block."""
    info, sz = blk["info"], blk["sizes"]
    bad = []
    e1 = info.get("e1", 0)
    if sz["01_bwt"] != info.get("vlq", -1):
        bad.append("bwt=%d != vlq=%d" % (sz["01_bwt"], info.get("vlq")))
    if e1 == 0:
        if sz["00_payload"] != sz["01_bwt"]:
            bad.append("stored payload %d != bwt %d" %
                       (sz["00_payload"], sz["01_bwt"]))
    else:
        if sz["00_payload"] != e1:
            bad.append("payload %d != e1=%d" % (sz["00_payload"], e1))
    # the BWT is a permutation of the LZP output, so these two always agree
    if sz["02_lzp"] != sz["01_bwt"]:
        bad.append("lzp=%d != bwt=%d" % (sz["02_lzp"], sz["01_bwt"]))
    if info.get("flag3") == 0:
        if sz["03_filter"] != sz["02_lzp"]:
            bad.append("flag3=0 but filter=%d != lzp=%d" %
                       (sz["03_filter"], sz["02_lzp"]))
    elif sz["03_filter"] < sz["02_lzp"]:
        bad.append("flag3=1 but filter=%d < lzp=%d (LZP expanded)" %
                   (sz["03_filter"], sz["02_lzp"]))
    # A record's flen is the number of *filtered* bytes it consumes, so the
    # records must add up to the filter layer (mode 4 shrinks text, so this is
    # the only size that matches).  Option bits are inferred, so a mismatch
    # usually means the record list was read ambiguously.
    warn = []
    if blk["recs"]:
        want = sum(r["len"] for r in blk["recs"])
        if want != sz["03_filter"]:
            warn.append("sum(recs)=%d != filter=%d (record parse ambiguous)" %
                        (want, sz["03_filter"]))
    return bad, warn


def summarize(arc, d):
    print("%-24s %s" % (arc.name, " ".join(
        "%s=%s" % (k, v) for k, v in parse_arc(d / "arc.txt").items()
        if k != "files")))
    blocks = load_blocks(d)
    total_bad = 0
    for b in blocks:
        i, sz = b["info"], b["sizes"]
        modes = ",".join("m%d" % r["mode"] if r["coded"] else "copy"
                         for r in b["recs"]) or "-"
        print("  blk%03d e1=%-5d %-8s flag3=%d vlq=%-6d prim=%-6d nbits=%-3d "
              "block=%-6d filter=%-6d lzp=%-6d bwt=%-6d payload=%-6d "
              "recs=%d[%s]" % (
                  b["idx"], i.get("e1", 0),
                  "comp" if i.get("e1", 0) else "stored",
                  i.get("flag3", 0), i.get("vlq", 0), i.get("primary", 0),
                  i.get("nbits", 0), sz["04_block"], sz["03_filter"],
                  sz["02_lzp"], sz["01_bwt"], sz["00_payload"],
                  len(b["recs"]), modes))
        bad, warn = check(arc, b)
        for msg in bad:
            total_bad += 1
            print("    !! %s" % msg)
        for msg in warn:
            print("    ~  %s" % msg)
    return blocks, total_bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default=str(ROOT / "_work" / "layers"))
    ap.add_argument("--bin", default=str(ROOT / "sbc"))
    ap.add_argument("--json", action="store_true",
                    help="also write manifest.json per archive")
    ap.add_argument("archives", nargs="*")
    a = ap.parse_args()
    arcs = ([Path(p) for p in a.archives] if a.archives else
            sorted((ROOT / "packed_corpus").glob("*.sbc")))
    nblocks = ncomp = nlzp = nbad = 0
    for arc in arcs:
        d, r = dump_archive(a.bin, arc, a.out)
        if r.returncode != 0:
            print("%-24s decoder exit %d" % (arc.name, r.returncode))
            nbad += 1
            continue
        blocks, bad = summarize(arc, d)
        nbad += bad
        nblocks += len(blocks)
        ncomp += sum(1 for b in blocks if b["info"].get("e1", 0))
        nlzp += sum(1 for b in blocks if b["info"].get("flag3", 0) == 1)
        if a.json:
            (d / "manifest.json").write_text(json.dumps(
                {"archive": arc.name, "blocks": blocks}, indent=1))
    print("\n%d block(s) in %d archive(s): %d compressed, %d with LZP, "
          "%d invariant failure(s)" % (nblocks, len(arcs), ncomp, nlzp, nbad))
    return 0 if nbad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
