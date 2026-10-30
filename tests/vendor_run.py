#!/usr/bin/env python3
"""Run ``sbc.exe`` under Wine without ever letting it wait for input.

The vendor archiver asks ``Overwrite <archive>? (Y/N)`` when the target exists,
and that question blocks a batch run until somebody types Y.  Every caller goes
through :func:`run_vendor`, which

* deletes the archive(s) it is about to create (``produces=``),
* redirects the process' stdin to ``/dev/null`` so a prompt reads EOF instead
  of hanging, and
* gives up after ``timeout`` seconds.

``CompletedProcess.returncode`` is 0 on success, the process status otherwise,
and ``-9`` when the run timed out.
"""
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "historical_bin" / "sbc.exe" if (ROOT / "historical_bin" / "sbc.exe").exists() else ROOT / "sbc.exe"
WINEPREFIX = ROOT / "_work" / "wineprefix"


def run_vendor(args, cwd, produces=(), timeout=900):
    """Run the vendor archiver in ``cwd`` and return its CompletedProcess.

    ``produces`` lists the files the run creates; each is removed first so the
    overwrite prompt can never appear.
    """
    for p in produces:
        try:
            os.remove(str(p))
        except FileNotFoundError:
            pass
    env = dict(os.environ)
    env["WINEPREFIX"] = str(WINEPREFIX)
    env["WINEDEBUG"] = "-all"
    cmd = ["wine", str(VENDOR)] + [str(a) for a in args]
    try:
        r = subprocess.run(cmd, cwd=str(cwd), env=env,
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(cmd, -9, e.stdout or b"",
                                           b"timeout")
    out = r.stdout or b""
    if b"verwrite" in out:
        # the prompt appeared anyway: report it instead of trusting the run
        return subprocess.CompletedProcess(cmd, -10, out,
                                           b"prompted for overwrite")
    return r
