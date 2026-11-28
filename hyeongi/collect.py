"""Pause and resume training-data collection (attack practice on the same host).

While paused, hyeongid keeps detecting but writes no flow rows, and on Linux
the hyeongi-capture packet capture is stopped and stays stopped across reboots
(its unit has an ExecCondition on the flag file). Every pause and resume is
appended to pauses.log, so a dataset can also drop that window afterwards.

  python3 -m hyeongi.collect pause [reason...]
  python3 -m hyeongi.collect resume
  python3 -m hyeongi.collect status
"""
import os, subprocess, sys, time
from hyeongi.config import WINDOWS, PROGRAMDATA

DATA = os.path.join(PROGRAMDATA, "") if WINDOWS else "/var/lib/hyeongi"
FLAG = os.path.join(DATA, "collection.paused")
LOG = os.path.join(DATA, "pauses.log")


def paused():
    return os.path.exists(FLAG)


def pause_reason():
    """The reason given when collection was paused ("-" if none was), or None
    when collection is not paused. Practice mode pauses with "practice: <memo>"."""
    try:
        with open(FLAG, encoding="utf-8", errors="replace") as f:
            return f.readline().strip() or "-"
    except OSError:
        return None


def _log(what):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {what}\n"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line)


def _capture(action):
    if WINDOWS:
        return
    subprocess.run(["systemctl", action, "hyeongi-capture"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "status"
    os.makedirs(DATA, exist_ok=True)
    if cmd == "pause":
        reason = " ".join(argv[1:]) or "-"
        if not paused():
            with open(FLAG, "w", encoding="utf-8") as f:
                f.write(reason + "\n")
            _log(f"pause {reason}")
        _capture("stop")
        print("[=] training-data collection PAUSED (detection keeps running).")
        print("    resume with: hyeongi resume")
    elif cmd == "resume":
        if paused():
            os.unlink(FLAG)
            _log("resume")
        _capture("start")
        print("[+] training-data collection resumed.")
    elif cmd == "status":
        print("paused" if paused() else "collecting")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
