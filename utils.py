"""
Helper module intentionally used as a cross-file reachability test bed.

Two functions, both contain findings Semgrep will fire on. One of them is
called from a route handler with user input (reachable TP). The other is
dead code — not imported or called from anywhere (unreachable, should be
downgraded by the Phase 3 reachability pass).
"""

import pickle
import subprocess


def run_diagnostic_cmd(cmd: str) -> str:
    """[V11] TP, reachable.

    Called from /admin/run-diag in app.py with user-supplied `cmd`. Semgrep
    will flag `shell=True`. Reachability analysis should CONFIRM this as
    exploitable because a caller on the public HTTP surface passes unvalidated
    input.
    """
    return subprocess.check_output(cmd, shell=True, text=True)


def legacy_import_data(blob: bytes):
    """[V12] TP-pattern, NOT reachable.

    pickle.loads is unsafe — Semgrep will fire. But this function is dead
    code: nothing in the repo imports or calls it. Reachability analysis
    should downgrade severity to `info`/`low` or recommend deleting the
    function rather than treating it as an emergency.
    """
    return pickle.loads(blob)
