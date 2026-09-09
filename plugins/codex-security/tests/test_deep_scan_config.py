from __future__ import annotations

import builtins
import runpy
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib

DEEP_SCAN_CONFIG_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deep_scan_config.py"


def test_deep_scan_config_falls_back_to_tomli_without_stdlib_tomllib(monkeypatch) -> None:
    real_import = builtins.__import__
    monkeypatch.setitem(sys.modules, "tomli", tomllib)

    def import_without_tomllib(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tomllib":
            raise ModuleNotFoundError("No module named 'tomllib'", name="tomllib")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_tomllib)

    namespace = runpy.run_path(str(DEEP_SCAN_CONFIG_SCRIPT), run_name="deep_scan_config_test")

    assert namespace["tomllib"] is tomllib
