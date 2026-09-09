from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_scan_history import create_cli_scan, run_workbench
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("completeness", ["complete", "partial"])
def test_deep_resume_uses_sealed_coverage_with_coverage_less_reducer(
    tmp_path: Path, completeness: str
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "extract.py").write_text("print('fixture')\n")
    scan = create_cli_scan(
        state, tmp_path / "scans", repository, mode="deep", completeness=completeness
    )
    snapshot = {"scanId": scan["scanId"], "findings": []}
    source = Path(scan["scanDir"]) / "artifacts" / "deep_discovery" / "reducer"
    checkpoint = write_checkpoint(source / "checkpoints", snapshot)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_checkpoints "
            "(scan_id, source_path, checkpoint_path, content_sha256, snapshot_json, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan["scanId"],
                str(source),
                str(checkpoint),
                checkpoint.stem,
                json.dumps(snapshot),
                "2026-09-01T00:00:00Z",
            ),
        )
    if completeness == "complete":
        result = run_workbench(
            state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False
        )
        assert result["returncode"] != 0
        assert "already completed" in result["stderr"]
    else:
        result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
        assert result["resumeMode"] == "checkpoint"
        assert result["checkpoint"]["sources"][0]["coverage"] == {}
