from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path

from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


def scan_fixture(tmp_path: Path, mode: str = "standard") -> tuple[Path, Path, Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "clean.ts").write_text("export const count = 1;\n")
    (repository / "pending.ts").write_text("export const count = 2;\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    state = tmp_path / "state"
    result = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": mode,
                "config": {},
            }
        ),
    )
    return state, repository, scan_dir, str(result["scanId"])


def semantic(scan_id: str, reviewed: list[str]) -> dict[str, object]:
    return {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": "candidate-1",
                    "reason": "Validation pending",
                    "candidate": {"summary": "Inspect the control"},
                }
            ],
            "reviewedFiles": reviewed,
        },
    }


def save(state: Path, scan_id: str, path: Path, *, check: bool = True) -> dict[str, object]:
    return run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        scan_id,
        "--checkpoint-path",
        str(path),
        check=check,
    )


def test_checkpoint_survives_new_process_with_clean_coverage_and_pending_evidence(
    tmp_path: Path,
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    payload = semantic(scan_id, ["clean.ts"])
    checkpoint = write_checkpoint(scan_dir / "checkpoints", payload)
    save(state, scan_id, checkpoint)
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert result["progress"]["status"] == "running"
    assert result["findingCount"] == 0
    assert result["checkpoint"]["reviewedFileCount"] == 1
    assert result["checkpoint"]["remainingFileCount"] == 1
    assert result["checkpoint"]["pendingCount"] == 1
    assert "coverage" not in result["checkpoint"]["sources"][0]
    assert "reviewedFiles" not in result["checkpoint"]
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["sources"][0]["coverage"] == payload["coverage"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        stored = connection.execute("SELECT snapshot_json FROM scan_checkpoints").fetchone()[0]
        assert json.loads(stored) == payload
    save(state, scan_id, checkpoint)
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["checkpoint"]
        == result["checkpoint"]
    )


def test_rejected_coverage_batch_does_not_commit_other_paths(tmp_path: Path) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    (repository / "pending.ts").write_text("changed source\n")
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints", semantic(scan_id, ["clean.ts", "pending.ts"])
    )
    result = save(state, scan_id, checkpoint, check=False)
    assert result["returncode"] != 0
    assert "changed: pending.ts" in result["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM scan_review_files WHERE reviewed_at IS NOT NULL"
        ).fetchone() == (0,)


def test_resume_reconciles_checkpoint_written_before_projection(tmp_path: Path) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path, "deep")
    run_workbench(state, "set-scan-thread", "--scan-id", scan_id, "--thread-id", str(uuid.uuid4()))
    checkpoint = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    (scan_dir / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert resumed["checkpoint"]["remainingFiles"] == ["pending.ts"]


def test_checkpoint_binding_rejects_wrong_scan_unknown_worker_and_changed_content(
    tmp_path: Path,
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    wrong_scan = write_checkpoint(scan_dir / "checkpoints", semantic(str(uuid.uuid4()), []))
    assert "this scan" in save(state, scan_id, wrong_scan, check=False)["stderr"]
    worker = write_checkpoint(
        scan_dir / "unregistered-worker" / "checkpoints", semantic(scan_id, [])
    )
    assert "registered scan worker" in save(state, scan_id, worker, check=False)["stderr"]
    changed = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, []))
    changed.write_text(changed.read_text() + " ")
    assert "saved content" in save(state, scan_id, changed, check=False)["stderr"]


def test_checkpoint_order_uses_receipts_and_old_replay_cannot_regress_it(tmp_path: Path) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    first = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    save(state, scan_id, first)
    payload = semantic(scan_id, ["clean.ts", "pending.ts"])
    payload["coverage"]["deferred"] = []
    second = write_checkpoint(scan_dir / "checkpoints", payload)
    os.utime(second, ns=(1, 1))
    save(state, scan_id, second)
    save(state, scan_id, first)
    result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert result["remainingFiles"] == []
    assert result["sources"][0]["coverage"] == payload["coverage"]
    assert json.loads((scan_dir / "checkpoint-head.json").read_text())["checkpoint"] == second.name
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (2,)


def test_child_inherits_saved_findings_coverage_and_cost_without_changing_parent_seal(
    tmp_path: Path,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    payload = semantic(scan_id, ["clean.ts"])
    payload["findings"] = [finding]
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", payload))
    run_workbench(state, "fail-scan", "--scan-id", scan_id, "--message", "Connection closed")
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        scan_id,
    )["scanId"]
    cost = {
        "model": "test-model",
        "inputTokens": 100,
        "outputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "estimatedUsd": 2.5,
    }
    result = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child,
        "--parent-scan-id",
        scan_id,
        "--cost-json",
        json.dumps(cost),
    )["checkpoint"]
    assert result["reviewedFiles"] == ["clean.ts"]
    assert result["remainingFiles"] == ["pending.ts"]
    assert result["sources"][0]["findings"][0]["title"] == finding["title"]
    assert (
        json.loads((child_dir / "findings.json").read_text())["findings"][0]["title"]
        == finding["title"]
    )
    assert json.loads((child_dir / "scan-manifest.json").read_text())["scan"]["complete"] is False
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        baseline, attempt = connection.execute(
            "SELECT continuation_cost_json, cost_json FROM scans WHERE id = ?",
            (child,),
        ).fetchone()
        assert json.loads(baseline) == cost
        assert attempt is None


def test_child_registration_against_changed_source_cannot_reuse_parent_coverage(
    tmp_path: Path,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    save(
        state, scan_id, write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    )
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    (repository / "pending.ts").write_text("changed target\n")
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        scan_id,
    )["scanId"]
    result = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child,
        "--parent-scan-id",
        scan_id,
        check=False,
    )
    assert "original source" in result["stderr"]
    assert not (child_dir / "findings.json").exists()


def test_worker_checkpoint_commits_under_registered_scan_with_clean_source_coverage(
    tmp_path: Path,
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    payload = semantic(scan_id, ["app.py"])
    path = write_checkpoint(result_path.parent / "checkpoints", payload)
    save(state, scan_id, path)
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["checkpoint"]
    assert result["sources"][0]["source"] == result_path.parent.relative_to(scan_dir).as_posix()
    assert result["reviewedFileCount"] == 1
    assert result["pendingCount"] == 1
    assert result["sources"][0]["checkpointPath"] == path.relative_to(scan_dir).as_posix()
