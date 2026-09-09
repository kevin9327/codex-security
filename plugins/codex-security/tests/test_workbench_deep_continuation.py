from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import fields
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint


@pytest.fixture(autouse=True)
def configure_deep(workbench_api):
    deep = workbench_api["deep_scan"]
    deep.configure(
        deep.DeepScanDependencies(
            **{
                field.name: workbench_api[
                    "preserve_stopped_results_after_transition"
                    if field.name == "preserve_stopped_results"
                    else field.name
                ]
                for field in fields(deep.DeepScanDependencies)
            }
        )
    )


def completed_deep_fixture(tmp_path: Path):
    state, repository, parent_dir, parent_id = scan_fixture(tmp_path, "deep")
    save(state, parent_id, write_checkpoint(parent_dir / "checkpoints", semantic(parent_id, [])))
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    worker_ids = [str(uuid.uuid4()) for _ in range(5)]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "completion_sequence, created_at, updated_at) "
            "VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', 2, 0, 2, 5, 4, 3, ?, ?)",
            (parent_id, "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"),
        )
        for index, worker_id in enumerate(worker_ids):
            reducer = index == 4
            name = "dedup-0001" if reducer else f"discovery-{index + 1:04d}"
            directory = (
                parent_dir
                / "artifacts"
                / "deep_discovery"
                / ("dedup" if reducer else "workers")
                / name
            )
            output = directory / "output"
            output.mkdir(parents=True)
            prompt = directory / "prompt.md"
            prompt.write_text(f"Paid prompt for {name}\n")
            result = semantic(parent_id, [])
            result["complete"] = True
            if reducer:
                result["findings"] = [
                    {
                        "summary": worker_ids[0],
                        "provenance": {
                            "sourceFindingIds": [f"{worker_ids[0]}:0"],
                            "sourceFindings": [
                                {"id": f"{worker_ids[0]}:0", "finding": {"provenance": {}}}
                            ],
                        },
                    }
                ]
            (output / "result.json").write_text(json.dumps(result))
            (output / "evidence.txt").write_text("Saved evidence\n")
            (output / "checkpoints").mkdir()
            (output / "checkpoints" / "old.json").write_text(json.dumps(result))
            (output / "checkpoint-head.json").write_text('{"checkpoint":"old.json"}')
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, merge_state, prompt_path, "
                "artifact_dir, result_manifest_path, attempt, sdk_thread_id, completion_sequence, "
                "created_at, updated_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
                (
                    worker_id,
                    parent_id,
                    "dedup" if reducer else "discovery",
                    "failed" if index == 3 else "succeeded",
                    "none" if reducer or index == 3 else ("merged" if index < 2 else "merging"),
                    str(prompt),
                    str(output),
                    str(output / "result.json"),
                    f"thread-{index}",
                    None if reducer or index == 3 else index + 1,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T01:00:00Z",
                    "2026-01-01T01:00:00Z",
                ),
            )
        connection.executemany(
            "INSERT INTO deep_scan_dedup_inputs VALUES (?, ?, ?, ?)",
            [(parent_id, worker_ids[4], worker_ids[index], index) for index in range(2)],
        )
    return state, parent_dir, parent_id, child_dir, child_id, worker_ids


def test_deep_continuation_restores_paid_workers_and_reducer_inputs(tmp_path: Path, workbench_api):
    state, parent_dir, parent_id, child_dir, child_id, workers = completed_deep_fixture(tmp_path)
    original = {
        p.relative_to(parent_dir): p.read_bytes() for p in parent_dir.rglob("*") if p.is_file()
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        deep = workbench_api["deep_scan"]
        mapping = deep.restore_checkpoint_workers(connection, parent, child, "2026-01-01T02:00:00Z")
        assert (
            deep.restore_checkpoint_workers(connection, parent, child, "2026-01-01T02:00:01Z")
            == mapping
        )
        run = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
        ).fetchone()
        assert run["discovery_runs_dispatched"] == 3
        assert run["completion_sequence"] == 3
        assert run["created_at"] == "2026-01-01T00:00:00Z"
        assert run["max_discovery_runs"] == 5
        assert not deep.coordinator_lease_is_live(connection, run, child, "2026-01-01T02:00:00Z")
        restored = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY kind, completion_sequence",
            (child_id,),
        ).fetchall()
        assert len(restored) == 4
        assert workers[3] not in mapping
        assert [row["merge_state"] for row in restored if row["kind"] == "discovery"] == [
            "merged",
            "merged",
            "buffered",
        ]
        inputs = connection.execute(
            "SELECT * FROM deep_scan_dedup_inputs WHERE scan_id = ? ORDER BY input_order",
            (child_id,),
        ).fetchall()
        assert [row["discovery_worker_id"] for row in inputs] == [
            mapping[workers[0]],
            mapping[workers[1]],
        ]
        for row in restored:
            result = json.loads(Path(row["result_manifest_path"]).read_text())
            assert result["scanId"] == child_id
            assert Path(row["prompt_path"]).read_text().startswith("Paid prompt")
            output = Path(row["artifact_dir"])
            assert (output / "evidence.txt").read_text() == "Saved evidence\n"
            assert not (output / "checkpoints").exists()
            assert not (output / "checkpoint-head.json").exists()
            if row["kind"] == "dedup":
                finding = result["findings"][0]
                assert finding["summary"] == workers[0]
                assert finding["provenance"]["sourceFindingIds"] == [f"{mapping[workers[0]]}:0"]
                assert (
                    finding["provenance"]["sourceFindings"][0]["id"] == f"{mapping[workers[0]]}:0"
                )
    assert original == {
        p.relative_to(parent_dir): p.read_bytes() for p in parent_dir.rglob("*") if p.is_file()
    }


def test_failed_deep_artifact_copy_does_not_record_completed_child_workers(
    tmp_path: Path, workbench_api
):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    # A worker artifact can contain links; it must not read outside the bound scan.
    artifact = parent_dir / "artifacts/deep_discovery/dedup/dedup-0001/output/evidence.txt"
    artifact.unlink()
    artifact.symlink_to(tmp_path / "outside.txt")
    (tmp_path / "outside.txt").write_text("Outside the scan\n")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        with pytest.raises((SystemExit, ValueError)):
            workbench_api["deep_scan"].restore_checkpoint_workers(
                connection, parent, child, "2026-01-01T02:00:00Z"
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )


def test_continue_command_restores_deep_units_before_starting_a_new_coordinator(tmp_path: Path):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    reducer = parent_dir / "artifacts/deep_discovery/dedup/dedup-0001/output/result.json"
    payload = json.loads(reducer.read_text())
    payload["findings"] = []
    reducer.write_text(json.dumps(payload))
    # Workers from before automatic checkpointing still have accepted result files.
    for head in parent_dir.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
    continued = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child_id,
        "--parent-scan-id",
        parent_id,
        "--cost-json",
        json.dumps(
            {
                "model": "test-model",
                "inputTokens": 100,
                "outputTokens": 10,
                "cachedInputTokens": 0,
                "cacheWriteInputTokens": 0,
                "estimatedUsd": 2.5,
            }
        ),
    )
    assert continued["restoredWorkers"] == 4
    assert not continued["completionReady"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT discovery_runs_dispatched FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
        ).fetchone() == (3,)
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_dedup_inputs WHERE scan_id = ?", (child_id,)
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT status FROM scans WHERE id = ?", (parent_id,)
        ).fetchone() == ("failed",)


def test_deep_continuation_rejects_a_changed_frozen_worker_result(tmp_path: Path, workbench_api):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    relative = "artifacts/deep_discovery/workers/discovery-0001/output/result.json"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
            (json.dumps({relative: "0" * 64}), parent_id),
        )
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        with pytest.raises(SystemExit, match="changed after the scan stopped"):
            workbench_api["deep_scan"].restore_checkpoint_workers(
                connection, parent, child, "2026-01-01T02:00:00Z"
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )
    assert (parent_dir / relative).is_file()
