from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint


def continue_scan(state: Path, repository: Path, parent_id: str, child: Path) -> str:
    child.mkdir(mode=0o700)
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    return child_id


def test_worker_receipts_keep_source_ownership_across_repeated_continuation(
    tmp_path: Path, workbench_api
):
    state, repository, parent, parent_id = scan_fixture(tmp_path, "deep")
    local_receipt = "artifacts/review/source.json"
    parent_receipt = parent / local_receipt
    parent_receipt.parent.mkdir(parents=True)
    parent_receipt.write_bytes(b"Parent review evidence\n")
    parent_payload = semantic(parent_id, [])
    parent_payload["coverage"]["deferred"] = []
    parent_payload["coverage"]["surfaces"] = [
        {
            "id": "parent-control",
            "candidateId": "parent-control",
            "label": "Parent control",
            "disposition": "rejected",
            "receiptRefs": [local_receipt],
        }
    ]
    save(state, parent_id, write_checkpoint(parent / "checkpoints", parent_payload))
    original_workers = {}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "created_at, updated_at) VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', "
            "2, 0, 2, 2, 2, '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (parent_id,),
        )
        for index in range(2):
            worker_id = str(uuid.uuid4())
            output = parent / f"artifacts/deep_discovery/workers/discovery-{index}/output"
            output.mkdir(parents=True)
            prompt = output.parent / "prompt.md"
            prompt.write_text("Synthetic resumed discovery\n")
            receipt = output / local_receipt
            receipt.parent.mkdir(parents=True)
            receipt.write_text(json.dumps({"worker": index}))
            original_workers[worker_id] = (
                output.relative_to(parent).as_posix(),
                receipt.read_bytes(),
            )
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, prompt_path, artifact_dir, "
                "attempt, created_at, updated_at) VALUES (?, ?, 'discovery', 'failed', ?, ?, 1, "
                "'2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
                (worker_id, parent_id, str(prompt), str(output)),
            )
    for worker_id, (source, _) in original_workers.items():
        payload = semantic(parent_id, ["clean.ts"])
        payload["coverage"]["deferred"] = []
        payload["coverage"]["surfaces"] = [
            {
                "id": "same-surface",
                "candidateId": "same-candidate",
                "label": "Reviewed control",
                "disposition": "rejected",
                "receiptRefs": [local_receipt],
                "provenance": {"workerId": worker_id},
            }
        ]
        save(state, parent_id, write_checkpoint(parent / source / "checkpoints", payload))

    owners = original_workers
    for attempt in range(2):
        child = tmp_path / f"child-{attempt}"
        child_id = continue_scan(state, repository, parent_id, child)
        owners = {
            str(uuid.uuid5(uuid.UUID(child_id), worker_id)): value
            for worker_id, value in owners.items()
        }
        coverage = json.loads((child / "coverage.json").read_text())
        assert len(coverage["surfaces"]) == 3
        for surface in coverage["surfaces"]:
            if surface["candidateId"] == "parent-control":
                assert surface["receiptRefs"] == [local_receipt]
                assert (child / local_receipt).read_bytes() == b"Parent review evidence\n"
                continue
            source, contents = owners[surface["provenance"]["workerId"]]
            assert surface["receiptRefs"] == [f"{source}/{local_receipt}"]
            assert (child / surface["receiptRefs"][0]).read_bytes() == contents
        checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)[
            "checkpoint"
        ]
        for source in checkpoint["sources"]:
            if source["source"] != ".":
                assert source["coverage"]["surfaces"][0]["receiptRefs"] == [local_receipt]
        parent_id = child_id

    # A resumed worker can add receipts before the coordinator's final merge.
    worker_id, (source, _) = next(iter(owners.items()))
    worker_source = next(item for item in checkpoint["sources"] if item["source"] == source)
    result = {
        "scanId": child_id,
        "complete": True,
        "findings": [],
        "coverage": worker_source["coverage"],
    }
    result["coverage"]["completeness"] = "complete"
    result["coverage"]["surfaces"].append(
        {
            "id": "resumed-control",
            "candidateId": "resumed-control",
            "label": "Resumed control",
            "disposition": "rejected",
            "receiptRefs": ["artifacts/review/resumed.json"],
            "provenance": {"workerId": worker_id},
        }
    )
    (child / source / "artifacts/review/resumed.json").write_bytes(b"Resumed evidence\n")
    result_path = child / source / "result.json"
    result_path.write_text(json.dumps(result))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'succeeded', result_manifest_path = ?, "
            "completion_sequence = 1 WHERE id = ?",
            (str(result_path), worker_id),
        )
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        documents = workbench_api["scan_checkpoints"].continued_deep_documents(
            connection,
            scan,
            workbench_api["workbench_completion_binding"](scan, workbench_api["now"]()),
            [],
        )
        resumed = next(
            item
            for item in documents[2]["surfaces"]
            if item.get("candidateId") == "resumed-control"
        )
        assert resumed["receiptRefs"] == [f"{source}/artifacts/review/resumed.json"]


@pytest.mark.parametrize("finalized", [False, True])
def test_missing_raw_checkpoint_receipt_remains_resumable_and_partial(
    tmp_path: Path, finalized: bool
):
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    payload = semantic(parent_id, ["clean.ts", "pending.ts"])
    payload["complete"] = True
    payload["coverage"].update(
        completeness="complete",
        deferred=[],
        surfaces=[
            {
                "id": "missing-receipt",
                "candidateId": "candidate-1",
                "label": "Unfinished receipt write",
                "disposition": "rejected",
                "receiptRefs": ["artifacts/review/never-written.json"],
            }
        ],
    )
    snapshot = write_checkpoint(parent / "checkpoints", payload)
    original = snapshot.read_bytes()
    save(state, parent_id, snapshot)
    if finalized:
        run_workbench(state, "fail-scan", "--scan-id", parent_id, "--message", "Writer interrupted")
        assert (
            json.loads((parent / "coverage.json").read_text())["surfaces"][0]["receiptRefs"] == []
        )
    child = tmp_path / "child"
    child_id = continue_scan(state, repository, parent_id, child)
    coverage = json.loads((child / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["receiptRefs"] == []
    assert coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    manifest = json.loads((child / "scan-manifest.json").read_text())
    assert manifest["scan"]["complete"] is False
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    assert resumed["checkpoint"]["sources"][0]["coverage"] == coverage
    assert snapshot.read_bytes() == original
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        warnings = json.loads(
            connection.execute(
                "SELECT completion_warnings_json FROM scans WHERE id = ?", (child_id,)
            ).fetchone()[0]
        )
    assert any("receipt" in warning for warning in warnings)
