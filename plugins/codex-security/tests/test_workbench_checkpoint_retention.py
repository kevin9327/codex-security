from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_workbench_deep_continuation import completed_deep_fixture
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
def test_stopped_standard_scan_matches_worker_provenance_to_root_decision(
    tmp_path: Path, disposition: str
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    write_completed_contract(scan_dir, scan_id, repository, relative_path="clean.ts")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"].update(workerId="investigator-1", candidateId="candidate-1")
    finding["extensions"] = {"candidateId": "candidate-1"}
    pending = semantic(scan_id, ["clean.ts"])
    pending["findings"] = [finding]
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", pending))

    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="partial", surfaces=[], explicitExclusions=[], deferred=[])
    coverage["explicitExclusions" if disposition == "not_applicable" else "surfaces"] = [
        {
            "id": "validated-candidate",
            "candidateId": "candidate-1",
            "label": "Saved candidate validation",
            "disposition": disposition,
            "reason": "The existing containment check prevents the candidate.",
            "receiptRefs": [],
            **({"pattern": "clean.ts"} if disposition == "not_applicable" else {}),
        }
    ]
    coverage_path.write_text(json.dumps(coverage))
    run_workbench(
        state, "fail-scan", "--scan-id", scan_id, "--message", "Interrupted after validation"
    )

    assert json.loads(findings_path.read_text())["findings"] == []
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert result["findingCount"] == 0


@pytest.mark.parametrize(
    ("mode", "pending_validation"), [("standard", False), ("deep", False), ("standard", True)]
)
def test_continuation_retains_unaccepted_findings_without_crediting_reviewed_files(
    tmp_path: Path, mode: str, pending_validation: bool
) -> None:
    if mode == "deep":
        state, parent, parent_id, _, _, _ = completed_deep_fixture(tmp_path)
        repository = tmp_path / "repository"
        # An accepted empty reducer must not erase separately retained evidence.
        for result in parent.glob("artifacts/deep_discovery/*/*/output/result.json"):
            payload = semantic(parent_id, [])
            payload["complete"] = True
            payload["coverage"].update(completeness="complete", deferred=[])
            result.write_text(json.dumps(payload))
            (result.parent / "checkpoint-head.json").unlink()
    else:
        state, repository, parent, parent_id = scan_fixture(tmp_path)
    accepted = semantic(parent_id, ["clean.ts"])
    accepted["coverage"]["deferred"] = []
    if pending_validation:
        accepted["complete"] = True
        accepted["coverage"].update(
            completeness="complete", reviewedFiles=["clean.ts", "pending.ts"]
        )
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["writeup"] = {"reportPath": "findings/retained/retained.md"}
    finding["extensions"] = {"receiptRefs": ["artifacts/review/retained.json"]}
    artifacts = {
        "findings/retained/retained.md": b"# Retained finding\n\n[Proof](poc/example.bin)\n",
        "findings/retained/poc/example.bin": b"\x00retained proof\xff",
        "artifacts/review/retained.json": b'{"evidence": "saved before acceptance"}\n',
    }
    for relative, contents in artifacts.items():
        artifact = parent / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(contents)
    unaccepted = semantic(parent_id, ["clean.ts", "pending.ts"])
    unaccepted["complete"] = True
    unaccepted["findings"] = [finding]
    unaccepted["coverage"] = json.loads((contract / "coverage.json").read_text())
    unaccepted["coverage"]["reviewedFiles"] = ["clean.ts", "pending.ts"]
    unaccepted["coverage"]["surfaces"][0]["receiptRefs"] = ["artifacts/review/retained.json"]
    if pending_validation:
        unaccepted["complete"] = False
        unaccepted["coverage"].update(
            completeness="partial",
            deferred=[
                {
                    "id": "retained-validation",
                    "candidateId": "retained-validation",
                    "reason": "Additional source validation remains unresolved.",
                }
            ],
        )
    path = write_checkpoint(parent / "checkpoints", unaccepted)
    original = path.read_bytes()
    run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        parent_id,
        "--message",
        "Stopped before checkpoint acceptance",
    )
    retained = json.loads((parent / "findings.json").read_text())["findings"]
    assert len(retained) == 1
    seal = (parent / "scan-manifest.json").read_bytes()
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child = tmp_path / "continued"
    child.mkdir(mode=0o700)
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
    result = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    reviewed = ["clean.ts", "pending.ts"] if pending_validation else ["clean.ts"]
    assert result["checkpoint"]["reviewedFiles"] == reviewed
    assert result["checkpoint"]["remainingFiles"] == ([] if pending_validation else ["pending.ts"])
    assert result["completionReady"] is False
    continued = json.loads((child / "findings.json").read_text())["findings"]
    assert len(continued) == 1
    assert continued[0]["title"] == retained[0]["title"]
    assert continued[0]["codeEvidence"] == retained[0]["codeEvidence"]
    assert continued[0]["writeup"] == finding["writeup"]
    assert continued[0]["extensions"] == retained[0]["extensions"]
    for relative, contents in artifacts.items():
        assert (child / relative).read_bytes() == contents
    coverage = json.loads((child / "coverage.json").read_text())
    if mode == "standard":
        assert any(
            "artifacts/review/retained.json" in item.get("receiptRefs", [])
            for item in coverage["surfaces"]
        )
    assert all(item.get("id") != "scan-stopped" for item in coverage["deferred"])
    if pending_validation:
        assert any(
            item.get("candidateId") == "retained-validation" for item in coverage["deferred"]
        )
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    assert resumed["checkpoint"]["reviewedFiles"] == reviewed
    assert resumed["checkpoint"]["sources"][0]["complete"] is False
    assert resumed["checkpoint"]["sources"][0]["findings"][0]["title"] == finding["title"]
    assert (parent / "scan-manifest.json").read_bytes() == seal
    assert path.read_bytes() == original
