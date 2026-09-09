"""Durable semantic checkpoints for running CLI scans."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)
from generate_rank_input import repo_scope_paths
from workbench_target import require_scan_target_identity
from workbench_validation import path_within_scope


def freeze_review_files(
    connection: sqlite3.Connection, scan_id: str, repository: Path, scopes: list[str]
) -> None:
    """Bind review declarations to selected source bytes without imposing a completion gate."""
    paths: set[Path] = set()
    for scope in scopes or ["."]:
        selected = repository / scope
        metadata = selected.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
            continue
        paths.update(repo_scope_paths(repository, selected))
    for path in sorted(paths):
        if not stat.S_ISREG(path.lstat().st_mode) or not path.resolve().is_relative_to(repository):
            continue
        connection.execute(
            "INSERT INTO scan_review_files (scan_id, relative_path, content_sha256) VALUES (?, ?, ?)",
            (scan_id, path.relative_to(repository).as_posix(), file_digest(path)),
        )


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_review_files(connection: sqlite3.Connection, scan: sqlite3.Row) -> None:
    """Backfill an upgraded scan's inventory only from its original source snapshot."""
    if connection.execute(
        "SELECT 1 FROM scan_review_files WHERE scan_id = ? LIMIT 1", (scan["id"],)
    ).fetchone():
        return
    from workbench_scan_start import scan_target_identity

    repository = require_scan_target_identity(scan)
    if scan_target_identity(repository, None) != (
        scan["target_revision"],
        scan["target_snapshot_digest"],
        scan["target_device"],
        scan["target_inode"],
    ):
        raise SystemExit("Cannot initialize checkpoints: the original source changed.")
    scopes = (
        json.loads(scan["recipe_json"])["target"]["paths"]
        if scan["recipe_json"]
        else [scan["scope"]]
    )
    freeze_review_files(connection, scan["id"], repository, scopes)


def record_checkpoint(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    checkpoint_path: Path,
    timestamp: str,
    *,
    commit: bool = True,
    publish_head: bool = True,
    acceptance_id: str | None = None,
) -> dict[str, Any]:
    """Accept a bound artifact, or replay the exact acceptance named by its durable head."""
    root = Path(scan["scan_dir"])
    try:
        relative = checkpoint_path.relative_to(root)
    except ValueError as exc:
        raise SystemExit("A scan checkpoint must be inside its registered scan directory.") from exc
    source = relative.parent.parent.as_posix()
    if relative.parent.name != "checkpoints":
        raise SystemExit("A scan checkpoint must belong to a checkpoint directory.")
    if source != ".":
        worker = connection.execute(
            "SELECT kind FROM deep_scan_workers WHERE scan_id = ? AND artifact_dir = ?",
            (scan["id"], str(root / source)),
        ).fetchone()
        if worker is None:
            raise SystemExit("The checkpoint does not belong to a registered scan worker.")
    descriptor = open_scan_local_file_descriptor(root, relative.as_posix(), "scan checkpoint")
    with os.fdopen(descriptor, "rb") as handle:
        contents = handle.read()
    digest = hashlib.sha256(contents).hexdigest()
    if relative.name != f"{digest}.json":
        # Older worker writers named pretty-printed files with the compact JSON
        # digest. Preserve their string escapes and number spelling when matching
        # that name; decoding and re-encoding JSON can change JavaScript's bytes.
        compact = re.sub(
            rb'"(?:\\.|[^"\\])*"|[ \t\r\n]+',
            lambda match: match[0] if match[0].startswith(b'"') else b"",
            contents,
        )
        if relative.name != f"{hashlib.sha256(compact).hexdigest()}.json":
            raise SystemExit("The checkpoint filename does not match its saved content.")
    snapshot = json.loads(contents)
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("scanId") != scan["id"]
        or not isinstance(snapshot.get("findings"), list)
        or any(not isinstance(finding, dict) for finding in snapshot["findings"])
    ):
        raise SystemExit("The checkpoint does not contain semantic results for this scan.")
    coverage = snapshot.get("coverage", {})
    if not isinstance(coverage, dict):
        raise SystemExit("The checkpoint has invalid semantic coverage.")
    reviewed = coverage.get("reviewedFiles", [])
    if not isinstance(reviewed, list) or any(not isinstance(path, str) for path in reviewed):
        raise SystemExit("Checkpoint reviewedFiles must contain repository-relative file paths.")
    if reviewed:
        ensure_review_files(connection, scan)
    for path in reviewed:
        row = connection.execute(
            "SELECT content_sha256 FROM scan_review_files WHERE scan_id = ? AND relative_path = ?",
            (scan["id"], path),
        ).fetchone()
        target = Path(scan["target_path"]) / path
        if (
            row is None
            or not path_within_scope(path, ".")
            or not target.resolve().is_relative_to(Path(scan["target_path"]))
            or target.is_symlink()
            or not target.is_file()
            or file_digest(target) != row["content_sha256"]
        ):
            raise SystemExit(f"Reviewed file is outside the saved inventory or changed: {path}")
    acceptance_id = acceptance_id or uuid.uuid4().hex
    result = {
        "scanId": scan["id"],
        "checkpointPath": relative.as_posix(),
        "digest": digest,
        "acceptanceId": acceptance_id,
    }
    existing = connection.execute(
        "SELECT content_sha256 FROM scan_checkpoints "
        "WHERE scan_id = ? AND source_path = ? AND acceptance_id = ?",
        (scan["id"], source, acceptance_id),
    ).fetchone()
    if existing:
        if existing["content_sha256"] != digest:
            raise SystemExit("The checkpoint acceptance refers to different saved content.")
        return result
    # Content can recur after a different decision. The head identifies this acceptance,
    # so a crash before its SQLite commit can be replayed without confusing it with an
    # older receipt for identical bytes.
    if publish_head:
        _write_checkpoint_head(root, relative, acceptance_id)
    # A transaction commits both the semantic projection and completed source coverage.
    with connection if commit else nullcontext():
        for path in set(reviewed):
            connection.execute(
                "UPDATE scan_review_files SET reviewed_at = COALESCE(reviewed_at, ?) "
                "WHERE scan_id = ? AND relative_path = ?",
                (timestamp, scan["id"], path),
            )
        connection.execute(
            "INSERT INTO scan_checkpoints (scan_id, source_path, checkpoint_path, content_sha256, "
            "snapshot_json, recorded_at, acceptance_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan["id"],
                source,
                relative.as_posix(),
                digest,
                json.dumps(snapshot),
                timestamp,
                acceptance_id,
            ),
        )
    return result


def _write_checkpoint_head(root: Path, relative: Path, acceptance_id: str) -> None:
    write_scan_local_bytes(
        root,
        (relative.parent.parent / "checkpoint-head.json").as_posix(),
        (json.dumps({"checkpoint": relative.name, "acceptanceId": acceptance_id}) + "\n").encode(),
    )


def checkpoint_state(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT * FROM scan_checkpoints WHERE sequence IN (SELECT MAX(sequence) "
        "FROM scan_checkpoints WHERE scan_id = ? GROUP BY source_path) OR "
        "(scan_id = ? AND acceptance_id = "
        "(SELECT continuation_checkpoint_acceptance_id FROM scans WHERE id = ?)) "
        "ORDER BY source_path, sequence",
        (scan_id, scan_id, scan_id),
    ).fetchall()
    if not rows:
        return None
    reviewed = connection.execute(
        "SELECT relative_path, reviewed_at FROM scan_review_files WHERE scan_id = ? "
        "ORDER BY relative_path",
        (scan_id,),
    ).fetchall()
    sources = []
    for row in rows:
        snapshot = json.loads(row["snapshot_json"])
        sources.append(
            {
                "source": row["source_path"],
                "checkpointPath": row["checkpoint_path"],
                "acceptanceId": row["acceptance_id"],
                "digest": row["content_sha256"],
                "savedAt": row["recorded_at"],
                "complete": snapshot.get("complete", True),
                **{key: snapshot[key] for key in ("scope", "threatModel") if key in snapshot},
                "findings": snapshot["findings"],
                "coverage": snapshot.get("coverage", {}),
            }
        )
    return {
        "status": "provisional",
        "savedAt": max(row["recorded_at"] for row in rows),
        "sources": sources,
        "reviewedFiles": [row["relative_path"] for row in reviewed if row["reviewed_at"]],
        "remainingFiles": [row["relative_path"] for row in reviewed if not row["reviewed_at"]],
    }


def checkpoint_summary(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    """Keep ordinary progress responses small; resume reads the full semantic state."""
    rows = connection.execute(
        "SELECT source_path, checkpoint_path, content_sha256, recorded_at, "
        "json_array_length(snapshot_json, '$.findings') AS findings, "
        "COALESCE(json_array_length(snapshot_json, '$.coverage.deferred'), 0) AS pending, "
        "COALESCE(json_extract(snapshot_json, '$.complete'), 1) AND "
        "json_extract(snapshot_json, '$.coverage.completeness') = 'complete' AS complete "
        "FROM scan_checkpoints WHERE sequence IN (SELECT MAX(sequence) FROM scan_checkpoints "
        "WHERE scan_id = ? GROUP BY source_path) OR "
        "(scan_id = ? AND acceptance_id = "
        "(SELECT continuation_checkpoint_acceptance_id FROM scans WHERE id = ?)) "
        "ORDER BY source_path, sequence",
        (scan_id, scan_id, scan_id),
    ).fetchall()
    if not rows:
        return None
    files = connection.execute(
        "SELECT COUNT(reviewed_at) AS reviewed, COUNT(*) - COUNT(reviewed_at) AS remaining "
        "FROM scan_review_files WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    return {
        "status": "provisional",
        "savedAt": max(row["recorded_at"] for row in rows),
        "findingCount": sum(row["findings"] for row in rows),
        "pendingCount": sum(row["pending"] for row in rows),
        "coverageComplete": all(row["complete"] for row in rows),
        "reviewedFileCount": files["reviewed"],
        "remainingFileCount": files["remaining"],
        "sources": [
            {
                "source": row["source_path"],
                "checkpointPath": row["checkpoint_path"],
                "digest": row["content_sha256"],
                "savedAt": row["recorded_at"],
            }
            for row in rows
        ],
    }


def reconcile_checkpoints(
    connection: sqlite3.Connection, scan: sqlite3.Row, timestamp: str
) -> None:
    """Complete artifact-to-database writes before a resumed scan incurs more work."""
    root = Path(scan["scan_dir"])
    sources = [
        root,
        *(
            Path(row["artifact_dir"])
            for row in connection.execute(
                "SELECT artifact_dir FROM deep_scan_workers WHERE scan_id = ?", (scan["id"],)
            )
        ),
    ]
    for source in sources:
        if not source.is_relative_to(root):
            raise SystemExit("The saved checkpoint directory is outside its bound scan.")
        head = source / "checkpoint-head.json"
        if not head.exists():
            continue
        descriptor = open_scan_local_file_descriptor(
            root, head.relative_to(root).as_posix(), "scan checkpoint head"
        )
        with os.fdopen(descriptor, "rb") as handle:
            saved_head = json.load(handle)
        name = saved_head.get("checkpoint")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise SystemExit("The saved checkpoint head does not name a semantic checkpoint.")
        acceptance_id = saved_head.get("acceptanceId")
        if acceptance_id is None:
            # Legacy heads only identify content. An already indexed snapshot is a replay,
            # never a new decision; otherwise accept it once and upgrade its head.
            existing = connection.execute(
                "SELECT acceptance_id FROM scan_checkpoints WHERE scan_id = ? AND checkpoint_path = ? "
                "ORDER BY sequence DESC LIMIT 1",
                (scan["id"], (source / "checkpoints" / name).relative_to(root).as_posix()),
            ).fetchone()
            if existing:
                acceptance_id = existing["acceptance_id"]
        elif not isinstance(acceptance_id, str) or not acceptance_id:
            raise SystemExit("The saved checkpoint head has an invalid acceptance identity.")
        record_checkpoint(
            connection,
            scan,
            source / "checkpoints" / name,
            timestamp,
            acceptance_id=acceptance_id,
        )


def checkpoint_completion_ready(checkpoint: dict[str, Any], mode: str) -> bool:
    return (
        mode == "standard"
        and not checkpoint["remainingFiles"]
        and all(
            source["complete"]
            and source["coverage"].get("completeness") == "complete"
            and not source["coverage"].get("deferred")
            for source in checkpoint["sources"]
        )
    )


def copy_checkpoint_artifacts(
    db: Any, parent: sqlite3.Row, child_root: Path, checkpoint: dict[str, Any]
) -> dict[str, str] | None:
    """Keep referenced evidence and derived hardening files with their saved result."""
    parent_root = db.require_canonical_scan_directory(Path(parent["scan_dir"]))
    parent_manifest = (
        _read_scan_local_json(parent_root, "scan-manifest.json", "Saved scan manifest")
        if parent["seal_manifest_digest"] is not None
        else None
    )
    sealed_artifacts = (
        {item["path"]: item["sha256"] for item in parent_manifest["scan"]["artifacts"]}
        if parent_manifest is not None
        else {}
    )
    files: set[str] = set()
    reports: set[str] = set()

    def references(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                references(item)
        elif isinstance(value, dict):
            writeup = value.get("writeup")
            report = writeup.get("reportPath") if isinstance(writeup, dict) else None
            if isinstance(report, str) and re.fullmatch(
                r"findings/([a-z0-9][a-z0-9._-]*)/\1\.md", report
            ):
                reports.add(report)
                files.add(report)
            for receipt in (
                value.get("receiptRefs", []) if isinstance(value.get("receiptRefs"), list) else []
            ):
                if isinstance(receipt, str) and receipt.startswith("artifacts/"):
                    files.add(receipt)
            for item in value.values():
                references(item)

    references(checkpoint["sources"])
    portfolio = "hardening/hardening.md"
    has_portfolio = bool(parent_manifest and parent_manifest["scan"].get("hardening")) or (
        (parent_root / portfolio).exists() or (parent_root / portfolio).is_symlink()
    )
    if has_portfolio:
        files.add(portfolio)
    directories_to_copy = [parent_root / Path(report).parent / "poc" for report in sorted(reports)]
    directories_to_copy.append(parent_root / "hardening")
    for evidence_dir in directories_to_copy:
        if not evidence_dir.exists() and not evidence_dir.is_symlink():
            continue
        db.deep_scan.deep_scan_path(
            parent, str(evidence_dir), "Saved report evidence", kind="directory"
        )
        for directory, directories, filenames in os.walk(evidence_dir, followlinks=False):
            for path in (Path(directory), *(Path(directory) / name for name in directories)):
                db.deep_scan.deep_scan_path(
                    parent, str(path), "Saved report evidence", kind="directory"
                )
            files.update(
                (Path(directory) / name).relative_to(parent_root).as_posix() for name in filenames
            )
    for relative in sorted(files):
        descriptor = open_scan_local_file_descriptor(
            parent_root, relative, "Saved checkpoint artifact"
        )
        with os.fdopen(descriptor, "rb") as source:
            contents = source.read()
        if (
            relative in sealed_artifacts
            and hashlib.sha256(contents).hexdigest() != sealed_artifacts[relative]
        ):
            raise ContractError(f"{relative}: sealed artifact changed after completion")
        write_scan_local_bytes(child_root, relative, contents)
    return {"portfolioPath": portfolio} if has_portfolio else None


def continue_checkpoint(db: Any, connection: sqlite3.Connection, args: Any) -> dict[str, Any]:
    """Seed a new bound scan from saved semantic results without reopening its parent."""
    # Reuse the stopped-result merger so finding identity and evidence retention have one owner.
    from workbench_saved_results import _candidate_owner, merge_saved_results

    with (
        db.scan_completion_lock(args.parent_scan_id),
        db.scan_completion_lock(args.scan_id),
        connection,
    ):
        parent = db.require_scan(connection, args.parent_scan_id)
        child = db.require_scan(connection, args.scan_id)
        if child["parent_scan_id"] != parent["id"] or child["status"] != "running":
            raise SystemExit(
                "Checkpoint continuation requires a new running child of the saved scan."
            )
        for field in (
            "target_path",
            "target_revision",
            "target_snapshot_digest",
            "target_device",
            "target_inode",
            "mode",
        ):
            if child[field] != parent[field]:
                raise SystemExit(
                    "Checkpoint continuation must use the original source and scan mode."
                )
        child_recipe, parent_recipe = (
            json.loads(child["recipe_json"]),
            json.loads(parent["recipe_json"]),
        )
        child_recipe.pop("pluginVersion", None)
        parent_recipe.pop("pluginVersion", None)
        if child_recipe != parent_recipe:
            raise SystemExit(
                "Checkpoint continuation must use the original target and launch recipe."
            )
        if parent["seal_manifest_digest"] is not None:
            db.require_recorded_manifest_digest(parent, Path(parent["scan_dir"]))
        reconcile_checkpoints(connection, parent, db.now())
        checkpoint = checkpoint_state(connection, parent["id"])
        if checkpoint is None:
            raise SystemExit("The parent scan has no saved semantic checkpoint to continue.")
        completion_ready = checkpoint_completion_ready(checkpoint, parent["mode"])
        worker_ids = db.deep_scan.restore_checkpoint_workers(connection, parent, child, db.now())
        root = db.require_canonical_scan_directory(Path(child["scan_dir"]))
        hardening = copy_checkpoint_artifacts(db, parent, root, checkpoint)
        sequence = {
            row["acceptance_id"]: row["sequence"]
            for row in connection.execute(
                "SELECT acceptance_id, sequence FROM scan_checkpoints WHERE scan_id = ?",
                (parent["id"],),
            )
        }
        sources = sorted(
            checkpoint["sources"],
            key=lambda source: sequence[source["acceptanceId"]],
            reverse=True,
        )
        current_checkpoints = []
        for source in sources:
            snapshot = {
                "scanId": child["id"],
                "complete": False,
                **{key: source[key] for key in ("scope", "threatModel") if key in source},
                "findings": source["findings"],
                "coverage": source["coverage"],
            }
            worker = connection.execute(
                "SELECT id, kind FROM deep_scan_workers WHERE scan_id = ? AND artifact_dir = ?",
                (parent["id"], str(Path(parent["scan_dir"]) / source["source"])),
            ).fetchone()
            snapshot = db.deep_scan.rebind_checkpoint_result(
                snapshot,
                child["id"],
                worker_ids,
                source_worker_id=worker["id"] if worker and worker["kind"] == "discovery" else None,
            )
            contents = (json.dumps(snapshot, indent=2) + "\n").encode()
            relative = f"checkpoints/{hashlib.sha256(contents).hexdigest()}.json"
            write_scan_local_bytes(root, relative, contents)
            if source["acceptanceId"] != parent["continuation_checkpoint_acceptance_id"]:
                current_checkpoints.append(relative)
        workers = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ?", (child["id"],)
        ).fetchall()
        merged = merge_saved_results(
            root,
            child["id"],
            db.workbench_completion_binding(child, db.now()),
            workers,
            [],
            stopped=False,
            reason="Continue saved source work",
            include_parent=False,
            current_checkpoint_paths=current_checkpoints,
        )
        if merged is None:
            raise SystemExit("The saved semantic checkpoint could not seed the continuation.")
        manifest, findings, coverage = merged
        for worker in workers:
            if worker["kind"] != "discovery" or worker["status"] != "queued":
                continue
            source_path = Path(worker["artifact_dir"]).relative_to(root).as_posix()
            saved = connection.execute(
                "SELECT snapshot_json FROM scan_checkpoints WHERE scan_id = ? AND source_path = ? "
                "ORDER BY sequence DESC LIMIT 1",
                (child["id"], source_path),
            ).fetchone()
            worker_snapshot = json.loads(saved["snapshot_json"])
            # The aggregate contains the latest decisions for each mapped owner.
            # Keep per-pass source coverage and scope, and carry those decisions
            # into the actual checkpoint the queued worker will read.
            worker_snapshot["findings"] = [
                finding
                for finding in findings["findings"]
                if _candidate_owner(finding, None) == worker["id"]
            ]
            for field in ("surfaces", "explicitExclusions", "deferred"):
                worker_snapshot["coverage"][field] = [
                    item
                    for item in coverage.get(field, [])
                    if _candidate_owner(item, None) == worker["id"]
                ]
            worker_contents = (json.dumps(worker_snapshot, indent=2) + "\n").encode()
            worker_path = (
                f"{source_path}/checkpoints/{hashlib.sha256(worker_contents).hexdigest()}.json"
            )
            write_scan_local_bytes(root, worker_path, worker_contents)
            record_checkpoint(connection, child, root / worker_path, db.now(), commit=False)
        root_source = next((source for source in sources if source["source"] == "."), None)
        if root_source is not None and isinstance(root_source.get("scope"), dict):
            manifest["scan"]["scope"] = {
                **root_source["scope"],
                **manifest["scan"]["scope"],
            }
        if hardening is not None:
            manifest["scan"]["hardening"] = hardening
        manifest["scan"]["complete"] = completion_ready
        coverage["completeness"] = "complete" if completion_ready else "partial"
        coverage["reviewedFiles"] = checkpoint["reviewedFiles"]
        snapshot = {
            "scanId": child["id"],
            "complete": completion_ready,
            **{
                key: manifest["scan"][key]
                for key in ("scope", "threatModel")
                if key in manifest["scan"]
            },
            "findings": findings["findings"],
            "coverage": coverage,
        }
        contents = (json.dumps(snapshot, indent=2) + "\n").encode()
        path = root / "checkpoints" / f"{hashlib.sha256(contents).hexdigest()}.json"
        write_scan_local_bytes(root, path.relative_to(root).as_posix(), contents)
        receipt = record_checkpoint(
            connection, child, path, db.now(), commit=False, publish_head=False
        )
        connection.execute(
            "UPDATE scans SET continuation_cost_json = ?, continuation_checkpoint_path = ?, "
            "continuation_checkpoint_acceptance_id = ? WHERE id = ?",
            (
                db.parse_scan_cost(args.cost_json),
                path.relative_to(root).as_posix() if child["mode"] == "deep" else None,
                receipt["acceptanceId"] if child["mode"] == "deep" else None,
                child["id"],
            ),
        )
        for filename, document in (
            ("findings.json", findings),
            ("coverage.json", coverage),
            ("scan-manifest.json", manifest),
        ):
            write_scan_local_bytes(root, filename, (json.dumps(document, indent=2) + "\n").encode())
        # Worker receipts, inherited spend, and the aggregate baseline become durable
        # together. Until then, no root head may expose this child to reconciliation.
        # Commit explicitly even when record_checkpoint replayed an existing receipt.
        connection.commit()
        _write_checkpoint_head(root, path.relative_to(root), receipt["acceptanceId"])
        if parent["status"] == "running":
            timestamp = db.now()
            message = f"Interrupted; continued from saved checkpoints in scan {child['id']}."
            with connection:
                connection.execute(
                    "UPDATE scans SET status = 'failed', failure_message = ?, completed_at = ?, "
                    "updated_at = ? WHERE id = ? AND status = 'running'",
                    (message, timestamp, timestamp, parent["id"]),
                )
                connection.execute(
                    "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                    (timestamp, parent["id"]),
                )
                db.deep_scan.fail_from_parent_scan(connection, parent["id"], message, timestamp)
        return {
            "checkpoint": checkpoint_state(connection, child["id"]),
            "completionReady": completion_ready,
            "restoredWorkers": len(worker_ids),
        }


def continued_deep_documents(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    binding: dict[str, Any],
    warnings: list[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Preserve inherited work when a continued coordinator publishes its result.

    A partial worker is not a completed independent pass. Its saved findings and
    pending evidence still belong in the final result, even if the deadline means
    that the resumed coordinator cannot dispatch another discovery.
    """
    from workbench_saved_results import _digest, _read_saved_result, merge_saved_results

    relative = scan["continuation_checkpoint_path"]
    if scan["mode"] != "deep" or relative is None:
        return None
    saved = connection.execute(
        "SELECT snapshot_json FROM scan_checkpoints WHERE scan_id = ? AND checkpoint_path = ? "
        "AND acceptance_id = ?",
        (scan["id"], relative, scan["continuation_checkpoint_acceptance_id"]),
    ).fetchone()
    if saved is None:
        raise SystemExit("The continuation's inherited checkpoint is missing from saved state.")
    root = Path(scan["scan_dir"])
    _, digest = _read_saved_result(root, relative, scan["id"])
    if digest != _digest(json.loads(saved["snapshot_json"])):
        raise SystemExit("The continuation's inherited checkpoint changed after it was saved.")
    workers = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ? AND status = 'succeeded'",
        (scan["id"],),
    ).fetchall()
    frozen = {relative: digest}
    for worker in workers:
        if worker["kind"] not in {"discovery", "dedup"}:
            continue
        result_path = Path(worker["result_manifest_path"]).relative_to(root).as_posix()
        _, worker_digest = _read_saved_result(root, result_path, scan["id"], kind=worker["kind"])
        frozen[result_path] = worker_digest
    return merge_saved_results(
        root,
        scan["id"],
        binding,
        workers,
        warnings,
        stopped=False,
        reason="",
        frozen_source_digests=frozen,
        allow_frozen_legacy_parent=True,
        preserve_sources={relative},
    )
