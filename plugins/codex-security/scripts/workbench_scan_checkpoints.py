"""Durable semantic checkpoints for running CLI scans."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

from finalize_scan_contract import open_scan_local_file_descriptor, write_scan_local_bytes
from workbench_target import git_directory_snapshot_paths, source_directory_snapshot_paths
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
        if selected.is_file():
            paths.add(selected)
        else:
            selected_paths = git_directory_snapshot_paths(selected)
            paths.update(
                source_directory_snapshot_paths(selected)
                if selected_paths is None
                else selected_paths
            )
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


def record_checkpoint(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    checkpoint_path: Path,
    timestamp: str,
) -> dict[str, Any]:
    """Index a bound immutable artifact; replay is safe after an interrupted projection."""
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
    result = {"scanId": scan["id"], "checkpointPath": relative.as_posix(), "digest": digest}
    if connection.execute(
        "SELECT 1 FROM scan_checkpoints WHERE scan_id = ? AND source_path = ? AND content_sha256 = ?",
        (scan["id"], source, digest),
    ).fetchone():
        return result
    # The durable head closes the artifact/SQLite crash window. Only validated cumulative
    # snapshots advance it; replay never makes an older receipt current again.
    write_scan_local_bytes(
        root,
        (relative.parent.parent / "checkpoint-head.json").as_posix(),
        (json.dumps({"checkpoint": relative.name}) + "\n").encode(),
    )
    # A transaction commits both the semantic projection and completed source coverage.
    with connection:
        for path in set(reviewed):
            connection.execute(
                "UPDATE scan_review_files SET reviewed_at = COALESCE(reviewed_at, ?) "
                "WHERE scan_id = ? AND relative_path = ?",
                (timestamp, scan["id"], path),
            )
        connection.execute(
            "INSERT INTO scan_checkpoints (scan_id, source_path, checkpoint_path, content_sha256, "
            "snapshot_json, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan["id"], source, relative.as_posix(), digest, json.dumps(snapshot), timestamp),
        )
    return result


def checkpoint_state(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT * FROM scan_checkpoints WHERE sequence IN (SELECT MAX(sequence) "
        "FROM scan_checkpoints WHERE scan_id = ? GROUP BY source_path) ORDER BY source_path",
        (scan_id,),
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
        "WHERE scan_id = ? GROUP BY source_path) ORDER BY source_path",
        (scan_id,),
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
            name = json.load(handle).get("checkpoint")
        if not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
            raise SystemExit("The saved checkpoint head does not name a semantic checkpoint.")
        record_checkpoint(connection, scan, source / "checkpoints" / name, timestamp)


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


def continue_checkpoint(db: Any, connection: sqlite3.Connection, args: Any) -> dict[str, Any]:
    """Seed a new bound scan from saved semantic results without reopening its parent."""
    # Reuse the stopped-result merger so finding identity and evidence retention have one owner.
    from workbench_saved_results import merge_saved_results

    with db.scan_completion_lock(args.parent_scan_id), db.scan_completion_lock(args.scan_id):
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
        for source in checkpoint["sources"]:
            snapshot = {
                "scanId": child["id"],
                "complete": False,
                **{key: source[key] for key in ("scope", "threatModel") if key in source},
                "findings": source["findings"],
                "coverage": source["coverage"],
            }
            snapshot = db.deep_scan.rebind_checkpoint_result(snapshot, child["id"], worker_ids)
            contents = (json.dumps(snapshot, indent=2) + "\n").encode()
            write_scan_local_bytes(
                root, f"checkpoints/{hashlib.sha256(contents).hexdigest()}.json", contents
            )
        merged = merge_saved_results(
            root,
            child["id"],
            db.workbench_completion_binding(child, db.now()),
            [],
            [],
            stopped=False,
            reason="Continue saved source work",
            include_parent=False,
        )
        if merged is None:
            raise SystemExit("The saved semantic checkpoint could not seed the continuation.")
        manifest, findings, coverage = merged
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
        connection.execute(
            "UPDATE scans SET continuation_cost_json = ? WHERE id = ?",
            (db.parse_scan_cost(args.cost_json), child["id"]),
        )
        record_checkpoint(connection, child, path, db.now())
        for filename, document in (
            ("findings.json", findings),
            ("coverage.json", coverage),
            ("scan-manifest.json", manifest),
        ):
            write_scan_local_bytes(root, filename, (json.dumps(document, indent=2) + "\n").encode())
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
