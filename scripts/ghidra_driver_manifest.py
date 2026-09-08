#!/usr/bin/env python3
"""State and evidence manifests for ghidra-decompile.sh."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def project_sha256(project_dir, project_name):
    """Hash all persistent files belonging to one closed Ghidra project."""
    project_dir = Path(project_dir)
    roots = [project_dir / (project_name + ".gpr"), project_dir / (project_name + ".rep")]
    if not roots[0].is_file() or not roots[1].is_dir():
        raise FileNotFoundError("project requires both .gpr and .rep")
    files = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    if not files:
        raise FileNotFoundError("project has no persistent files")
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: str(item.relative_to(project_dir))):
        relative = str(path.relative_to(project_dir)).encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def ghidra_version(headless):
    for parent in headless.parents:
        properties = parent / "Ghidra" / "application.properties"
        if properties.is_file():
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    return "unknown"


def fingerprint(args):
    artifact = Path(args.artifact).resolve()
    headless = Path(args.headless).resolve()
    scripts = [Path(item).resolve() for item in args.script]
    value = {
        "schema": 1,
        "artifact": {
            "path": str(artifact),
            "sha256": sha256(artifact),
            "size": artifact.stat().st_size,
        },
        "ghidra": {
            "analyzeHeadless": str(headless),
            "analyzeHeadlessSha256": sha256(headless),
            "version": ghidra_version(headless),
        },
        "toolScripts": [
            {"name": path.name, "sha256": sha256(path)} for path in sorted(scripts)
        ],
        "analysis": {
            "loader": "ELF",
            "processor": args.processor or None,
            "autoAnalysis": not args.no_analysis,
            "settingsProfile": "ghidra-default-v1",
        },
    }
    write_json(Path(args.output), value)
    print(sha256(Path(args.output)))


def select_project(args):
    project_dir = Path(args.project_dir)
    wanted = json.loads(Path(args.fingerprint).read_text(encoding="utf-8"))
    if not project_dir.is_dir():
        return
    for marker in sorted(project_dir.glob("*.analysis-manifest.json")):
        try:
            value = json.loads(marker.read_text(encoding="utf-8"))
            name = value["projectName"]
            actual_project_hash = project_sha256(project_dir, name)
            if (value.get("status") == "complete" and value.get("fingerprint") == wanted
                    and value.get("projectSha256") == actual_project_hash):
                print(name)
                return
        except (OSError, ValueError, KeyError, TypeError):
            continue


def read_targets(path):
    if not path:
        return []
    values = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line.split("\t", 1)[0].strip())
    return values


def finalize(args):
    run_dir = Path(args.run_dir).resolve()
    fingerprint_value = json.loads(Path(args.fingerprint).read_text(encoding="utf-8"))
    status_paths = sorted(run_dir.glob("**/export-status.json"))
    statuses = []
    invalid_status = None
    for path in status_paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            for field in ("complete", "requested", "matched", "unmatched", "failed",
                          "dumped", "program"):
                if field not in value:
                    raise ValueError("missing field " + field)
            if type(value["complete"]) is not bool:
                raise TypeError("complete must be a boolean")
            for field in ("requested", "matched", "unmatched", "failed"):
                if (not isinstance(value[field], list)
                        or any(not isinstance(item, str) for item in value[field])):
                    raise TypeError(field + " must be an array of strings")
            if (type(value["dumped"]) is not int or value["dumped"] < 0
                    or not isinstance(value["program"], str) or not value["program"]):
                raise TypeError("invalid dumped or program field")
            program_requested = set(value["requested"])
            program_matched = set(value["matched"])
            if program_matched - program_requested:
                raise ValueError("matched contains a target that was not requested")
            if set(value["unmatched"]) != program_requested - program_matched:
                raise ValueError("unmatched is inconsistent with requested and matched")
            if value["complete"] and value["failed"]:
                raise ValueError("complete export contains failed functions")
            statuses.append(value)
        except (OSError, ValueError, TypeError) as error:
            invalid_status = f"{path.relative_to(run_dir)}: {error}"
            break

    expected = set(read_targets(args.targets))
    expected_programs = set(read_targets(args.expected_programs))
    actual_programs = [value["program"] for value in statuses]
    requested = {item for value in statuses for item in value.get("requested", [])}
    matched = {item for value in statuses for item in value.get("matched", [])}
    failed = [item for value in statuses for item in value.get("failed", [])]
    unmatched = sorted(expected - matched)

    if args.headless_rc != 0:
        state = "headless-failed"
        reason = f"analyzeHeadless exited with status {args.headless_rc}"
    elif invalid_status:
        state = "export-incomplete"
        reason = "invalid export status: " + invalid_status
    elif not statuses:
        state = "export-incomplete"
        reason = "no export-status.json was produced"
    elif any(not value.get("complete") for value in statuses) or failed:
        state = "export-incomplete"
        reason = "one or more program exports failed or were cancelled"
    elif (len(actual_programs) != len(set(actual_programs))
          or set(actual_programs) != expected_programs):
        state = "export-incomplete"
        reason = ("program export inventory mismatch; expected "
                  + ", ".join(sorted(expected_programs)) + "; got "
                  + ", ".join(sorted(actual_programs)))
    elif expected and requested != expected:
        state = "export-incomplete"
        reason = "export status did not record the exact requested target set"
    elif unmatched:
        state = "targets-unmatched"
        reason = "requested targets were not found: " + ", ".join(unmatched)
    else:
        state = "complete"
        reason = None

    files = []
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file()):
        if path.name == "run-manifest.json":
            continue
        files.append({
            "path": str(path.relative_to(run_dir)),
            "size": path.stat().st_size,
            "sha256": sha256(path),
        })
    project_hash = None
    if state == "complete" and args.analysis_marker:
        if not args.project_dir:
            state = "export-incomplete"
            reason = "project directory is required for an analysis marker"
        else:
            try:
                project_hash = project_sha256(args.project_dir, args.project_name)
            except OSError as error:
                state = "export-incomplete"
                reason = f"could not hash completed project: {error}"

    manifest = {
        "schema": 1,
        "status": state,
        "reason": reason,
        "mode": args.mode,
        "projectName": args.project_name,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "fingerprint": fingerprint_value,
        "targets": {
            "requested": sorted(expected),
            "matched": sorted(matched),
            "unmatched": unmatched,
        },
        "programs": {
            "expected": sorted(expected_programs),
            "exported": sorted(actual_programs),
        },
        "programStatuses": statuses,
        "files": files,
    }
    write_json(run_dir / "run-manifest.json", manifest)

    if state == "complete" and args.analysis_marker:
        write_json(Path(args.analysis_marker), {
            "schema": 1,
            "status": "complete",
            "completedAt": manifest["createdAt"],
            "projectName": args.project_name,
            "projectSha256": project_hash,
            "fingerprint": fingerprint_value,
        })
    if state != "complete":
        print(reason, file=sys.stderr)
        return 1
    return 0


def parser():
    top = argparse.ArgumentParser()
    sub = top.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("fingerprint")
    fp.add_argument("--artifact", required=True)
    fp.add_argument("--headless", required=True)
    fp.add_argument("--script", action="append", required=True)
    fp.add_argument("--processor", default="")
    fp.add_argument("--no-analysis", action="store_true")
    fp.add_argument("--output", required=True)

    select = sub.add_parser("select-project")
    select.add_argument("--project-dir", required=True)
    select.add_argument("--fingerprint", required=True)

    finish = sub.add_parser("finalize")
    finish.add_argument("--run-dir", required=True)
    finish.add_argument("--fingerprint", required=True)
    finish.add_argument("--mode", choices=("import", "reprocess"), required=True)
    finish.add_argument("--project-name", required=True)
    finish.add_argument("--headless-rc", type=int, required=True)
    finish.add_argument("--targets")
    finish.add_argument("--expected-programs", required=True)
    finish.add_argument("--analysis-marker")
    finish.add_argument("--project-dir")
    return top


def main():
    args = parser().parse_args()
    if args.command == "fingerprint":
        fingerprint(args)
        return 0
    if args.command == "select-project":
        select_project(args)
        return 0
    return finalize(args)


if __name__ == "__main__":
    raise SystemExit(main())
