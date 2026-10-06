"""Read hash-bound MintID trace triples through installed raw admission.

This finite profile checks recorded facts. It does not contact a service, verify
an ICS23/BBS proof, authenticate an operator or infer an external action.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_BYTES = 20 << 20  # Existing jcs-admit/Go adapter default; never widened.
MAX_DEPTH = 128
SCHEMA = "mintid-trace-manifest/2"
META = frozenset(("utc", "unix", "t", "kind"))
REFUSALS = frozenset(("credential_revoked", "witness_not_usable"))


class Refused(ValueError):
    """A specific input, binding or record refusal."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def require(condition: bool, code: str, detail: str) -> None:
    if not condition:
        raise Refused(code, detail)


def strict_json(raw: bytes) -> Any:
    """Decode only after raw admission; refuse hostile command responses too."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "DuplicateMember", key)
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise Refused("NonFiniteNumber", value)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refused("InvalidJSON", str(error)) from error


def read_member(directory: Path, filename: str) -> bytes:
    """Open one canonical basename without following a symlink; bound reads."""
    require(filename == Path(filename).name and filename not in ("", ".", ".."), "MemberPath", filename)
    require(directory.absolute() == directory.resolve() and directory.is_dir(), "MemberPath", "canonical record directory")
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode), "MemberType", filename)
            require(info.st_size <= MAX_BYTES, "TooLarge", filename)
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "TooLarge", filename)
        return raw
    except OSError as error:
        raise Refused("MemberUnavailable", filename) from error


class Admission:
    """Trusted absolute installed commands admit original JSON bytes first."""

    def __init__(self, go: Path, admission: Path, capture: Path):
        for command in (go, admission):
            require(command.is_absolute() and command.is_file() and os.access(command, os.X_OK), "CommandUnavailable", str(command))
        require(capture.is_absolute() and capture.absolute() == capture.resolve() and not capture.exists(), "CapturePath", "new canonical capture directory")
        try:
            capture.mkdir(parents=True, mode=0o700)
        except OSError as error:
            raise Refused("CaptureUnavailable", str(capture)) from error
        self.capture = capture
        self.go = go
        self.admission = admission
        self.calls: list[dict[str, Any]] = []

    def document(self, raw: bytes, member: str) -> Any:
        require(len(raw) <= MAX_BYTES, "TooLarge", member)
        argv = [str(self.go), "--admission", str(self.admission), "--profile", "ijson", "--max-depth", str(MAX_DEPTH), "--max-bytes", str(MAX_BYTES)]
        # Disk spooling bounds Python memory. A trusted writer can emit at most
        # two hex characters per admitted input byte plus its JSON envelope.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            child = subprocess.run(argv, input=raw, stdout=output, stderr=errors)
            output.seek(0); response = output.read(2 * MAX_BYTES + 4096)
            errors.seek(0); stderr = errors.read(MAX_BYTES + 1)
            require(output.read(1) == b"" and len(stderr) <= MAX_BYTES, "CommandProtocol", "unbounded command response")
        receipt = {"member": member, "input_bytes": len(raw), "input_sha256": hashlib.sha256(raw).hexdigest(), "native_exit": child.returncode, "stdout_sha256": hashlib.sha256(response).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}
        call = self.capture / f"call-{len(self.calls) + 1:06d}"
        call.mkdir(mode=0o700)
        (call / "stdin.bin").write_bytes(raw)
        (call / "stdout.bin").write_bytes(response)
        (call / "stderr.bin").write_bytes(stderr)
        (call / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
        self.calls.append(receipt)
        require(child.returncode == 0 and not stderr, "CommandFailed", member)
        outcome = strict_json(response)
        require(type(outcome) is dict, "CommandProtocol", "response object")
        if outcome.get("status") == "refused":
            require(set(outcome) == {"status", "stage", "error_class"} and all(type(outcome[key]) is str for key in outcome), "CommandProtocol", "refusal fields")
            raise Refused(outcome["error_class"], member)
        require(set(outcome) == {"status", "stage", "canonical_hex"} and outcome["status"] == "accepted" and outcome["stage"] == "byte-agreement", "CommandProtocol", "accepted fields")
        require(type(outcome["canonical_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2})+", outcome["canonical_hex"]) is not None, "CommandProtocol", "canonical bytes")
        # Parse the original bytes, not a writer's replacement. The native
        # adapter already required exact Go/admission canonical agreement.
        value = strict_json(raw)
        require(type(value) in (dict, list), "ObjectOrArrayRequired", member)
        return value


def exact(left: Any, right: Any) -> bool:
    """JSON equality with exact scalar types; bool never stands for int."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(exact(left[key], right[key]) for key in left)
    if type(left) is list:
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def stripped(event: dict[str, Any] | None, *drop: str) -> dict[str, Any] | None:
    return None if event is None else {key: value for key, value in event.items() if key not in META and key not in drop}


def one(events: list[dict[str, Any]], kind: str, **match: Any) -> dict[str, Any] | None:
    selected = [event for event in events if event["kind"] == kind and all(exact(event.get(key), value) for key, value in match.items())]
    require(len(selected) <= 1, "AmbiguousEvent", kind)
    return selected[0] if selected else None


def delta(at: Any, origin: Any) -> float | None:
    if at is None or origin is None:
        return None
    require(type(at) in (int, float) and type(origin) in (int, float) and math.isfinite(at) and math.isfinite(origin), "InvalidTime", "relative clock")
    return round(at - origin, 1)


def root(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not entry:
        return None
    require(type(entry) is dict, "RootShape", "root object")
    for key in ("status_epoch", "finalized_height", "generated_at_unix"):
        require(entry.get(key) is None or type(entry[key]) is int, "RootShape", key)
    require(entry.get("emergency") is None or type(entry["emergency"]) is bool, "RootShape", "emergency")
    return {key: entry.get(key) for key in ("status_epoch", "finalized_height", "generated_at_unix", "finalized_at_utc", "emergency")}


def inspect_events(events: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    decisions: dict[str, dict[str, Any]] = {}
    logs: dict[str, dict[str, Any]] = {}
    for event in events:
        require(type(event) is dict and type(event.get("kind")) is str, "EventShape", "kind")
        if event["kind"] not in ("decision", "decision_log_line"):
            continue
        session = event.get("session_id")
        require(type(session) is str and bool(session), "EventShape", "session identity")
        if event["kind"] == "decision":
            require(session not in decisions, "AmbiguousDecision", session)
            require(type(event.get("accepted")) is bool and type(event.get("reason_code")) is str, "DecisionShape", session)
            decisions[session] = event
        else:
            line = event.get("line")
            require(type(line) is dict and session not in logs, "AmbiguousDecisionLog", session)
            require(line.get("session_id") == session and type(line.get("accepted")) is bool, "DecisionLogShape", session)
            for key in ("condition", "root_epoch", "root_height", "root_age_seconds"):
                require(line.get(key) is None or type(line[key]) is int, "DecisionLogShape", key)
            logs[session] = line
    for session, line in logs.items():
        require(session in decisions, "UnboundDecisionLog", session)
        event = decisions[session]
        require(exact(line["accepted"], event["accepted"]) and exact(line.get("reason_code"), event["reason_code"]), "DecisionLogMismatch", session)
    return decisions, logs


def decision(event: dict[str, Any] | None, logs: dict[str, dict[str, Any]], origin: Any, decisions: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if event is None:
        return None
    session = event.get("session_id")
    require(session in decisions, "UnboundSummaryDecision", str(session))
    recorded = decisions[session]
    # The summary may attach a ring/refusal explanation after the event. The
    # original event fields must still match, including the decision outcome.
    require(all(key in event and exact(event[key], value) for key, value in recorded.items()), "SummaryDecisionMismatch", str(session))
    line = logs.get(session)
    return {"utc": event.get("utc"), "seconds_after_t0": delta(event.get("unix"), origin), "session_id": session, "accepted": event.get("accepted"), "reason_code": event.get("reason_code"), "chain_height_after": event.get("chain_height_after"), "decision_log": None if line is None else {key: line.get(key) for key in ("condition", "root_epoch", "root_height", "root_age_seconds")}}


def refresh(events: list[dict[str, Any]], path: str, agent: str | None, origin: Any, control: bool) -> dict[str, Any]:
    selected = [event for event in events if event["kind"] == "holder_refresh" and event.get("path") == path and event.get("agent") == agent]
    refused = [event for event in selected if event.get("outcome") in REFUSALS]
    other = [event for event in selected if event.get("outcome") == ("refreshed" if control else "not_refused_within_budget")]
    hit = (refused or other or [None])[0]
    observation = "refused" if refused else hit["outcome"] if hit else "not_recorded"
    return {"observation": observation, "outcome": hit["outcome"] if refused else None, "utc": hit.get("utc") if hit else None, "seconds_after_t0": delta(hit.get("unix"), origin) if hit else None}


def paths(summary: dict[str, Any], events: list[dict[str, Any]], logs: dict[str, dict[str, Any]], decisions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in summary.get("results", []):
        path = result.get("path")
        require(path in ("issuer", "kill_switch", "cascade", "emergency", "unreachable") and path not in seen, "PathShape", str(path))
        seen.add(path)
        if result.get("skipped"):
            out.append({"path": path, "skipped": result["skipped"]}); continue
        origin = result.get("t0")
        decide = lambda event, clock=origin: decision(event, logs, clock, decisions)
        if path == "unreachable":
            during = result.get("during", [])
            for observed in during:
                if observed.get("kind") == "challenge_during_outage":
                    require(any(exact(event, observed) for event in events if event["kind"] == "challenge_during_outage"), "UnboundOutageChallenge", path)
            out.append({"path": path, "t0_unix": origin, "t0_definition": result.get("t0_def"), "restored_seconds_after_t0": delta(result.get("restored_unix"), origin), "decided_during_outage": [decide(event) for event in during if event.get("kind") == "decision"], "challenges_during_outage": [{"utc": event.get("utc"), "seconds_after_t0": delta(event.get("unix"), origin), "http": event.get("http"), "error": event.get("error")} for event in during if event.get("kind") == "challenge_during_outage"], "first_accepted_after_restore": decide(result.get("first_accepted_after"), result.get("restored_unix"))}); continue
        common = {"t0_unix": origin, "t0_definition": result.get("t0_def"), "bound_seconds": result.get("bound_seconds"), "bound_formula": result.get("bound_formula")}
        require(type(common["bound_seconds"]) in (int, float), "PathShape", "bound")
        entries = list((result.get("per_agent") or {}).items()) if path == "cascade" else [(None, result)]
        for agent, item in entries:
            no = item.get("first_no")
            ring = (no or {}).get("ring_at_denial") or []
            if ring:
                ring_event = one(events, "ring_at_denial", path=path, agent=(no or {}).get("agent"))
                require(ring_event is not None and exact(ring_event.get("ring"), ring), "RingBindingMismatch", path)
            carrying = result.get("trigger_root") if path == "cascade" else result.get("carrying_root")
            row = {"path": path, **({"agent": agent} if path == "cascade" else {}), **common, "last_accepted": decide(item.get("last_ok")), "first_refused": decide(no), "root_at_denial": root(ring[-1]) if ring else None, "root_carrying_revocation": root(carrying), "refresh_refused_seconds_after_t0": delta(item.get("refresh_failed_at"), origin)}
            forced = [event.get("agent") for event in events if event["kind"] == "decision" and event.get("path") == path and event.get("attempt") == "forced"]
            label = agent if agent is not None else forced[0] if forced else None
            attribution = {"revoked": {"agent": label, "refresh": refresh(events, path, label, origin, False)}, "control": None}
            if path == "issuer" and result.get("control") is not None:
                controls = result["control"]
                yes = [event for event in controls if event.get("accepted") is True]
                no_control = next((event for event in controls if event.get("accepted") is False), None)
                row["control_never_revoked"] = {"last_accepted": decide(yes[-1] if yes else None), "first_refused": decide(no_control), "after_refresh": decide(result.get("control_refreshed"))}
                attribution["control"] = {"agent": "sibling_control", "refused": decide(no_control), "refresh": refresh(events, path, "sibling_control", origin, True), "after_refresh": decide(result.get("control_refreshed"))}
            row["attribution"] = attribution
            out.append(row)
    return out


def derive(stem: str, events: list[dict[str, Any]], stated: Any, files: dict[str, str]) -> dict[str, Any]:
    """Independently project the finite published manifest-v2 contract."""
    decisions, logs = inspect_events(events)
    stack = one(events, "stack") or {}
    source = one(events, "source")
    build = one(events, "build")
    policy = one(events, "policy")
    before = stripped(one(events, "verifier_status", when="before"), "when")
    after = stripped(one(events, "verifier_status", when="after"), "when")
    parameters = stripped(one(events, "parameters"))
    summary = one(events, "summary")
    require(summary is not None and type(summary.get("results")) is list, "MissingSummary", stem)
    require(stated is None or type(stated) is dict and set(stated) <= {"source_revision", "services_revision"} and all(type(value) is str and bool(value) for value in stated.values()), "StatedShape", stem)
    deployment = {"target": stem.split("-")[2], "chain_id": stack.get("chain_id"), "issuer_id": stack.get("issuer_id"), "verifier_id": stack.get("verifier_id"), "kyc_provider": stack.get("kyc_provider"), "endpoints": {key: stack.get(key) for key in ("issuer_url", "verifier_url", "rpc", "relay")}, "build": stripped(build), "parameters": parameters, **{key: (before or {}).get(key) for key in ("max_root_age_seconds", "heartbeat_seconds", "max_height_lag")}}
    if build and type(build.get("issuer")) is dict:
        services = {}
        for name in ("verifier", "issuer"):
            served = build.get(name) or {}; revision = served.get("source_revision"); fallback = (source or {}).get("services_revision_stated") or None
            services[name] = {"source_revision": revision if revision not in (None, "", "unknown") else fallback, "release": served.get("release") if revision not in (None, "", "unknown") else None, "basis": "build-info" if revision not in (None, "", "unknown") else "stated" if fallback else None}
        deployment["services"] = services
    policy_fields = None
    if policy:
        policy_fields = {key: policy.get(key) for key in ("claim_policy", "issuer_policy", "sha256")}
        # MintID's declared policy digest uses Python's sorted compact JSON.
        # It is not relabeled as an RFC8785/JCS digest.
        encoded = json.dumps({key: policy[key] for key in ("claim_policy", "issuer_policy")}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        require(policy.get("sha256") == hashlib.sha256(encoded).hexdigest(), "PolicyHashMismatch", stem)
    projected_decisions = []
    for event in events:
        if event["kind"] == "decision":
            line = logs.get(event["session_id"], {})
            projected_decisions.append({**{key: event.get(key) for key in ("utc", "path", "agent", "attempt", "accepted", "reason_code")}, **{key: line.get(key) for key in ("condition", "root_epoch", "root_height", "root_age_seconds")}})
    return {"schema": SCHEMA, "record": stem, "derived": source is None, "started_utc": events[0].get("utc"), "source": stripped(source), "stated": stated, "deployment": deployment, "policy": policy_fields, "verifier_status": {"before": before, "after": after}, "decision_log_source": (one(events, "decision_log") or {}).get("source"), "paths": paths(summary, events, logs, decisions), "decisions": projected_decisions, "files": files}


def summary_disclosure(raw: bytes, stem: str, projected: dict[str, Any]) -> dict[str, Any]:
    """Check original Markdown disclosures without treating prose as JSON."""
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise Refused("SummaryEncoding", stem) from error
    require(f"Raw events: `{stem}.jsonl`" in text, "SummaryDisclosure", "raw event member")
    chain = projected["deployment"]["chain_id"]
    require(f"Chain `{chain}`" in text, "SummaryDisclosure", "chain label")
    rows = [line for line in text.splitlines() if line.startswith("| Field |") or line.startswith("| Source |") or line.startswith("| Revision |")]
    require(any(line.startswith("| Source |") for line in rows), "SummaryDisclosure", "source narrative")
    return {"original_sha256": hashlib.sha256(raw).hexdigest(), "raw_member_and_chain_disclosures_match": True, "authority_narrative_rows": rows, "narrative_identity_authenticated": False, "prose_semantic_grade": "not-performed"}


def _read_record(directory: Path, stem: str, admission: Admission) -> dict[str, Any]:
    require(re.fullmatch(r"revocation-trace-(?:local|testnet)-[0-9]{8}T[0-9]{6}Z", stem) is not None, "RecordName", stem)
    names = [stem + suffix for suffix in (".manifest.json", ".jsonl", ".md")]
    raw = {name: read_member(directory, name) for name in names}
    members = admission.capture / "members"
    members.mkdir(mode=0o700)
    for name, original in raw.items():
        (members / name).write_bytes(original)
    manifest = admission.document(raw[names[0]], names[0])
    require(type(manifest) is dict and manifest.get("schema") == SCHEMA and manifest.get("record") == stem, "ManifestShape", stem)
    hashes = {name: hashlib.sha256(raw[name]).hexdigest() for name in names[1:]}
    require(exact(manifest.get("files"), hashes), "MemberHashMismatch", stem)
    events = []
    for number, line in enumerate(raw[names[1]].splitlines(), 1):
        require(bool(line.strip()), "BlankEvent", f"line {number}")
        event = admission.document(line, f"{names[1]}:{number}")
        require(type(event) is dict, "EventShape", str(number))
        events.append(event)
    require(bool(events), "EmptyRecord", stem)
    projected = derive(stem, events, manifest.get("stated"), hashes)
    require(exact(manifest, projected), "ManifestEventMismatch", stem)
    disclosure = summary_disclosure(raw[names[2]], stem, projected)
    return {"schema": "jcs-admit.mintid-trace-consumer.v1", "profile": "mintid-trace-records-v2", "status": "accepted", "record": stem, "member_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}, "event_count": len(events), "source": projected["source"], "stated": projected["stated"], "deployment": projected["deployment"], "policy": projected["policy"], "paths": projected["paths"], "decision_count": len(projected["decisions"]), "summary_disclosure": disclosure, "admission_calls": admission.calls, "does_not_assert": ["authenticated operator or source/build identity", "independent operation or custody", "chain state or ICS23/BBS proof validity", "authority beyond the recorded verifier outcomes", "target bytes or external action effects", "truth of all Markdown prose", "independent chain observation of roots declared in the JSONL summary", "a real unreachable-authority workload from the original three records"]}


def read_record(directory: Path, stem: str, admission: Admission) -> dict[str, Any]:
    """Return a clear shape refusal for malformed untrusted nested records."""
    try:
        return _read_record(directory, stem, admission)
    except Refused:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, RecursionError) as error:
        raise Refused("RecordShape", type(error).__name__) from error
