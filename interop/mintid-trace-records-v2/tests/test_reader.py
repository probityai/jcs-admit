"""Actual installed commands check original triples and hostile record controls."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from mintid_trace.reader import Admission, MAX_BYTES, Refused, read_record

RECORDS = Path(os.environ["MINTID_RECORDS"])
GO = Path(os.environ["MINTID_GO"])
ADMISSION = Path(os.environ["MINTID_ADMISSION"])
STEMS = ("revocation-trace-local-20261004T122943Z", "revocation-trace-testnet-20261004T153434Z", "revocation-trace-testnet-20261005T022948Z")


class ReaderControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.stem = STEMS[2]
        for suffix in (".jsonl", ".manifest.json", ".md"):
            (self.directory / (self.stem + suffix)).write_bytes((RECORDS / (self.stem + suffix)).read_bytes())
        self.capture = Path(os.environ["MINTID_CAPTURE_ROOT"]) / self.id().split(".")[-1]
        self.selected = Admission(GO, ADMISSION, self.capture)

    def manifest(self):
        return json.loads((self.directory / (self.stem + ".manifest.json")).read_bytes())

    def save_manifest(self, value):
        (self.directory / (self.stem + ".manifest.json")).write_text(json.dumps(value, indent=2) + "\n")

    def mutate_manifest(self, callback):
        value = self.manifest(); callback(value); self.save_manifest(value)

    def events(self):
        return [json.loads(line) for line in (self.directory / (self.stem + ".jsonl")).read_bytes().splitlines()]

    def save_raw(self, raw):
        (self.directory / (self.stem + ".jsonl")).write_bytes(raw)
        self.mutate_manifest(lambda value: value["files"].update({self.stem + ".jsonl": hashlib.sha256(raw).hexdigest()}))

    def save_events(self, events):
        self.save_raw(b"".join(json.dumps(event).encode() + b"\n" for event in events))

    def refuse(self, code=None):
        with self.assertRaises(Refused) as caught:
            read_record(self.directory, self.stem, self.selected)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception.code

    def test_MTRV2_001_original_local(self):
        value = read_record(RECORDS, STEMS[0], self.selected)
        self.assertEqual(value["event_count"], 198)
        self.assertEqual(value["decision_count"], 85)
        self.assertIsNone(value["source"]); self.assertIsNone(value["policy"])
        cascade = [row for row in value["paths"] if row["path"] == "cascade"]
        self.assertEqual([row["attribution"]["revoked"]["refresh"]["observation"] for row in cascade], ["not_recorded", "not_recorded"])
        self.assertEqual(len(self.selected.calls), 199)

    def test_MTRV2_002_original_testnet_first(self):
        value = read_record(RECORDS, STEMS[1], self.selected)
        self.assertEqual(value["event_count"], 75)
        self.assertEqual(value["decision_count"], 23)
        cascade = [row for row in value["paths"] if row["path"] == "cascade"]
        self.assertEqual([row["attribution"]["revoked"]["refresh"]["observation"] for row in cascade], ["refused", "not_recorded"])
        self.assertEqual(value["stated"]["services_revision"], "08ca3d829665")

    def test_MTRV2_003_original_testnet_second(self):
        value = read_record(RECORDS, STEMS[2], self.selected)
        issuer = next(row for row in value["paths"] if row["path"] == "issuer")
        self.assertEqual(issuer["first_refused"]["reason_code"], "status_root_stale")
        self.assertEqual(issuer["attribution"]["revoked"]["refresh"]["outcome"], "credential_revoked")
        self.assertEqual(issuer["attribution"]["control"]["refresh"]["observation"], "not_recorded")
        self.assertIs(issuer["control_never_revoked"]["after_refresh"]["accepted"], True)
        self.assertFalse(value["summary_disclosure"]["narrative_identity_authenticated"])
        self.assertEqual(len(self.selected.calls), 76)

    def test_MTRV2_004_changed_summary_bytes(self):
        with (self.directory / (self.stem + ".md")).open("ab") as stream: stream.write(b"changed")
        self.refuse("MemberHashMismatch")

    def test_MTRV2_005_changed_event_bytes(self):
        with (self.directory / (self.stem + ".jsonl")).open("ab") as stream: stream.write(b"{}\n")
        self.refuse("MemberHashMismatch")

    def test_MTRV2_006_missing_declared_member(self):
        (self.directory / (self.stem + ".md")).unlink()
        self.refuse("MemberUnavailable")

    def test_MTRV2_007_escaped_duplicate_manifest_member(self):
        member = self.directory / (self.stem + ".manifest.json")
        member.write_bytes(member.read_bytes().replace(b'"schema":', b'"\\u0073chema":"other","schema":', 1))
        self.refuse("DuplicateMember"); self.assertEqual(len(self.selected.calls), 1)

    def test_MTRV2_008_scalar_manifest(self):
        (self.directory / (self.stem + ".manifest.json")).write_bytes(b"null")
        self.refuse("ObjectOrArrayRequired")

    def test_MTRV2_009_nonfinite_manifest(self):
        # I-JSON first refuses the integral 1e309 token as UnsafeInteger.
        member = self.directory / (self.stem + ".manifest.json")
        member.write_bytes(member.read_bytes().replace(b'"derived": true', b'"derived": 1e309', 1))
        self.refuse("UnsafeInteger")

    def test_MTRV2_010_symlink_member(self):
        target = self.directory / "sentinel.txt"; target.write_bytes(b"must not be opened")
        member = self.directory / (self.stem + ".md"); member.unlink(); member.symlink_to(target)
        self.refuse("MemberUnavailable"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_011_record_path_escape(self):
        self.stem = "../" + self.stem
        self.refuse("RecordName"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_012_unknown_manifest_field(self):
        self.mutate_manifest(lambda value: value.update({"unknown_authority": True}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_013_promoted_stated_source(self):
        self.mutate_manifest(lambda value: value.update({"source": {"revision": value["stated"]["source_revision"]}, "derived": False}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_014_unrecorded_refresh_promoted_to_revocation(self):
        def mutate(value):
            row = next(row for row in value["paths"] if row.get("agent") == "cascade_agent_1")
            row["attribution"]["revoked"]["refresh"]["observation"] = "refused"
        self.mutate_manifest(mutate); self.refuse("ManifestEventMismatch")

    def test_MTRV2_015_boolean_root_count(self):
        self.mutate_manifest(lambda value: value.update({"derived": 1}))
        self.refuse("ManifestEventMismatch")

    def test_MTRV2_016_failed_native_command(self):
        command = self.directory / "failed-command"; command.write_text("#!/bin/sh\nexit 7\n"); command.chmod(0o700)
        self.selected = Admission(command, ADMISSION, self.directory / "other-capture")
        self.refuse("CommandFailed"); self.assertEqual(self.selected.calls[0]["native_exit"], 7)

    def test_MTRV2_017_malformed_command_response(self):
        command = self.directory / "malformed-command"; command.write_text("#!/bin/sh\nprintf '%s' '{\"status\":true}'\n"); command.chmod(0o700)
        self.selected = Admission(command, ADMISSION, self.directory / "other-capture"); self.refuse("CommandProtocol")

    def test_MTRV2_018_duplicate_event_before_parse(self):
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"shadow","\\u006bind":"stack"', 1)
        self.save_raw(raw); self.refuse("DuplicateMember"); self.assertEqual(len(self.selected.calls), 2)

    def test_MTRV2_019_duplicate_decision_log_identity(self):
        events = self.events(); line = copy.deepcopy(next(event for event in events if event["kind"] == "decision_log_line")); events.insert(-1, line)
        self.save_events(events); self.refuse("AmbiguousDecisionLog")

    def test_MTRV2_020_excessive_native_nesting(self):
        raw = b'{"kind":"stack","nested":' + b'[' * 129 + b'0' + b']' * 129 + b'}\n'
        self.save_raw(raw); self.refuse("TooDeep")

    def test_MTRV2_021_unsafe_integer_event(self):
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"stack","number":9007199254740993', 1)
        self.save_raw(raw); self.refuse("UnsafeInteger")

    def test_MTRV2_022_nonfinite_event(self):
        # Keep the native I-JSON policy refusal; do not relabel it.
        raw = (self.directory / (self.stem + ".jsonl")).read_bytes().replace(b'"kind": "stack"', b'"kind":"stack","number":1e309', 1)
        self.save_raw(raw); self.refuse("UnsafeInteger")

    def test_MTRV2_023_invalid_utf8_event(self):
        self.save_raw(b'{"kind":"stack","bad":"\xed\xa0\x80"}\n'); self.refuse("StringNotScalar")

    def test_MTRV2_024_boolean_deciding_condition(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision_log_line")["line"]["condition"] = True
        self.save_events(events)
        self.mutate_manifest(lambda value: value["decisions"][0].update({"condition": True}))
        self.refuse("DecisionLogShape")

    def test_MTRV2_025_integer_decision_boolean(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision")["accepted"] = 1
        self.save_events(events); self.refuse("DecisionShape")

    def test_MTRV2_026_unbound_summary_decision(self):
        events = self.events(); events[-1]["results"][0]["first_no"]["session_id"] = "invented"
        self.save_events(events); self.refuse("UnboundSummaryDecision")

    def test_MTRV2_027_duplicate_files_map(self):
        member = self.directory / (self.stem + ".manifest.json"); member.write_bytes(member.read_bytes().replace(b'"files":', b'"files":{},"files":', 1)); self.refuse("DuplicateMember")

    def test_MTRV2_028_declared_path_escape(self):
        self.mutate_manifest(lambda value: value["files"].update({"../sentinel.txt": "0" * 64}))
        self.refuse("MemberHashMismatch")

    def test_MTRV2_029_symlink_directory(self):
        alias = self.directory / "alias"; alias.symlink_to(RECORDS, target_is_directory=True)
        self.directory = alias; self.refuse("MemberPath")

    def test_MTRV2_030_bounded_member(self):
        with (self.directory / (self.stem + ".md")).open("wb") as stream: stream.truncate(MAX_BYTES + 1)
        self.refuse("TooLarge"); self.assertEqual(self.selected.calls, [])

    def test_MTRV2_031_rehashed_false_summary_disclosure(self):
        raw = (self.directory / (self.stem + ".md")).read_bytes().replace(b"Raw events:", b"Other events:")
        (self.directory / (self.stem + ".md")).write_bytes(raw)
        self.mutate_manifest(lambda value: value["files"].update({self.stem + ".md": hashlib.sha256(raw).hexdigest()}))
        self.refuse("SummaryDisclosure")

    def test_MTRV2_032_missing_summary_event(self):
        self.save_events(self.events()[:-1]); self.refuse("MissingSummary")

    def test_MTRV2_033_ambiguous_source_event(self):
        events = self.events(); events.insert(-1, {"kind": "source", "revision": "a"}); events.insert(-1, {"kind": "source", "revision": "b"})
        self.save_events(events); self.refuse("AmbiguousEvent")

    def test_MTRV2_034_ring_detached_from_native_event(self):
        events = self.events(); events[-1]["results"][0]["first_no"]["ring_at_denial"][-1]["status_epoch"] += 1
        self.save_events(events); self.refuse("RingBindingMismatch")

    def test_MTRV2_035_wrong_policy_digest(self):
        events = self.events(); events.insert(-1, {"kind": "policy", "claim_policy": [], "issuer_policy": {}, "sha256": "0" * 64})
        self.save_events(events); self.refuse("PolicyHashMismatch")

    def test_MTRV2_036_decision_log_outcome_disagreement(self):
        events = self.events(); next(event for event in events if event["kind"] == "decision_log_line")["line"]["accepted"] = False
        self.save_events(events); self.refuse("DecisionLogMismatch")

    def test_MTRV2_037_unreachable_transport_is_not_denial(self):
        events = self.events(); outage = {"path": "unreachable", "t0": 100.0, "t0_def": "authored unavailable-authority control", "restored_unix": 104.0, "during": [{"kind": "challenge_during_outage", "path": "unreachable", "utc": "authored", "unix": 101.0, "http": 503, "error": "unavailable"}], "first_accepted_after": None}
        events[-1]["results"].append(outage); events.insert(-1, copy.deepcopy(outage["during"][0])); self.save_events(events)
        expected = {"path": "unreachable", "t0_unix": 100.0, "t0_definition": "authored unavailable-authority control", "restored_seconds_after_t0": 4.0, "decided_during_outage": [], "challenges_during_outage": [{"utc": "authored", "seconds_after_t0": 1.0, "http": 503, "error": "unavailable"}], "first_accepted_after_restore": None}
        self.mutate_manifest(lambda value: value["paths"].append(expected))
        result = read_record(self.directory, self.stem, self.selected)
        self.assertEqual(result["paths"][-1], expected)
        self.assertEqual(result["decision_count"], 23)

    def test_MTRV2_038_outage_invented_decision(self):
        events = self.events(); events[-1]["results"].append({"path": "unreachable", "t0": 100.0, "during": [{"kind": "decision", "session_id": "invented", "accepted": False}]})
        self.save_events(events); self.refuse("UnboundSummaryDecision")


if __name__ == "__main__":
    unittest.main(verbosity=2)
