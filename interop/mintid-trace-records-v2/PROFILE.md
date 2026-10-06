# MintID manifest-v2 consumer profile

The profile ID is `mintid-trace-records-v2`. Control IDs `MTRV2-001` through `MTRV2-038` belong to this profile. They do not replace any earlier corpus, comparison or study.

## Original inputs

[SOURCE-SELECTION.json](SOURCE-SELECTION.json) pins twelve files from public source `e4efba09598fe0110a929e224a814cb706cc9d0c`: the records directory's ten original members, LICENSE and NOTICE. Every byte length, SHA-256 and Git blob is checked before qualification. The selected records are:

- `revocation-trace-local-20261004T122943Z`: 198 events and 85 decisions.
- `revocation-trace-testnet-20261004T153434Z`: 75 events and 23 decisions.
- `revocation-trace-testnet-20261005T022948Z`: 75 events and 23 decisions.

These are later published copies of older records. The originally advertised October 4 tag was unavailable when checked. The public project and available tag/tree routes supplied positive controls. The later source pin does not authenticate an older deployed revision. In all three original manifests, `source`, `deployment.build` and `policy` are null. Operator assertions remain under `stated`.

The imported records retain MintID's Apache-2.0 LICENSE and NOTICE. The Go source and its license remain under the unchanged existing Go profile.

## One installed entry point

Use the installed wheel and trusted absolute paths to the Go and admission executables:

```sh
/absolute/qualification/reader/bin/python -m mintid_trace \
  --records /absolute/path/to/records \
  --record revocation-trace-testnet-20261005T022948Z \
  --go /absolute/qualification/commands/go-jcs \
  --admission /absolute/qualification/commands/go-jcs-admission \
  --capture-dir /absolute/new/private/capture
```

The record directory must be canonical. Each member must be a regular file with its exact expected basename. The reader does not follow symlinks or open names from the manifest's hash map. Every declared member must match the actual SHA-256. A new capture directory prevents overwriting an earlier result.

The reader uses the existing I-JSON admission profile. Fractions remain supported. Unsafe integral tokens, duplicate names, malformed UTF-8, non-scalar strings, excessive depth and scalar roots refuse before Python parses the original bytes. Native refusal classes remain unchanged. For example, the I-JSON gate refuses `1e309` as `UnsafeInteger` before its nonfinite-number check.

Each member and JSONL line has the existing 20 MiB admission bound; nesting has the existing 128-level bound. A whole JSONL file has the same byte bound. These limits bound file reads and parser input. The reader spools native output to disk and bounds the decoded response. It selects no smaller silent cap or larger admission limit. This profile uses POSIX file descriptors and no-follow flags. Its maintained workflow runs on Linux.

## Facts and limits

The consumer independently projects the manifest's finite v2 fields from the admitted events. Boolean values cannot replace numbers. A summary decision must bind an actual decision. A decision-log identity must be unique and bind the same outcome. A declared ring must match its recorded event. Source/build/service/policy observations stay separate from operator assertions. Policy digests use MintID's stated sorted compact Python JSON format; they do not become JCS digests.

A first `status_root_stale` refusal alone does not establish revocation. The issuer path also records a never-revoked control that refuses its old witness and later succeeds. Witness refresh observations keep `refused`, `not_refused_within_budget` and `not_recorded` distinct. An original absent cascade refresh stays absent.

An authored outage control keeps unavailable challenges separate from decisions. The three original bundles contain no outage workload. Root fields declared in the JSONL summary do not establish independent chain observations. Recorded wall clocks and relative offsets do not establish an external time anchor.

Markdown never enters the JSON parser or canonicalizer. Its original hash, raw-event filename, chain label and authority narrative disclosures are checked separately. The consumer does not grade all prose or authenticate its narrative identity claims.

## Qualification and retention

`qualify.py` runs the unchanged Cargo and Go checks, builds one wheel, and imports it outside the checkout. It compares each installed module byte-for-byte with selected source. It retains actual runtime probes, wheel and executable hashes, all three original results, 38 actual test outcomes, original member bytes and each native admission call's input/output/exit.

The first control run had two wrong expectations about I-JSON refusal ordering. Its full failed capture remains preserved separately. The correction changes the expected native class, without rewriting the native outcome.

These are author-operated technical checks. A maintained outside job needs the host's selected source pin and actual execution. Required merge enforcement, an outside operator, independent custody, chain/proof validation and external action effects need their own evidence. This profile creates no registry release or host acceptance.
