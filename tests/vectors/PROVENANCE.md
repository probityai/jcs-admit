# Where these vectors come from

Nothing in this directory was invented. Each set is copied from a pinned source
and the source is named so a reader can re-derive it.

## `rfc8785/`

The RFC 8785 reference test suite: six input documents and their canonical
forms. Taken verbatim from
`https://github.com/trailofbits/rfc8785.py` at commit
`f1a446e930dcd54228414bd2319b78ccc92be12a` (2026-06-09), files
`test/assets/input/*.json` and `test/assets/output/*.json`, which that
repository in turn states are taken verbatim from the RFC's own reference
implementation, `https://github.com/cyberphone/json-canonicalization`.

Licence, as a line item: rfc8785.py is Apache-2.0 (Trail of Bits), and the
upstream reference implementation is Apache-2.0 (Anders Rundgren).

## The cases in `tests/*.rs` that are not files

The string, surrogate, duplicate-member, depth and number-profile cases in
`tests/reference_parity.rs` are copied from the Go implementation this crate is
a port of: `aee/jcs.go` and its tests `aee/surrogate_test.go`,
`aee/jcs_string_test.go`, `aee/jcs_number_test.go` and `aee/jcs_dos_test.go`
in `github.com/astrogilda/agent-evidence-vectors`, at the `aee/jcs.go` revision
`d7689f9445dcb966ac0e4ce6cbc21ae69efeafd1` (2026-08-10). Each test names the
case it came from. Where a test case is this crate's own rather than copied, it
says so.

## `cross-rail/`

The differential corpus. `input/` holds conformance vectors copied unmodified
from `vectors/statements/` in `github.com/astrogilda/agent-evidence-vectors`, and
`canonical/` holds the canonical form each one takes under THAT repository's Go
implementation -- `aee.Canonicalize` in `aee/jcs.go` at revision
`d7689f9445dcb966ac0e4ce6cbc21ae69efeafd1`, run under Go 1.25.5. Nothing in
`canonical/` was produced by this crate.

`refused.tsv` lists the vectors the Go rail refuses, with the error class this
crate must refuse them in and the reason the Go rail gave verbatim.

What is committed is a deterministic subset, 30 accepted vectors plus all 9
refused ones. `differential/REPORT.md` records the full 272-vector run and
`differential/regenerate.sh` rebuilds it.

Licence, as a line item: `agent-evidence-vectors` is Apache-2.0, and the
copyright holder is the same person who holds this crate's.

## `attack/`

`strings-keys-members.tsv` is 317 adversarial documents aimed at strings,
member names and members, enumerated rather than sampled: every C0 control as
an escape and again raw, in value and in member-name position; DEL and the C1
range; each escape whose mandated output differs from the escape written;
surrogate halves alone, mispaired, and in either hex case; surrogates, overlong
forms and truncated sequences encoded directly in the bytes; the Unicode
noncharacters in the BMP and in a supplementary plane; member names differing
only by escaping, only by Unicode normalisation form, or only by hex case; the
empty name; a name carrying NUL; repeats at the top level, nested, and inside
an array element; and member ordering across the boundary where UTF-16
code-unit order stops agreeing with UTF-8 byte order.

The inputs are this crate's own. The EXPECTED column is not: it is what
`aee.Canonicalize` in `aee/jcs.go` produced, at the revision named above, under
Go 1.25.5 -- so a mistake this crate and its test share cannot pass by agreeing
with itself. That rail applies the I-JSON string profile and the integers-only
tightening unconditionally, which is why `tests/attack_strings_keys_members.rs`
compares under `Options::ijson().integers_only(true)`.

A third implementation arbitrated the same corpus independently: the RFC
author's own reference lineage, via `trailofbits/rfc8785.py` at the commit named
above. It is a value-level canonicalizer, so it cannot express the byte-level
refusals; over the 178 cases it can express it agreed byte for byte with both
other rails.

The same two rails were also compared over a seeded randomised corpus of 39,276
documents built from the same adversarial alphabet, half of them byte-mutated.
Result: no accept-versus-refuse disagreement and no byte disagreement. That
corpus is regenerable rather than committed -- `differential/REPORT.md` records
the run -- because 317 enumerated cases are the ones a reader can check by eye.
