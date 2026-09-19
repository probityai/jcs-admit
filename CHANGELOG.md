# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - unreleased

First release. Admission control for JSON about to be signed, decided on the
raw bytes before any decode, with RFC 8785 canonicalization delegated to
`serde_json_canonicalizer`.

### Added

- `admit`, `admit_ijson` and `admit_with`: `&[u8]` in, canonical `Vec<u8>` out.
  Taking bytes rather than `&str` is the design, not a convenience: a surrogate
  written directly in UTF-8 and an overlong form are unrepresentable in a Rust
  string, so a `&str` entry point cannot be handed them at all.
- `is_canonical` and `is_canonical_with`: the question a verifier actually has,
  because it must hash the bytes it received rather than bytes it re-serialized.
- `Options` with seven `const` builder methods, so a profile can be built in a
  static.
- `Error`, `#[non_exhaustive]`, ten variants, each carrying a byte offset or the
  offending token.
- `DEFAULT_MAX_DEPTH` (128, the value in-toto's normative text carries),
  `MAX_SUPPORTED_DEPTH` (512) and `DEFAULT_MAX_BYTES` (20 MiB).

### Refusals this crate makes that a `serde` `Serializer` over a parsed value
### cannot

- A repeated object member, compared on the decoded name. By the time a
  `serde_json::Value` exists the repeat has already collapsed to last-wins, so
  the fault is only catchable on the bytes.
- Nesting past a depth cap, charged per open container.
- A string whose bytes are not Unicode scalar values: unpaired or mispaired
  surrogate escapes, surrogates encoded directly in the bytes, overlong forms.
- Unicode noncharacters, under the I-JSON profile only.
- An integer at or above 2^53 under the safe-integer profile, decided on the
  digit string and notation-blind, so `1e21` is seen as the integer it denotes.
- A number with a fractional part, under the integers-only tightening.
- A number token with no finite double.
- An input past a size cap: a depth cap bounds the stack, a size cap bounds the
  heap.
