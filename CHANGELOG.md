# Changelog

All notable changes to this crate are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - unreleased

First release. Admission control for JSON about to be signed, decided on the raw bytes before
any decode, with RFC 8785 canonicalization delegated to `serde_json_canonicalizer`.

### Added

Three entry points that canonicalize, and two that answer a verifier's question directly:

- `admit`, `admit_ijson` and `admit_with`: `&[u8]` in, canonical `Vec<u8>` out.
- `is_canonical` and `is_canonical_with`, because a verifier must hash the bytes it received
  rather than bytes it re-serialized.

Taking bytes is a design decision rather than a convenience. A surrogate written directly in
UTF-8 and an overlong form cannot be represented in a Rust string, so a `&str` entry point
cannot be handed them at all.

Then the supporting surface:

- `Options`, with seven `const` builder methods, so you can build a profile in a static.
- `Error`, `#[non_exhaustive]`, ten variants, each carrying a byte offset or the offending
  token.
- `DEFAULT_MAX_DEPTH` (128, the value in-toto's normative text carries),
  `MAX_SUPPORTED_DEPTH` (512) and `DEFAULT_MAX_BYTES` (20 MiB).

**What this refuses that a serializer over a parsed value cannot.** Structural faults, which a parse destroys on its way past them:

- A repeated object member, compared on the decoded name. By the time a `serde_json::Value`
  exists the repeat has collapsed to last-wins.
- Nesting past a depth cap, charged per open container.
- An input past a size cap. A depth cap bounds the stack; a size cap bounds the heap.

String faults, checked before any decode:

- Unpaired or mispaired surrogate escapes.
- Surrogates encoded directly in the bytes, and overlong forms.
- Unicode noncharacters, under the I-JSON profile only.

Number faults, decided on the digit string:

- An integer at or above 2^53 under the safe-integer profile. The check is notation-blind, so
  `1e21` is seen as the integer it denotes.
- A number with a fractional part, under the integers-only tightening.
- A number token with no finite double.
