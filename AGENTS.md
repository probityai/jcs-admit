# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; these are the rules an agent most often breaks here.

- `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo doc` must pass with no
  warnings before you push.
- A new refusal comes with a test that fails without it. [docs/MUTATION-SWEEP.md](docs/MUTATION-SWEEP.md)
  records how each existing refusal was checked that way.
- Never regenerate the pinned vectors in `tests/vectors/` from this crate. They come from an
  independent Go implementation; [tests/vectors/PROVENANCE.md](tests/vectors/PROVENANCE.md) says
  where.
- Don't reimplement number formatting. It is delegated to `serde_json_canonicalizer` on purpose.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py`
  fails a README over its word limit.
