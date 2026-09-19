# What the delegate actually does

Raw output of the probe run behind every claim in `tests/incumbent_differential.rs`
and the README table. Run 2026-09-19 on Linux x86-64, rustc 1.98.0-nightly
(57d06900f 2026-05-27), against `serde_json_canonicalizer` 0.3.2 resolving
`serde_json` 1.0.151 and `ryu-js` 1.0.3.

Crate source read at `serde_json_canonicalizer-0.3.2.crate`,
sha256 `fe52319a927259afbfa5180c5157cd8167edfd3e8c254f9558c7fef44c5649f2`,
downloaded from static.crates.io the same day. Its whole public API is four
functions in `src/util.rs`: `to_vec`, `to_string`, `to_writer` (all
`S: Serialize`) and `pipe(&str)`.

## crates.io, read 2026-09-19

```
agent-evidence-admission  HTTP 404  crate does not exist
serde_json_canonicalizer  HTTP 200  v0.3.2  7,852,211 total  5,259,528 recent  updated 2026-02-03
serde_jcs                 HTTP 200  v0.2.0  3,825,932 total  2,711,166 recent  updated 2026-03-25
serde_json                HTTP 200  v1.0.151                                    updated 2026-07-20
```

The 404 is a negative, so it carries three positive controls from the same
call in the same session: the identical request shape returned 200 with
populated fields for three names known to exist.

## Probe output, verbatim

```
--- A. duplicate member via pipe() (bytes in, string out)
  pipe("{\"a\":1,\"a\":2}") = Ok("{\"a\":2}")
--- B. duplicate member via to_vec(&Value) (their serde path)
  serde_json::Value = {"a":2}  -> to_vec = Ok("{\"a\":2}")
--- C. duplicate member emitted straight into their serializer
  to_string(TwiceKeyed) = Ok("{\"a\":1}")
--- D. nesting: pipe() at 128 / 129 / 256 / 1000
  depth   128: Err: recursion limit exceeded at line 1 column 128
  depth   129: Err: recursion limit exceeded at line 1 column 128
  depth   256: Err: recursion limit exceeded at line 1 column 128
  depth  1000: Err: recursion limit exceeded at line 1 column 128
--- E. nesting: to_vec(&Value) built WITHOUT their parser, 129 and 10000
  depth   129: ACCEPTED (262 bytes out)

thread 'main' (2794532) has overflowed its stack
fatal runtime error: stack overflow, aborting
timeout: the monitored command dumped core
--- A. duplicate member via pipe() (bytes in, string out)
  pipe("{\"a\":1,\"a\":2}") = Ok("{\"a\":2}")
--- B. duplicate member via to_vec(&Value) (their serde path)
  serde_json::Value = {"a":2}  -> to_vec = Ok("{\"a\":2}")
--- C. duplicate member emitted straight into their serializer
  to_string(TwiceKeyed) = Ok("{\"a\":1}")
--- D. nesting: pipe() at 128 / 129 / 256 / 1000
  depth   128: Err: recursion limit exceeded at line 1 column 128
  depth   129: Err: recursion limit exceeded at line 1 column 128
  depth   256: Err: recursion limit exceeded at line 1 column 128
  depth  1000: Err: recursion limit exceeded at line 1 column 128
--- E. nesting: to_vec(&Value) built WITHOUT their parser, 129 and 10000
  depth   129: ACCEPTED (262 bytes out)
  depth   512: ACCEPTED (1028 bytes out)
--- F. the RFC 8785 reference number, through their pipe()
  pipe("333333333.33333329") = Ok("333333333.3333333")
  str::parse::<f64> bits    = 0x41b3de4355555555
--- G. non-finite and unsafe integer, through their pipe()
  pipe("1e400") = Err("number out of range at line 1 column 5")
  pipe("9007199254740993") = Ok("9007199254740992")
  pipe("1e21") = Ok("1e+21")
--- H. unpaired surrogate escape, through their pipe()
  pipe("{\"a\":\"\\ud800\"}") = Err("unexpected end of hex escape at line 1 column 13")
--- I. exact depth boundary on pipe()
  depth 126: Ok(252)
  depth 127: Ok(254)
  depth 128: Err("recursion limit exceeded at line 1 column 128")
  depth 129: Err("recursion limit exceeded at line 1 column 128")
--- J. exact depth boundary on to_vec(&Value)
  depth 128: Ok(260)
  depth 129: Ok(262)
  depth 1000: Ok(2004)
--- K. the string profile through pipe()
  noncharacter U+FFFF escaped        = Ok("{\"k\":\"\u{ffff}\"}")
  noncharacter U+FDD0 escaped        = Ok("{\"k\":\"\u{fdd0}\"}")
  noncharacter U+1FFFE escaped        = Ok("{\"k\":\"\u{1fffe}\"}")
  high surrogate alone               = Err("unexpected end of hex escape at line 1 column 13")
  low surrogate alone                = Err("lone leading surrogate in hex escape at line 1 column 12")
  high then high                     = Err("lone leading surrogate in hex escape at line 1 column 18")
  raw DEL U+007F                     = Ok("{\"k\":\"\u{7f}\"}")
  raw control U+0001                 = Err("control character (\\u0000-\\u001F) found while parsing a string at line 1 column 7")
  surrogate direct in bytes ED A0 80:
    (CESU-8)                         = NOT UTF-8, pipe() takes &str so it is unreachable: invalid utf-8 sequence of 1 bytes from index 6
  overlong NUL C0 80:
    (overlong)                       = NOT UTF-8, pipe() takes &str so it is unreachable: invalid utf-8 sequence of 1 bytes from index 6
--- L. the unsafe-integer family through pipe()
  9007199254740992       = Ok("9007199254740992")
  9007199254740993       = Ok("9007199254740992")
  99999999999999999999   = Ok("100000000000000000000")
  1.5                    = Ok("1.5")
  -0.1                   = Ok("-0.1")
  1E21                   = Ok("1e+21")
  1.0e21                 = Ok("1e+21")
--- M. size: is there any cap?  20 MiB + 1 of array
  input 12000003 bytes -> Ok(12000003)
```

## The abort

Section E of the first run ended the process. `to_vec` on 10,000 nested
arrays printed `thread 'main' has overflowed its stack` then
`fatal runtime error: stack overflow, aborting`, exit status 134, core dumped.
It is not asserted in the test suite because an abort would take the test
binary with it; the suite asserts the uncapped acceptance at 1,000 levels
instead.
