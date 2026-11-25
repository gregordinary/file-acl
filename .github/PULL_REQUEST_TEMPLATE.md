<!-- A change is best agreed in an issue before it is written; see
     CONTRIBUTING.md. Link that issue here if there is one. -->

## What this changes

<!-- The change in the repository's own terms: what the code now does. -->

## Why

<!-- The reasoning, where it is not obvious from the change itself. -->

## Checks

<!-- CI runs all of these; running them locally first is faster than a round
     trip. See CONTRIBUTING.md. -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] The same two for the fuzzing harness, with
      `--manifest-path fuzz/Cargo.toml`
- [ ] `cargo test --workspace --all-features`, with the `FILE_ACL_REQUIRE_*`
      variables set where the references are available
- [ ] `cargo doc --workspace --all-features --no-deps` with `RUSTDOCFLAGS='-D warnings'`
- [ ] `cargo build --lib --target thumbv7em-none-eabihf`
- [ ] `cargo +1.88 check --workspace --all-targets --all-features` with `RUSTFLAGS='-D warnings'`
- [ ] `cargo deny check licenses advisories sources`, and the same with
      `--manifest-path fuzz/Cargo.toml`, if a dependency changed
- [ ] `cargo +nightly fuzz build` in `fuzz/`, if the API the fuzz targets
      drive changed
- [ ] The public surface is unchanged, **or** `public-api.txt` is regenerated
      and the diff is intentional

## What it accepts and writes

- [ ] No list is accepted, refused, read or written differently, **or** the
      description says which, and a comparison test shows the reference's
      answer
- [ ] A difference from a reference the change introduces or leaves is
      listed in the documentation
