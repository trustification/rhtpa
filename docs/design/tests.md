# Unit and integration tests

This section features a bit of information about unit and integration tests. Test which you can run using `cargo test`.

## panic, unwrap, expect, and println

In most cases, calls that panic are not allowed in this project. However, for tests, that is different. It is ok
to have tests panic. Ideally, there is a proper error message attached to that panic. That is why using `expect` is
preferable over `unwrap`.

It is also ok to dump information via `println` and others. It might still make more sense to use logging/tracing.

Also see: [log_tracing.md#println-and-panic](log_tracing.md#println-and-panic)

## Long-running tests

Some tests are expected to be long-running. Such tests might not fit into the test run for GitHub CI workflows which tests PRs.

Those tests may be skipped by default, but should be enabled using the `long_running` feature flag. This
should be done using:

```rust
#[test]
#[cfg_attr(not(feature = "long_running"), ignore = "enable with: cargo test --features long_running")]
fn long_running_test() {
    // runs for several hours
}
```

This will keep the tests available, show them as "ignored", and give the user instructions on how to enable them.

The feature needs to be declared once for each module. If it hasn't been in the module you are using it,
you can do this using:

```toml
[features]
long_running = [] # enable long-running tests
```
