# vnd-bench

This directory contains a tool to run benchmarks for V-Apps on Ledger devices.

## Structure

Benchmark cases are auto-discovered from the path given with the `--path` argument, that should be a folder with one subfolder per testcase.

### Testcase structure

Each testcase is a full V-App as its own crate. The V-App should accept a single 64-bit big-endian number, encoding the number of repetitions.

The benchmark app should initialize the testcase outside of a loop, and then run the relevant code inside a loop with the given number of repetitions.

The tool runs the V-App with 0 repetitions to estimate the baseline initialization cost. Then, the V-App is run again with the correct number of repetitions.

You can find example benchmarks in the [bench](../../bench) folder.

#### Case metadata

Each case can set benchmark-specific metadata in its `Cargo.toml`:

```toml
[package.metadata.benchmark]
repetitions = 10
```

Currently, only a single `repetitions` field is defined, which is the number of repetitions for this testcase.

## Installing the tool

```sh
cargo install --path .
```

## Running Benchmarks

To run all benchmark testcases, looking for testcases in default folder named `cases` in the current working directory:

```sh
vnd-bench
```

You can specify a different folder to find the testcases with the `--path` parameter

```sh
vnd-bench --path my_testcases
```

To list all discovered cases and their configured run counts, use the `--list` argument:

```sh
vnd-bench --path my_testcases --list
```

To run only specific testcases, pass one or more substrings of the testcase names as command line arguments. Only testcases whose name includes at least one of the arguments will be run. For example:

```sh
vnd-bench sha256 base58
```

This will run all testcases whose names include either `sha256` or `base58`.

## Output

The benchmark runner will print a summary table with the total and average execution time for each testcase, adjusted by the baseline measurement.
