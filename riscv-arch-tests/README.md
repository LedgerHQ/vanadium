# vanadium-riscv-arch-tests

Integration tests that compile and run the official
[RISC-V Architecture Tests](https://github.com/riscv-non-isa/riscv-arch-test)
against the Vanadium CPU model.

## Prerequisites

### 1. Clone the test suite

The test suite repository is **not** cloned automatically.  You must clone it
once into the `vendor/` directory before building:

```sh
git clone --depth 1 --branch 3.9.1 \
    https://github.com/riscv-non-isa/riscv-arch-test \
    riscv-arch-tests/vendor/riscv-arch-test
```

Run this command from the root of the Vanadium workspace.  The expected layout
after cloning is:

```
riscv-arch-tests/
  vendor/
    riscv-arch-test/
      riscv-test-suite/
        ...
```

If `vendor/riscv-arch-test` is absent, the build script will emit a warning
and skip all arch tests without failing.

### 2. Generate golden reference outputs

The upstream repo does **not** ship precomputed reference outputs.  They must
be generated once using [Spike](https://github.com/riscv-software-src/riscv-isa-sim)
and stored in `riscv-arch-tests/references/`.

#### Install Spike

On Debian/Ubuntu:

```sh
sudo apt install device-tree-compiler libboost-all-dev
git clone https://github.com/riscv-software-src/riscv-isa-sim
cd riscv-isa-sim && mkdir build && cd build
../configure --prefix=/usr/local
make -j$(nproc) && sudo make install
```

#### Run Spike to produce reference outputs

From the root of the Vanadium workspace:

```sh
#!/bin/bash
set -euo pipefail

SUITE=riscv-arch-tests/vendor/riscv-arch-test/riscv-test-suite
REFS=riscv-arch-tests/references

for EXT in I M A C; do
  mkdir -p "$REFS/$EXT"
  for SRC in "$SUITE/rv32i_m/$EXT/src/"*.S; do
    STEM=$(basename "$SRC" .S)

    # Skip ebreak tests: Spike halts waiting for a debugger on ebreak rather
    # than taking a normal trap, causing the script to hang indefinitely.
    [[ "$STEM" == *ebreak* ]] && { echo "[$EXT] $STEM: skipping (ebreak)"; continue; }

    # Skip tests that require Zcb: those instructions are not part of the
    # rv32imac_zicsr profile and Vanadium does not implement them.
    grep -q '_Zcb\|_zcb' "$SRC" && { echo "[$EXT] $STEM: skipping (Zcb not supported)"; continue; }

    echo "[$EXT] $STEM: compiling..."
    ELF=$(mktemp --suffix=.elf)

    # Compile the test source to a bare-metal ELF.
    riscv64-unknown-elf-gcc \
      -march=rv32imac_zicsr -mabi=ilp32 -static -mcmodel=medany \
      -fvisibility=hidden -nostdlib -nostartfiles \
      -I "$SUITE/env" \
      -I riscv-arch-tests/model \
      -T riscv-arch-tests/model/link.ld \
      -DXLEN=32 -DTEST_CASE_1=1 \
      "$SRC" -o "$ELF" 2>/dev/null || { echo "[$EXT] $STEM: compile failed, skipping"; rm -f "$ELF"; continue; }

    # Get the signature region bounds from the ELF symbol table.
    SIG_BEGIN=$(riscv64-unknown-elf-nm "$ELF" | awk '/rvtest_sig_begin/{print "0x"$1; exit}')
    SIG_END=$(riscv64-unknown-elf-nm   "$ELF" | awk '/rvtest_sig_end/{  print "0x"$1; exit}')

    if [ -z "$SIG_BEGIN" ] || [ -z "$SIG_END" ]; then
      echo "[$EXT] $STEM: no sig symbols, skipping"
      rm -f "$ELF"
      continue
    fi

    echo "[$EXT] $STEM: running spike (sig $SIG_BEGIN..$SIG_END)..."
    # Run Spike and capture the commit log (contains every memory store).
    COMMITS=$(mktemp)
    spike --log-commits --isa=rv32imac_zicsr "$ELF" 2>"$COMMITS"
    echo "[$EXT] $STEM: spike done (exit $?), extracting signature..."

    # Extract the signature region from the commit log.
    # Pass the ELF so initial (unwritten) words use their true ELF value.
    python3 riscv-arch-tests/extract_sig.py \
            "$ELF" "$COMMITS" "$SIG_BEGIN" "$SIG_END" \
            "$REFS/$EXT/$STEM.reference_output"

    echo "[$EXT] $STEM: done."
    rm -f "$ELF" "$COMMITS"
  done
done
```

Commit the generated files in `riscv-arch-tests/references/` so they are
available to all developers without requiring Spike.

Tests whose reference output file is missing are silently skipped.

### 3. Install a RISC-V cross-compiler

One of the following compilers must be available on `PATH`:

| Candidate | Typical package |
|-----------|----------------|
| `riscv32-unknown-elf-gcc` | `gcc-riscv32-unknown-elf` |
| `riscv64-unknown-elf-gcc` | `gcc-riscv64-unknown-elf` |
| `riscv32-linux-gnu-gcc`   | `gcc-riscv32-linux-gnu`   |
| `riscv64-linux-gnu-gcc`   | `gcc-riscv64-linux-gnu`   |

On Debian/Ubuntu:

```sh
sudo apt install gcc-riscv64-unknown-elf
```

If no compiler is found, the build script will emit a warning and skip all
arch tests without failing.

## Running the tests

```sh
cargo test -p vanadium-riscv-arch-tests
```
