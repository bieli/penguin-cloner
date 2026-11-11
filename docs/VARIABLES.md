# Automatic variable discovery for penguin-cloner

Finds the variables of a **running, stripped** Linux program on its own: no symbol table, no debug
info, no JSON declaration of what to look for. The result is `variables.json`, a real dictionary
(`name -> int | float | string`).

```json
"variables": {
  "g_4020": 512,
  "g_4024": 2.5,
  "g_4040": "legacy-01.example",
  "g_4070": "/etc/legacyd.conf",
  "g_4080": 6000,
  "g_4098->+0x8": 36,
  "g_4098->+0x18": "alice"
}
```

Names are synthesized (`g_<offset>`) when the binary has no symbols, and are the real names when it
has them. A name never changes between runs of the same build (the offset is link-time, not ASLR).

## How variables are discovered

| Source | Needs | Finds |
|---|---|---|
| `symbol` | `.symtab` (or `--symbols` file) | named globals with their exact size |
| `xref` | x86_64, `xrefs` feature | every global the program's **code** touches, typed by the instruction |
| `watch` | the process must be running (opt-in) | mutable state: counters, flags, floats, and fields of heap objects behind a global pointer |

**`xref`.** A compiler reaches each global through the program counter (`mov eax, [rip+disp]`).
Decoding the executable sections and collecting those data addresses lists the variables the program
really uses, and the instruction types them:

| Evidence in the code | Result |
|---|---|
| 4-byte access, no SSE | `i32` |
| `movss` / `addss` / `cvtss2sd` ... | `f32` |
| 8-byte access holding a pointer to readable memory | followed: text there → `char*` string, else `ptr` |
| `movsd` / `addsd` / `cvtsd2ss` ... | `f64` |
| 8-byte access, anything else | `i64` |
| 1-byte access, bytes form text | `char[N]` string (it was the first element of an array) |
| only `lea` (address taken), bytes form text | `char[N]` string |
| only `lea`, not text | `blob` (struct / array) — not in the dictionary |

Neighbouring fields touched by the code become separate variables, so a struct that the code
reads field by field comes out field by field.

**`watch`.** The process is sampled N times. A 4- or 8-byte slot is a variable only if it behaves
like one: a counter (fixed step, or small monotonic steps), a flag (two values), or a smooth float.
Only two kinds of memory are watched, because everything else is noise that looks like variables
(allocator metadata, stack frames): the executable's own `.data`/`.bss`, and **heap blocks reachable
from a global pointer** (size from the glibc chunk header, 64 bytes if there is none, at most 4 KiB).
Watching also upgrades known variables: a symbol or `xref` variable that changes gets
`changed Nx while watched (counter)` as evidence — proof that it is live state.

Measured on the reference programs (`testdata/`, stripped binaries):

| Program | Result |
|---|---|
| `target2.c`, quiet | all 11 globals with correct types; 4 of 4 fields of the heap struct behind `sess`; 1 runtime-bookkeeping variable (`completed.0`) |
| `noisy.c`, 400 mallocs/frees + random writes per loop, one real global | the real counter, 0 false variables (+ `completed.0`) |

The same watch applied to *all* heap and stack memory produced 105 false counters and 682 false
flags on the noisy program. That is why only the two kinds of memory above are watched.

## 1. Add the module

```text
penguin-cloner/src/vars.rs
penguin-cloner/src/vars/discover.rs
```

```rust
// src/main.rs
mod vars;
```

`Cargo.toml` — one optional dependency, the x86_64 decoder (see `Cargo.toml.snippet`):

```toml
[dependencies]
iced-x86 = { version = "=1.21.0", optional = true }

[features]
default = ["xrefs"]
xrefs = ["dep:iced-x86"]
```

`cargo build --no-default-features` drops it: symbols and `watch` keep working, `xref` discovery is
reported as skipped in `notes`. Everything else uses only `std`. MSRV 1.88.

## 2. Wire it into the CLI

I could not read `src/` of the repo, so these snippets assume `clap` derive; rename to match.

**Flags on `dump`** (the target is frozen there, so there is no `--watch`):

```rust
/// Also write variables.json: typed dictionary of the program's variables (auto-discovered)
#[arg(long)]
vars: bool,
/// Unstripped build or .debug file of the SAME build (real names instead of g_<offset>)
#[arg(long, value_name = "FILE")]
symbols: Option<std::path::PathBuf>,
/// Mask values of variables / env vars whose name looks secret
#[arg(long)]
redact_secrets: bool,
```

**Subcommand `vars`** (variables only, no memory dump; here `--watch` is allowed):

```rust
Vars {
    #[arg(long)] pid: u32,
    #[arg(long)] out: std::path::PathBuf,
    #[arg(long, value_name = "FILE")] symbols: Option<std::path::PathBuf>,
    /// Observe the running process for SECONDS to find counters, flags and floats
    #[arg(long, value_name = "SECONDS")] watch: Option<f64>,
    /// Treat the binary as stripped even if it has symbols
    #[arg(long)] ignore_symbols: bool,
    /// Symbols only: no automatic discovery
    #[arg(long)] no_discover: bool,
    /// Also report read-only constants (.rodata) found from code (noisy)
    #[arg(long)] discover_rodata: bool,
    #[arg(long)] redact_secrets: bool,
    /// List pointers / structs / zeroed buffers under `details`
    #[arg(long)] keep_opaque: bool,
},
```

**Helper both call:**

```rust
fn write_variables(
    pid: u32,
    out: &std::path::Path,
    symbols: Option<&std::path::Path>,
    opts: vars::VarOptions,
) -> Result<(), String> {
    let (path, report) = vars::dump_variables(pid, out, symbols, &opts)?;
    eprintln!(
        "variables.json: {} variables, {} env vars -> {}",
        report.dictionary().len(),
        report.environment.len(),
        path.display()
    );
    Ok(())
}

fn watch_options(seconds: Option<f64>) -> Option<vars::WatchOptions> {
    seconds.map(|s| {
        let samples = 6usize;
        vars::WatchOptions {
            samples,
            interval_ms: ((s * 1000.0) / (samples as f64 - 1.0)).max(10.0) as u64,
            ..Default::default()
        }
    })
}
```

For `vars`:
```rust
let opts = vars::VarOptions {
    redact_secrets,
    keep_opaque,
    discover: !no_discover,
    discover_rodata,
    ignore_symbols,
    watch: watch_options(watch),
    ..Default::default()
};
write_variables(pid, &out, symbols.as_deref(), opts)?;
```

For `dump --vars`, call it **after the regions are written and before the ptrace detach**, never
with `watch` (a frozen process cannot change):

```rust
if args.vars {
    let opts = vars::VarOptions { redact_secrets: args.redact_secrets, ..Default::default() };
    if let Err(e) = write_variables(pid, &out_dir, args.symbols.as_deref(), opts) {
        eprintln!("warning: variables.json not written: {e}"); // never fail the whole dump
    }
}
```

Values and code are read from the **live process** (`/proc/<pid>/mem`, `/proc/<pid>/exe`), so the
result is complete even with `--heap-stack-only` (globals live in `.data`/`.bss`, which that mode
does not dump).

## 3. Output

`variables.json` (mode 0600):

| Key | Content |
|---|---|
| `variables` | the dictionary: `name -> int / float / string` |
| `environment` | the process environment, typed the same way (`0644`, `1.10`, `+5` stay strings) |
| `details` | per variable: `addr`, `size`, `type`, `section`, `source` (`symbol`/`xref`/`watch`), `evidence`, `aliases`, `as_unsigned`, `points_to` |
| `elf` | `type`, `load_bias`, `symbols_from` (`symtab` / `dynsym` / `ignored` / `none`) |
| `notes` | what was skipped, what the watch saw, which caveats apply |

```json
"details": {
  "g_4024": {"addr": "0x5605fcd44024", "size": 4, "type": "f32", "section": ".data",
             "binding": "unknown", "in_dictionary": true, "source": "xref",
             "evidence": ["1 code references", "read or written with SSE float instructions",
                          "accessed as 4 byte(s)"]},
  "g_4090": {"addr": "0x5605fcd44090", "size": 8, "type": "f64", "section": ".bss",
             "binding": "unknown", "in_dictionary": true, "source": "xref",
             "evidence": ["2 code references", "read or written with SSE float instructions",
                          "accessed as 8 byte(s)", "changed 5x while watched (float): 0.899 -> 0.77"]},
  "g_4098->+0x8": {"addr": "0x5605fe2c42a8", "size": 4, "type": "i32", "section": "heap block behind g_4098",
                   "binding": "unknown", "in_dictionary": true, "source": "watch",
                   "evidence": ["changed 5x while watched (counter): 18 -> 36"]}
}
```

```bash
jq '.variables' clone-12345/variables.json
jq -r '.details | to_entries[] | select(.value.evidence | any(test("counter"))) | .key' clone-12345/variables.json
```

## 4. Limits (read these)

1. **Synthesized names.** Without symbols the program's own names are gone; you get `g_<offset>`.
   `--symbols <unstripped build | .debug file>` of the same build restores them (build-id verified).
2. **x86_64 only** for `xref` (aarch64 binaries still get symbols and `watch`). ELF64 little-endian.
3. **Only what the code touches.** A global that no instruction references, or that is reached only
   through a pointer parameter or a computed index, is not found by `xref`; `watch` finds it if it changes.
4. **C-runtime bookkeeping leaks in:** one variable such as `completed.0` shows up (a pointer to
   itself, `__dso_handle`, is filtered). It is harmless and recognizable by its tiny value and many references.
5. **Heap objects only behind a global pointer**, one level deep. A heap object held only on the
   stack, or in a pointer inside another heap object, is not followed. The block size comes from the
   glibc chunk header; other allocators (musl, jemalloc, tcmalloc) get a 64-byte window.
6. **`watch` needs the process running** and only proves *mutable* state. Constants and settings that
   do not change during the watch come from `xref`/symbols, not from `watch`. A 4-byte flag next to
   another 4-byte flag is told apart by its own behaviour, but two unrelated changing 4-byte values that
   look like one double are merged into one `f64`.
7. **Types are inferred, no DWARF.** A struct the code never reads field by field is a `blob`;
   an `unsigned` above `i32::MAX` shows negative (`as_unsigned` has the other reading); `char[4]` is an `i32`.
8. Main executable only (not the globals of shared libraries). Stack locals are not covered.
9. Values can contain secrets. The file is `0600`; `--redact-secrets` masks suspicious names.

## 5. Tests

```bash
cargo test vars
```

| Test | What it proves |
|---|---|
| `code_references_reveal_typed_variables_without_symbols` | hand-assembled x86_64 code in a synthetic ELF: `mov`, `movss`, `movsd`, `lea` become `i32`, `f32`, `f64`, string — no symbols involved |
| `watch_finds_counter_float_and_flag` | a mock live memory: a step-7 counter, a smooth double and a flag are told apart |
| `live_watch_sees_a_counter_change` | the test binary watches **itself** while a thread increments a static; the counter is reported |
| `live_self_dump_maps_typed_globals` | symbols + `/proc/self/mem` end to end |
| `series_classification`, `halves_are_joined_by_sample_index`, … | the rules in isolation, including allocator-like garbage staying `varying` |

The `xref` tests need the default `xrefs` feature. `testdata/` has the C programs behind the
measurements:

```bash
gcc -O0 -w -o t2 testdata/target2.c -lm && strip t2 && ./t2 &
sudo penguin-cloner vars --pid $! --out ./v --watch 1 && jq .variables ./v/variables.json

gcc -O0 -w -o noisy testdata/noisy.c && strip noisy && ./noisy &
sudo penguin-cloner vars --pid $! --out ./vn --watch 1 && jq .variables ./vn/variables.json
```

## 6. Re-running on an existing dump (not wired)

`vars --dir` depends on how `memory_index.json` names region files, which I could not see. The core
accepts any memory through `MemSource`; `RegionsMem` serves `(start address, bytes)` regions:

```rust
let mem = vars::RegionsMem::new(regions);          // regions read from the dump
let input = vars::Input {
    pid, exe_path: &exe_path, elf: &exe_bin, maps: &maps_txt,
    environ: Some(&environ), symbols_elf: None,
};
let report = vars::collect(&input, &mem, &vars::VarOptions::default())?;   // no watch: nothing runs
```

`.data` and `.rodata` are file-backed mappings, so such a dump needs `--include-file-backed`.
