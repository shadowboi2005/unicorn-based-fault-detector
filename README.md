# ucpqc — a Unicorn-based fault-analysis platform for PQC firmware

Runs **CRYSTALS-Dilithium (ML-DSA)** — and any other pqm4 scheme — on an
emulated ARM Cortex-M4, and exposes the execution to Python: call individual
functions with your own inputs, trace them, and inject faults to assess whether
the firmware leaks its secret key under a fault.  This is a fault-analysis
platform, not a side-channel leakage simulator.

The emulated board is **MPS2-AN386**, the same target the pqm4 `make` flow and
the QEMU setup in `../QEMU-test` use, so the ELFs are byte-identical to what
`qemu-system-arm -M mps2-an386` executes. Unlike QEMU-plus-GDB, the whole
machine is a Python object: you can call `crypto_sign_signature_ctx` directly,
snapshot the state, flip a bit in a register at instruction 4,712,003, and read
the resulting signature back — without a debugger in the loop.

```
$ python -m ucpqc roundtrip firmware/ml-dsa-44_m4f_test.elf
scheme:   ml-dsa-44/m4f (sign)
  pk     1312 bytes  ae8960e8d4ec99ab190ec60f1ad82b02...
  sk     2560 bytes  ae8960e8d4ec99ab190ec60f1ad82b02...
  sig    2420 bytes  2640ceec5fc84107eb3c788a25cba8b3...

instruction counts:
  keypair         1,292,688
  signature      12,132,505
  verify          1,261,019

verified: True   (1.40s wall)
```

## Setup

```bash
make setup          # .venv with unicorn, capstone, pyelftools, numpy
make firmware       # builds ML-DSA-44/65, ML-KEM-768 and the ML-DSA reference
make test           # 26 tests, ~25s
make demo
```

`make firmware` drives the pqm4 tree at `../pqm4` (override with `PQM4=`). It
stages each ELF into `firmware/` together with a JSON manifest recording the
scheme's buffer sizes, read out of its headers with the C preprocessor.

## Command line

```bash
python -m ucpqc run       fw.elf            # boot it, print its UART output
python -m ucpqc info      fw.elf            # API binding, sizes, memory map
python -m ucpqc symbols   fw.elf 'poly_*'
python -m ucpqc roundtrip fw.elf            # keygen/sign/verify (or KEM) by direct calls
python -m ucpqc profile   fw.elf --op sign --top 15
python -m ucpqc calls     fw.elf --op keypair --depth 4
python -m ucpqc trace     fw.elf --func ntt --scope body --csv ntt.csv
python -m ucpqc fault     fw.elf --func challenge --model skip --hit 2 --csv faults.csv
python -m ucpqc sweep     fw.elf --n 24                    # whole-call leak sweep (ALAFA)
python -m ucpqc funcskip  fw.elf --target polyvecl_add     # intra-function skip sweep
python -m ucpqc build     crypto_kem/ml-kem-768/m4fspeed
python -m ucpqc schemes   dilithium         # what is available in the pqm4 tree
```

`sweep` and `funcskip` are the two **fault-leakage assessment modes** — they ask
whether a *fault* makes the output leak the secret key (no side-channel traces
are involved).  `sweep` skips each whole operation call in the signing loop —
its sites are **auto-discovered** by disassembling the resolved signing function
(no per-firmware address table) — and runs a two-key test on the released
signatures (only `z = z + y` leaks, at 100%).  `funcskip` skips every
instruction *inside* one function by capturing its I/O once and replaying just
that function per trial (~240x cheaper than re-signing).  Both auto-select an
**analysis profile** from the scheme (`--profile` to override, `--detector` to
force `two_key`/`uniformity`/`spec_aware`, `--plot DIR` to render a bar chart).

`--func` accepts a symbol name or one of the landmarks the framework resolves
per scheme family (`ntt`, `invntt`, `challenge`, `decompose`, `keccak`).

## Python API

```python
from ucpqc import Machine, Scheme

m = Machine.from_elf("firmware/ml-dsa-44_m4f_test.elf")
scheme = Scheme.bind(m)          # entry points and sizes come from the ELF
m.boot()                         # reset -> SystemInit -> main, C runtime ready
m.stub_randombytes(b"seed")      # RNG becomes a reproducible SHAKE256 stream

pk, sk = scheme.keypair()
sig = scheme.sign(b"hello", sk)
assert scheme.verify(sig, b"hello", pk)
print(scheme.last_cost)          # {'keypair': 1292688, 'signature': 12132505, ...}
```

Any function in the image can be called directly with AAPCS arguments:

```python
import struct
poly = m.alloc_bytes(struct.pack("<256i", *coefficients))
m.call("pqcrystals_dilithium_ntt", [poly])
transformed = struct.unpack("<256i", m.read(poly, 1024))
```

### Analysis layers

| Tool | What it gives you | Cost |
|---|---|---|
| `Profiler` | instructions per function over a whole operation | negligible |
| `CallTracer` | call tree with per-call instruction cost | low |
| `InstructionTracer` | every instruction, optionally with registers | high |
| `MemoryTracer` | every load/store in an address range | medium |
| `FaultCampaign` | sweep of fault models, classified against a golden run | one run per trial |
| `assess.sweep_sites` | whole-call leak sweep of the operation loop (mode `sweep`) | one op per trial |
| `assess.sweep_function` | intra-function instruction-skip sweep via capture-replay (mode `funcskip`) | one function per trial |
| `detectors` | two-key classifier, TVLA t-test, MMD, uniformity, band tests | — |

Faults are a `FaultSpec` (what) plus a trigger (when): `at=` a global
instruction index, or `pc=` a symbol/address on its `hit`-th execution. Models
are instruction skip, register bit-flip, register stuck-at, memory bit-flip,
memory stuck-at, and condition-flag inversion.

```python
from ucpqc import FaultCampaign, FaultSpec
from ucpqc.faults import sweep_function_body

campaign = FaultCampaign(m, lambda mm: scheme.sign(msg, sk))
campaign.prepare()                                    # golden run + snapshot
campaign.run(sweep_function_body(m, "pqcrystals_dilithium_poly_chknorm"))
print(campaign.format())        # silent / different / rejected / crash / timeout
```

Each trial restores a snapshot taken just before the golden run, so a trial
costs one signing operation and nothing else.

## Running another PQC scheme

The emulator, the tracers, the fault injector and the analysis engine work on
instructions and memory; none of them names an algorithm. Only
`ucpqc/scheme.py` knows what a signature or a KEM is, and it discovers that
from the ELF. For a scheme that is in pqm4, the whole change is a build:

```bash
python -m ucpqc build crypto_kem/ml-kem-768/m4fspeed
python -m ucpqc roundtrip firmware/ml-kem-768_m4fspeed_test.elf
```

That works because `Scheme.bind()` does three things automatically:

1. **Entry points** — pattern-matches the symbol table for `crypto_sign_*` or
   `crypto_kem_*`, including PQClean's namespaced spellings
   (`PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc`) and the pq-crystals reference
   names (`pqcrystals_dilithium2_ref_keypair`). Signature schemes with the
   FIPS 204 context API get the 7-argument `_ctx` form; older ones get the
   5-argument form.
2. **Buffer sizes** — from the manifest written at build time, falling back to
   a table of well-known schemes, and finally to over-allocation with size
   probing (`Scheme.probe_sizes()`).
3. **Operations** — `keypair`/`sign`/`verify` for signatures,
   `keypair`/`encaps`/`decaps` for KEMs, both reachable through
   `scheme.roundtrip()`.

What you *may* want to add, and where:

| Situation | What to change |
|---|---|
| Another pqm4 scheme | nothing — `python -m ucpqc build <scheme path>` |
| Keep it in `make firmware` | add the path to `SCHEMES` in the `Makefile` |
| Firmware built outside pqm4 | point `Machine.from_elf()` at the ELF; if it has no manifest, pass `Scheme(m, sizes=Sizes(pk=..., sk=..., sig=...))` or call `probe_sizes()` |
| Unusual API names | `Scheme(m, binding=Binding(kind, {"keypair": "...", ...}))` |
| Convenient names for internals (`--func ntt`) | add an entry to `LANDMARKS` in `ucpqc/scheme.py` |
| A different board (STM32, nRF, …) | add a `Platform` in `ucpqc/platform.py` (memory map + UART base) and model any peripheral the firmware pokes in `Peripherals` |
| A different core (Cortex-M0/M33, RISC-V) | `Machine(..., cpu=...)` for another Cortex-M; another architecture needs the Unicorn arch/mode and the semihosting decoder in `machine.py` |
| Fault `sweep`/`funcskip` on a new scheme | add an **analysis profile** (below) |

### Adding a scheme to the fault modes

`Scheme.bind` makes any pqm4 scheme *run*.  The `sweep`/`funcskip` modes need one
more thing — an **`AnalysisProfile`** (`ucpqc/profiles/`) that supplies the
scheme-specific analysis knowledge the emulator can't infer: which fault sites to
sweep, how to turn a released artifact or a captured buffer into a detector
feature, and which detector fits a target.  The engine (`ucpqc/assess.py`) is
written entirely against this interface, so a new scheme is a new module here and
no engine change.  `ucpqc/profiles/mldsa.py` is the worked example:

```python
from ucpqc.profiles import AnalysisProfile, register

class FalconProfile(AnalysisProfile):
    patterns = ("falcon-*",)                     # glob -> auto-selected
    def challenge(self, machine, artifact): ...  # per-artifact context
    def response_from_signature(self, art): ...  # sweep-mode response
    def response_from_output(self, buf): ...     # funcskip-mode response
    def feature(self, context, response): ...    # -> real-valued classifier feature

register(FalconProfile)
```

The profile is auto-selected from `scheme.name`; KEM profiles set `op = "decaps"`.
The sweep `fault_sites` are **auto-discovered** by disassembling the signing
function (base-class default) — override only for curated/filtered sites.

**What a new algorithm must supply**, by which detector you want:

| detector | what the profile must add | example |
|---|---|---|
| `two_key` / `per_coord` / `subspace` | `challenge`, `response_from_*`, `feature` (a real-valued, ideally leak-aligned feature — e.g. Dilithium's matched filter) | `MLDSAProfile.feature` |
| `uniformity` / `spec_aware` | the raw-coefficient response + the relevant bound (`reject_bound`) | `MLDSAProfile.reject_bound` |
| `structural` (field-aware) | `field` (a `detectors.Field`: `PrimeField(q)`, `GF2m(m)`, …) **and** `structural_feature(context, response)` returning a row of **field elements** built so a leak shows as a low-rank, key-dependent subspace | `MLDSAProfile` (`PrimeField(Q)` + `s1` deconvolution), `MayoProfile` (`GF2m(4)` + oil bytes) |
| `funcskip` mode | `targets()` / `default_target` (a `replay.Target`: function, arg layout, output) | `MLDSAProfile.targets` |

`challenge`/`response_from_*`/`feature` are the minimum to run any two-key-family
sweep; `field`+`structural_feature` are the extra pair for the field-aware
structural detector, and `targets()` is the extra piece for the intra-function
`funcskip` mode. Everything else (fault-site discovery, the mode engine, the
detectors themselves) is scheme-agnostic. The **structural feature is where the
scheme's algebra enters** — it is the piece expected to be supplied per scheme
when scanning it (the framework does not infer the leak's algebraic form).

Implementations of the same algorithm should agree bit for bit under the same
seeded RNG, which is a good check after adding one:

```
$ python examples/05_other_schemes.py
ml-dsa-44/clean          sign  ok=True   keypair=1,554,753  signature=3,419,958 ...
ml-dsa-44/m4f            sign  ok=True   keypair=1,272,633  signature=2,084,160 ...
ml-kem-768/m4fspeed      kem   ok=True   keypair=565,098  enc=579,495  dec=619,135

cross-implementation check (same seed, same message):
  ml-dsa-44: ml-dsa-44_clean_test.elf vs ml-dsa-44_m4f_test.elf  ->  identical
```

## Examples

| File | What it shows |
|---|---|
| `examples/01_run_and_call.py` | booting the firmware vs. driving its API |
| `examples/02_profile_and_calls.py` | where a signature spends its cycles |
| `examples/03_fault_campaign.py` | skipping instructions in the norm check |
| `examples/05_other_schemes.py` | the same code driving KEMs and other schemes |
| `examples/08_fault_r0_check.py` | forcing the r0 rejection check to release out-of-spec signatures |
| `examples/09_alafa_sweep.py` | the whole-call fault sweep (mode `sweep`) |
| `examples/10_intra_function_skip.py` | the intra-function skip sweep (mode `funcskip`) |

## How it works

**Boot.** The ELF's `PT_LOAD` segments are written at their physical
addresses, `.bss` is zeroed, and the core starts at the reset vector with SP
from the vector table. `boot()` runs as far as `main`, so by the time you call
anything the C runtime, the FPU and the UART are up.

**Peripherals.** Unicorn emulates only the CPU core, so the board is modelled
in `platform.py`: the CMSDK UART (its output is captured), SysTick and the DWT
cycle counter (both derived from the emulated instruction count), and SCB/NVIC
registers as plain storage. ARM semihosting (`bkpt 0xAB`) is decoded for
`SYS_WRITEC/WRITE0/WRITE/EXIT`, which is how pqm4 firmware signals that it is
done.

**Direct calls.** `call()` sets up AAPCS arguments, points `lr` at an
unmapped-to-the-guest trampoline page, and stops when execution returns there.
Arguments are allocated in a scratch region that the firmware's own heap can
never collide with.

**Counting.** Instructions are counted per basic block (cheap, exact at block
boundaries). Anything needing an exact index — an instruction tracer, a fault
triggered on `at=` — switches the machine to per-instruction counting, which
costs roughly 10× in speed. Hooks scoped to an address range keep the fast
path; that is what `--scope body` does.

Rough speeds on this machine: 14 MIPS unhooked (a full ML-DSA-44 signature in
~1s), ~1.5 MIPS with a global per-instruction hook.

## Caveats

- **Instructions, not cycles.** The counter is an instruction count. It is a
  good proxy for the pqm4 cycle counts (keypair 1,286,649 reported by the
  firmware's own benchmark vs 1,286,622 counted here) but it does not model
  wait states, flash latency or pipeline effects.
- **Fault-effect, not physical leakage.** The two-key/uniformity detectors
  measure whether a *fault* makes the output depend on the secret; they are
  noise-free and idealised — enough to answer *whether* and *where* a fault
  leaks, not how many real traces or faults an attack needs. (Side-channel
  leakage-trace simulation lives on the `has-leakage` branch, not here.)
- **No interrupts.** SysTick is modelled as a counter but its interrupt is
  never delivered, so the firmware's own overflow bookkeeping would wrap;
  `stub_cycle_counter()` replaces `hal_get_time` with the exact count instead.
- **Block-level attribution.** `Profiler` and `CallTracer` attribute at basic
  block granularity, so a block interrupted mid-way is charged in full.

## What's general vs scheme-specific

Almost everything is scheme-agnostic. **All of the Dilithium/ML-DSA specifics are
isolated in one file — `ucpqc/profiles/mldsa.py`** (plus the demo scripts under
`examples/`); the ten other `ucpqc/` modules work on any firmware.

| Layer | Scope |
|---|---|
| `machine`, `elfimage`, `platform` | general — an ARM/Unicorn core, ELF loading, a board |
| `tracing`, `faults`, `replay` | general — operate on instructions/registers/memory/buffers |
| `assess`, `report`, `cli` | general — the mode engine and reporting, written against the profile interface |
| `scheme` | crypto-API-general — auto-detects SIGN/KEM entry points and sizes (ML-DSA, ML-KEM, Falcon, SPHINCS+); not one specific scheme |
| `detectors` | general — `loo_scores`, `two_key_accuracy`, `tvla_t`, `mmd_test`, `uniformity_divergence`, `band_*` take plain feature matrices |
| `detectors.matched_filter` | lattice-FS-specific — negacyclic correlation of a sparse ±1 challenge against response polynomials (the Dilithium *family*, not KEMs/hash-sigs) |
| **`profiles/mldsa.py`** | **Dilithium-specific — everything below** |

The scheme-specific file stacks **three tiers** of specificity, worth separating
if you extend it:

1. **ML-DSA algorithm** — `expand_challenge` (SampleInBall), the matched-filter
   `feature`, and the `z`/`s1` decoders.
2. **The ML-DSA-44 parameter set** — `L=4, K=4, GAMMA1/2, BETA, TAU, ETA,
   SIGLEN=2420`, the `s1` offset. ML-DSA-65/87 would need different values.
3. **This firmware build** — the `pqcrystals_dilithium_*` symbol names used by
   `challenge`/`targets`. These are portable across `ml-dsa-44` builds (symbol
   names, not addresses). The sweep sites are no longer hard-coded: `fault_sites`
   discovers them by disassembling the signing function, so the profile works on
   any `ml-dsa-44` ELF, not just this one.

**MAYO** (multivariate, a NIST additional-signatures candidate) is a second,
non-lattice worked example.  It *runs* on the general core with nothing added —
`python -m ucpqc build crypto_sign/mayo1/m4f` then `roundtrip`/`profile`/`fault`/
`leak` all work.  Its `profiles/mayo.py` shows the honest edge of the abstraction:
MAYO has no sparse challenge or masked response, so the matched filter does not
apply.  The profile therefore discovers its sweep sites by **disassembly**
(`discover_call_sites`, portable across builds) and uses a **generic raw-byte
feature** — a scaffold, since MAYO's randomised signature can confound a two-key
test (the engine's golden-baseline guard flags that).  A high-SNR MAYO leak
feature needs MAYO-specific cryptanalysis and is left as future work.

The `AnalysisProfile` interface *is* the boundary: everything a new scheme must
supply is exactly this scheme-specific surface, and everything else is reused.

```
must write per scheme         auto / optional (defaulted)      reused unchanged (general)
─────────────────────         ───────────────────────────      ──────────────────────────
patterns  (glob)              fault_sites() (disassembly)      machine, elfimage, platform,
challenge()                   detector_for() (-> two_key)      tracing, faults, replay,
response_from_signature()     targets() (probe_target.py,      assess (engine), report, cli,
response_from_output()          opt-in; else hand-written)     scheme (API detection),
feature()      + constants    setup(), artifact_len, op        detectors (incl. the field
field + structural_feature()  field=None (structural off)        backends; except matched_filter),
  (only for structural)                                        profiles/__init__ (registry)
```

## Layout

```
ucpqc/
  platform.py   board memory map and peripheral models
  elfimage.py   ELF loading, symbol index, address -> function
  machine.py    the emulated core: boot, run, call, snapshot, hooks
  scheme.py     the only scheme-aware layer: API detection and sizes
  tracing.py    profiler, call tracer, instruction and memory traces
  faults.py     fault models, injector, campaign runner
  replay.py     capture a function's I/O, replay it in isolation under faults
  detectors.py  two-key classifier, TVLA, MMD, uniformity, band tests
  assess.py     the sweep/funcskip mode engine (scheme-agnostic)
  report.py     console table + bar-chart reporting for assessments
  profiles/     per-scheme analysis knowledge (AnalysisProfile; mldsa.py, mayo.py)
  firmware.py   pqm4 builds and manifest generation
  cli.py        python -m ucpqc
```
