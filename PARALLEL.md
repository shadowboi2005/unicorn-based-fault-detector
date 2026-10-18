# Free-threaded parallelism (`-j`)

Both sweep modes parallelise with **real threads on a no-GIL CPython 3.14t**
build. `-j1` (the default) is the untouched serial path; `-j N` (or `-j0` = all
CPUs) runs the thread backend. On a GIL build the threaded paths still give the
same results, just serially (`sweep -j` prints a warning).

| command | module | what is split across threads | parity test |
|---|---|---|---|
| `sweep -j N` | `ucpqc/parallel.py` | the whole-call fault sites (one task per site, `as_completed`) | `test_parallel_sweep_matches_serial` — bit-identical to serial |
| `funcskip -j N` | `ucpqc/parallel_funcskip.py` | both phases: the 2N capture signings *and* the skip-site replays | `test_funcskip_parallel_jobs_invariant` — `jobs=1` ≡ `jobs=K` |

Because a Unicorn `Uc` is stateful, threads don't *share* a machine — each worker
thread builds its own from the ELF path (held in a `threading.local`). Nothing is
pickled: the read-only inputs (keys, messages, captures, golden baseline) are
shared in memory.

`funcskip -j` makes each capture signing an order-free unit (fresh post-setup
snapshot + per-`(key, index)` RNG seed), so its dumps are identical for any `-j`,
but its nonces differ from the serial (`-j1`, single RNG stream) capture — compare
verdicts, not raw outputs, across the two. It uses the `call` backend.

A `ProcessPoolExecutor` alternative (works on stock 3.12, ~11× the memory at
`-j20`, see `examples/plots/9/09.md`) lives on the unmerged
`parallel-multiprocessing` branch.

## Result (`sweep -j`)

- **Spike (the go/no-go):** 8 threads, each a full ML-DSA signing, 1.93 s → 0.43 s
  (~4×), with `sys._is_gil_enabled()` staying `False` and threaded outputs equal
  to serial. Independent `Uc` instances genuinely parallelise under free-threading.
- **Full sweep, N=12:** serial ~300 s → `-j20` **~22.5 s (~13×)**, ~16 cores busy,
  same verdict (`0x4d5e polyvecl_add` LEAK). Floored by the slowest hang-to-cap
  site, not the site count (see `examples/plots/9/09.md`).

## Setting up the 3.14t venv

`scripts/setup_env.sh --ft` does all of the below and builds `.venv314t`; the run
scripts pick it up automatically. The manual steps, for reference:

The one non-obvious dependency is **unicorn**. It is a ctypes binding around a
bundled `libunicorn.so` (no CPython extension module), so the 2.1.4 package files
run unchanged on 3.14t. But its *published* wheel is `cp37-abi3`, which is
tag-incompatible with free-threading (pip won't accept it), and a source build
trips `py_limited_api` + `bdist_wheel` (setuptools#4420). So:

1. Free-threaded interpreter (`python3.14t`). On Debian/Ubuntu:
   `sudo apt install python3.14-nogil` (deadsnakes PPA). Then
   `python3.14t -m venv .venv314t`. (Debian strips the bundled pip, so
   `ensurepip` fails during venv creation and the venv itself still gets made;
   bootstrap pip with `curl -fsSL https://bootstrap.pypa.io/get-pip.py |
   .venv314t/bin/python`.)
2. FT-native wheels: `.venv314t/bin/pip install numpy scipy capstone pyelftools`
   (numpy/scipy ship real `cp314t` wheels; capstone/pyelftools are portable).
3. unicorn: `pip install unicorn` on 3.14t resolves to an **older** 2.1.x with a
   `py2.py3-none` wheel, which has an mmio/`ctl` bug that breaks the peripheral
   setup. Use the 2.1.4 package instead — it is pure ctypes, so copy its files
   from a 3.12 venv (`site-packages/unicorn` + `unicorn-2.1.4.dist-info`), or
   build 2.1.4 from source with `py_limited_api` dropped when
   `sysconfig.get_config_var("Py_GIL_DISABLED")` is set (the upstream fix). Verify:
   `python -c "import unicorn; print(unicorn.__version__)"  # 2.1.4`.

Then `python -m ucpqc sweep <elf> --n 12 -j20`,
`python -m ucpqc funcskip <elf> --target ntt --n 24 -j20 --dumpdir runs/dumps`, and
`python tests/run_tests.py` on that interpreter.
