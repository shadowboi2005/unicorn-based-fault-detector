# Free-threaded parallel sweep (`parallel-freethreading` branch)

This branch parallelises the fault sweep with **real threads on a no-GIL CPython
3.14t** build. The sweep/replay engine is unchanged on `master`; this branch adds
one file (`ucpqc/parallel.py`, a `ThreadPoolExecutor` backend) plus a `-j/--jobs`
flag on the `sweep`/`funcskip` CLI commands. `-j1` is the untouched serial path;
`-j N` (or `-j0` = all CPUs) runs the thread backend.

Because a Unicorn `Uc` is stateful, threads don't *share* a machine — each worker
thread builds its own from the ELF path (held in a `threading.local`), exactly
like the process backend's per-worker initializer. The win over processes is that
nothing is pickled: the read-only inputs (keys, messages, captures) are shared in
memory. Results are **bit-identical** to the serial engine (asserted by
`tests/run_tests.py::test_parallel_sweep_matches_serial`).

See the sibling `parallel-multiprocessing` branch for the `ProcessPoolExecutor`
backend (works on stock 3.12, no interpreter change).

## Result

- **Spike (the go/no-go):** 8 threads, each a full ML-DSA signing, 1.93 s → 0.43 s
  (~4×), with `sys._is_gil_enabled()` staying `False` and threaded outputs equal
  to serial. Independent `Uc` instances genuinely parallelise under free-threading.
- **Full sweep, N=12:** serial ~300 s → `-j20` **~22.5 s (~13×)**, ~16 cores busy,
  same verdict (`0x4d5e polyvecl_add` LEAK). Floored by the slowest hang-to-cap
  site, not the site count (see `examples/plots/9/09.md`).

## Setting up the 3.14t venv

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

Then `python -m ucpqc sweep <elf> --n 12 -j20` and
`python tests/run_tests.py` on that interpreter.
