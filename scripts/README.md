# scripts/

Convenience wrappers for the common tasks.

| script | what it does |
|---|---|
| `setup_env.sh` | Create the project venv and install all dependencies. On this branch it builds the standard `.venv` from `requirements.txt` (plus scipy/matplotlib for the plots). Override the interpreter with `PYTHON=python3.12 scripts/setup_env.sh`. |
| `run_sweep.sh [ELF] [N] [JOBS] …` | Whole-call fault sweep (`ucpqc sweep`), parallel by default (`JOBS=0` = all CPUs, `JOBS=1` = serial). |
| `run_funcskip.sh [ELF] [N] [JOBS] …` | Intra-function instruction-skip sweep (`ucpqc funcskip`). Pass extra flags like `--target y_sampler`, `--dumpdir dumps`, or `--captures captures`. |
| `capture.sh [ELF] [N] [JOBS] [OUT] …` | Build a persistent **capture cache** (`ucpqc capture`): one 2N-signing pass over every target, so later funcskip runs replay with no re-signing. |
| `detect.sh DUMPDIR [--detector X]` | Re-run a detector **offline** on a dumped sweep/funcskip (`ucpqc detect`) — no emulator. |
| `llvm_study.sh [N] [JOBS]` | The LLVM-IR → ARM-binary translation study: capture once, replay every Dilithium target from the cache, build `report/llvm_vs_arm.md` + plots. |
| `run_tests.sh` | Run the test suite (includes the serial-vs-parallel parity check). |

Typical capture-once / replay-many workflow:
```sh
scripts/capture.sh                                   # one signing pass -> captures/ (all targets)
scripts/run_funcskip.sh firmware/ml-dsa-44_m4f_test.elf 40 14 \
    --target poly_add --captures captures --dumpdir dumps   # replay, no re-sign
scripts/detect.sh dumps/poly_add_instrskip --detector structural
```

The run scripts pick the interpreter automatically: the free-threaded `.venv314t`
if present, else the standard `.venv`, else `python3`. Override with
`VENV=/path/to/venv scripts/run_sweep.sh …`.

```sh
scripts/setup_env.sh                                       # once
scripts/run_tests.sh
scripts/run_sweep.sh                                       # defaults: ml-dsa-44, N=12, all CPUs
scripts/run_sweep.sh firmware/ml-dsa-44_m4f_test.elf 12 1  # serial baseline
```

On the `parallel-freethreading` branch, `setup_env.sh` instead builds a
free-threaded `.venv314t` (Python 3.14t) for the no-GIL threading backend — see
`PARALLEL.md` there.
