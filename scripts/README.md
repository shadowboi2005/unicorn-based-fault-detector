# scripts/

Convenience wrappers for the common tasks.

| script | what it does |
|---|---|
| `setup_env.sh [--ft]` | Create the project venv and install all dependencies. Default: the standard `.venv` from `requirements.txt` (plus scipy/matplotlib for the plots); override the interpreter with `PYTHON=python3.12`. `--ft`: the free-threaded `.venv314t` (Python 3.14t), including the unicorn workaround for no-GIL builds — needed for `-j` to actually speed up (see `PARALLEL.md`). |
| `run_sweep.sh [ELF] [N] [JOBS] …` | Whole-call fault sweep (`ucpqc sweep`), parallel by default (`JOBS=0` = all CPUs, `JOBS=1` = serial). |
| `run_funcskip.sh [ELF] [N] [JOBS] …` | Intra-function instruction-skip sweep (`ucpqc funcskip`). Pass extra flags like `--target y_sampler`. |
| `run_tests.sh` | Run the test suite (includes the serial-vs-parallel parity checks). |
| `cm_compare.sh BASE_ELF HARDENED_ELF [SCHEME]` | Baseline-vs-hardened candidate comparison (funcskip both builds, per-build reports + `cm_compare.md`). |

The run scripts pick the interpreter automatically: the free-threaded
`.venv314t` if present, else the standard `.venv`, else `python3`. Override with
`VENV=/path/to/venv scripts/run_sweep.sh …`.

```sh
scripts/setup_env.sh --ft                                  # once (or without --ft: stock .venv)
scripts/run_tests.sh
scripts/run_sweep.sh                                       # defaults: ml-dsa-44, N=12, all CPUs
scripts/run_sweep.sh firmware/ml-dsa-44_m4f_test.elf 12 1  # serial baseline
```
