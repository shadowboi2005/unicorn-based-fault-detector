"""Command line front end: `python -m ucpqc <command>`."""

import argparse
import os
import sys
import time

from . import assess as assessmod
from . import faults as faultmod
from . import firmware as fw
from . import profiles as profilemod
from . import report as reportmod
from .elfimage import ElfImage
from .machine import EmulationError, Machine
from .platform import PLATFORMS
from .scheme import SIGN, Scheme
from .tracing import CallTracer, InstructionTracer, MemoryTracer, Profiler

DEFAULT_PQM4 = os.environ.get("UCPQC_PQM4", "../pqm4")


# --- helpers ----------------------------------------------------------------


def _machine(args, stub_rng=True):
    m = Machine.from_elf(args.elf, platform=PLATFORMS[getattr(args, "platform", "mps2-an386")])
    scheme = Scheme.bind(m)
    m.boot()
    if stub_rng:
        try:
            m.stub_randombytes(getattr(args, "seed", "ucpqc").encode())
        except KeyError:
            print("warning: no randombytes symbol; using the firmware's own RNG",
                  file=sys.stderr)
    m.stub_cycle_counter()
    return m, scheme


def _operation(scheme, name, message=b"ucpqc", budget=200_000_000):
    """Build a callable performing one named operation, for reuse by commands.

    Returns (fn, description).  The keys/ciphertext it needs are generated
    once, up front, so the measured operation is only the one asked for.
    """
    kwargs = {"max_instructions": budget}
    if scheme.kind == SIGN:
        if name == "keypair":
            return (lambda m: scheme.keypair(**kwargs)), "keypair"
        pk, sk = scheme.keypair()
        if name == "sign":
            return (lambda m: scheme.sign(message, sk, **kwargs)), "sign"
        if name == "verify":
            sig = scheme.sign(message, sk)
            return (lambda m: scheme.verify(sig, message, pk, **kwargs)), "verify"
        if name == "roundtrip":
            return (lambda m: scheme.roundtrip(message, **kwargs)), "roundtrip"
    else:
        if name == "keypair":
            return (lambda m: scheme.keypair(**kwargs)), "keypair"
        pk, sk = scheme.keypair()
        if name in ("enc", "sign"):
            return (lambda m: scheme.encaps(pk, **kwargs)), "encaps"
        if name in ("dec", "verify"):
            ct, _ = scheme.encaps(pk)
            return (lambda m: scheme.decaps(ct, sk, **kwargs)), "decaps"
        if name == "roundtrip":
            return (lambda m: scheme.roundtrip(message, **kwargs)), "roundtrip"
    raise SystemExit(f"unknown operation {name!r} for a {scheme.kind} scheme")


def _resolve_func(scheme, name):
    """Allow landmark aliases (ntt, keccak, ...) wherever a symbol is expected."""
    return scheme.landmark(name) or name


# --- commands ---------------------------------------------------------------


def cmd_build(args):
    staged = fw.build(
        args.scheme,
        args.pqm4,
        out_dir=args.out,
        platform=args.platform,
        tests=tuple(args.tests.split(",")),
        jobs=args.jobs,
    )
    print(f"\n{len(staged)} firmware image(s) ready in {args.out}/")
    return 0


def cmd_schemes(args):
    found = fw.discover(args.pqm4, args.pattern)
    for path in found:
        print(path)
    print(f"\n{len(found)} implementation(s) in {args.pqm4}", file=sys.stderr)
    return 0


def cmd_info(args):
    image = ElfImage(args.elf)
    m, scheme = _machine(args)
    print(f"firmware: {args.elf}")
    print(f"entry:    {image.entry:#010x}   functions: {len(image.functions)}")
    print(scheme.describe())
    print("\nmemory map:")
    for region in m.platform.ram_regions:
        print(f"  {region.name:<11} {region.base:#010x} - {region.end:#010x}")
    for region in (m.platform.apb, m.platform.ppb):
        print(f"  {region.name:<11} {region.base:#010x} - {region.end:#010x}  (mmio)")
    print(f"\nboot to main: {m.icount} instructions")
    return 0


def cmd_symbols(args):
    image = ElfImage(args.elf)
    for sym in image.find(args.pattern or "*", kind=None if args.all else "STT_FUNC"):
        print(f"{sym.addr:#010x}  {sym.size:>7}  {sym.kind:<11} {sym.name}")
    return 0


def cmd_run(args):
    m = Machine.from_elf(args.elf, platform=PLATFORMS[args.platform])
    if args.stream:
        m.peripherals.on_uart_byte = lambda b: (
            sys.stdout.write(chr(b)),
            sys.stdout.flush(),
        )
    started = time.time()
    try:
        m.run(max_instructions=args.max_insns)
    except EmulationError as exc:
        print(f"\n!! {exc}", file=sys.stderr)
        return 1
    finally:
        elapsed = time.time() - started
    if not args.stream:
        print(m.uart_text())
    print(
        f"--- exit={m.exit_code:#x} instructions={m.icount:,} "
        f"time={elapsed:.2f}s ({m.icount / max(elapsed, 1e-9) / 1e6:.1f} MIPS)",
        file=sys.stderr,
    )
    return 0


def cmd_roundtrip(args):
    m, scheme = _machine(args)
    started = time.time()
    result = scheme.roundtrip(args.message.encode())
    print(f"scheme:   {scheme.name} ({scheme.kind})")
    for key in ("pk", "sk", "sig", "ct", "ss"):
        if key in result:
            value = result[key]
            print(f"  {key:<4} {len(value):>6} bytes  {value[:16].hex()}...")
    print("\ninstruction counts:")
    for op, count in result["cost"].items():
        print(f"  {op:<10} {count:>14,}")
    verdict = "verified" if scheme.kind == SIGN else "shared secrets match"
    print(f"\n{verdict}: {result['ok']}   ({time.time() - started:.2f}s wall)")
    return 0 if result["ok"] else 1


def cmd_profile(args):
    m, scheme = _machine(args)
    op, label = _operation(scheme, args.op, args.message.encode())
    prof = Profiler(m)
    started = time.time()
    op(m)
    prof.detach()
    print(f"profile of {label} ({scheme.name}), {time.time() - started:.2f}s wall\n")
    print(prof.format(args.top))
    return 0


def cmd_calls(args):
    m, scheme = _machine(args)
    op, label = _operation(scheme, args.op, args.message.encode())
    tracer = CallTracer(m, max_depth=args.depth)
    op(m)
    tracer.finish()
    tracer.detach()
    print(f"call tree of {label} ({len(tracer.calls)} calls):\n")
    print(tracer.format(args.lines, min_cost=args.min_cost))
    return 0


def cmd_trace(args):
    m, scheme = _machine(args)
    func = _resolve_func(scheme, args.func) if args.func else None
    op, label = _operation(scheme, args.op, args.message.encode())
    if args.mem:
        tracer = MemoryTracer(m, window=func, limit=args.limit)
    else:
        tracer = InstructionTracer(
            m, window=func, limit=args.limit, with_regs=args.regs, scope=args.scope
        )
    op(m)
    scope = f" inside {func}" if func else ""
    print(f"{len(tracer)} records from {label}{scope}\n")
    if args.csv:
        print("written to", tracer.write_csv(args.csv))
    else:
        print(tracer.format(args.lines))
    return 0


def cmd_fault(args):
    m, scheme = _machine(args)
    func = _resolve_func(scheme, args.func)
    message = args.message.encode()

    if scheme.kind == SIGN:
        pk, sk = scheme.keypair()

        def operation(machine):
            sig = scheme.sign(message, sk, max_instructions=args.budget)
            if args.check and not scheme.verify(sig, message, pk):
                raise ValueError("faulty signature does not verify")
            return sig

    else:
        pk, sk = scheme.keypair()

        def operation(machine):
            ct, ss = scheme.encaps(pk, max_instructions=args.budget)
            if args.check and scheme.decaps(ct, sk) != ss:
                raise ValueError("shared secrets disagree")
            return ct, ss

    campaign = faultmod.FaultCampaign(m, operation, budget=args.budget)
    print(f"golden run of {scheme.name}...", flush=True)
    campaign.prepare()

    if args.model == faultmod.BITFLIP_REG:
        specs = list(
            faultmod.sweep_register_bits(
                m.addr_of(func),
                regs=tuple(args.regs.split(",")),
                bits=range(0, 32, args.stride),
                hit=args.hit,
            )
        )
    else:
        specs = list(
            faultmod.sweep_function_body(
                m, func, kind=args.model, stride=args.stride, count=args.count, hit=args.hit
            )
        )
    print(f"{len(specs)} trials against {func} (hit #{args.hit})\n", flush=True)
    campaign.run(specs, progress=args.progress)
    print("\n" + campaign.format())
    if args.csv:
        print("\nwritten to", campaign.write_csv(args.csv))
    return 0


def _profile(args, scheme):
    return profilemod.profile_for(scheme, override=getattr(args, "profile", None))


def _emit(args, result):
    print(reportmod.format_table(result))
    if getattr(args, "plot", None):
        os.makedirs(args.plot, exist_ok=True)
        out = os.path.join(args.plot, f"{result.mode}.png")
        written = reportmod.plot_sweep(result, out)
        if written:
            print(f"wrote {written}")
    return 0


def cmd_sweep(args):
    """Whole-call fault sweep over the operation's inner loop (ALAFA-style)."""
    m, scheme = _machine(args)
    profile = _profile(args, scheme)
    result = assessmod.sweep_sites(scheme, profile, n=args.n, detector=args.detector,
                                   calibrate=not args.legacy_thresholds, n_perm=args.n_perm,
                                   fdr_q=args.fdr, correction=args.correction,
                                   key_mode=args.key_mode, dump=args.dump)
    rc = _emit(args, result)
    if args.dump:
        print(f"\ndumped golden + {len(result.rows) - 1} faulted sites to {args.dump}/ "
              f"(replay offline with:  ucpqc detect {args.dump} --detector <name>)")
    return rc


def cmd_detect(args):
    """Re-run a detector on a dumped sweep or funcskip capture (`ucpqc.dump`) -- no
    emulator, no scheme build.  Dispatches on the dump's mode, so both a `sweep --dump`
    and a `funcskip --dump` directory replay any detector's calibrated verdict in
    seconds, without re-emulating."""
    import json
    meta = json.load(open(os.path.join(args.dumpdir, "meta.json")))
    if meta.get("mode") == "funcskip":
        result = assessmod.assess_funcskip_from_dump(
            args.dumpdir, detector=args.detector,
            calibrate=not args.legacy_thresholds, n_perm=args.n_perm,
            fdr_q=args.fdr, correction=args.correction)
    else:
        result = assessmod.assess_from_dump(
            args.dumpdir, detector=args.detector or "per_coord",
            calibrate=not args.legacy_thresholds, n_perm=args.n_perm,
            fdr_q=args.fdr, correction=args.correction)
    return _emit(args, result)


def cmd_funcskip(args):
    """Instruction-skip sweep inside one function, via capture-and-replay."""
    dump_dir = getattr(args, "dump", None)
    autoname = f"{args.target or 'funcskip'}_instrskip"
    if getattr(args, "dumpdir", None):            # --dumpdir BASE -> BASE/<target>_instrskip/
        dump_dir = os.path.join(args.dumpdir, autoname)
    elif dump_dir == "__auto__":                  # `--dump` with no value -> <target>_instrskip
        dump_dir = autoname
    if getattr(args, "jobs", 1) != 1:             # multithreaded path (free-threaded 3.14t)
        from . import parallel_funcskip as pf
        result = pf.sweep_function_dump_parallel(
            args.elf, args.target, platform_name=args.platform, n=args.n, jobs=args.jobs,
            key_mode=args.key_mode, profile_override=getattr(args, "profile", None),
            detector=args.detector, calibrate=not args.legacy_thresholds, n_perm=args.n_perm,
            fdr_q=args.fdr, correction=args.correction, dump_dir=dump_dir,
            replay_budget=args.replay_budget)
        rc = _emit(args, result)
        if dump_dir:
            print(f"\ndumped {len(result.rows)} skip sites to {dump_dir}/ "
                  f"(replay offline with:  ucpqc detect {dump_dir})")
        return rc
    m, scheme = _machine(args)
    profile = _profile(args, scheme)
    target = None
    if args.target:
        targets = profile.targets() if hasattr(profile, "targets") else {}
        if args.target not in targets:
            raise SystemExit(f"unknown --target {args.target!r}; "
                             f"known: {', '.join(sorted(targets)) or 'none'}")
        target = targets[args.target]
    result = assessmod.sweep_function(scheme, profile, target=target, n=args.n,
                                      detector=args.detector, backend=args.backend,
                                      budget=args.replay_budget,
                                      calibrate=not args.legacy_thresholds, n_perm=args.n_perm,
                                      fdr_q=args.fdr, correction=args.correction,
                                      key_mode=args.key_mode, dump=dump_dir)
    rc = _emit(args, result)
    if dump_dir:
        print(f"\ndumped {len(result.rows)} skip sites to {dump_dir}/ "
              f"(replay offline with:  ucpqc detect {dump_dir})")
    return rc


# --- argument parsing -------------------------------------------------------


def _add_calibration_flags(p):
    """Shared flags for the leak-detector sweeps (sweep + funcskip): calibration knobs
    and the A/B key mode.

    By default every LEAK verdict is a calibrated decision: a per-site permutation/
    analytic p-value combined across the swept sites by a false-discovery-rate rule.
    `--legacy-thresholds` restores the old fixed cutoffs (0.80 / 0.50 / 0.10)."""
    p.add_argument("--key-mode", default="independent", choices=("independent", "sibling"),
                   help="A/B keys: independent (default) or sibling (key B = key A with "
                        "one secret byte flipped -- a controlled minimal difference, #1)")
    _add_scoring_flags(p)


def _add_scoring_flags(p):
    """Calibration knobs shared by the live sweeps AND the offline `detect` replay:
    permutation count, FDR level, across-site correction, and the legacy opt-out.
    (Unlike `--key-mode`, these are scoring-time choices, so `detect` re-exposes them
    to re-score a dump at a different level without re-emulating.)"""
    p.add_argument("--n-perm", type=int, default=assessmod.DEFAULT_N_PERM, dest="n_perm",
                   help="permutation shuffles for the calibrated p-value (default %(default)s)")
    p.add_argument("--fdr", type=float, default=assessmod.FDR_Q,
                   help="false-discovery-rate level across swept sites (default %(default)s)")
    p.add_argument("--correction", default="bh", choices=("bh", "holm"),
                   help="across-site correction: bh=Benjamini-Hochberg (FDR), "
                        "holm=Holm-Bonferroni (FWER); default bh")
    p.add_argument("--legacy-thresholds", action="store_true", dest="legacy_thresholds",
                   help="keep the old fixed cutoffs (0.80/0.50/0.10), decided per-site, "
                        "with no permutation and no FDR pass")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ucpqc",
        description="Unicorn-based emulation of post-quantum crypto firmware "
        "(CRYSTALS-Dilithium and friends) on Cortex-M4.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_elf(p, op_default=None):
        p.add_argument("elf", help="firmware ELF to emulate")
        p.add_argument("--platform", default="mps2-an386", choices=sorted(PLATFORMS))
        p.add_argument("--seed", default="ucpqc", help="seed for the stubbed RNG")
        p.add_argument("--message", default="ucpqc", help="message to sign")
        if op_default:
            p.add_argument(
                "--op",
                default=op_default,
                help="operation to drive: keypair, sign/enc, verify/dec, roundtrip",
            )

    p = sub.add_parser("build", help="build a scheme from pqm4 and stage it")
    p.add_argument("scheme", help="e.g. crypto_sign/ml-dsa-44/m4f")
    p.add_argument("--pqm4", default=DEFAULT_PQM4)
    p.add_argument("--out", default="firmware")
    p.add_argument("--platform", default=fw.DEFAULT_PLATFORM)
    p.add_argument("--tests", default="test", help="comma separated: test,speed,stack,...")
    p.add_argument("--jobs", type=int, default=None)
    p.set_defaults(handler=cmd_build)

    p = sub.add_parser("schemes", help="list schemes available in a pqm4 tree")
    p.add_argument("pattern", nargs="?", default="")
    p.add_argument("--pqm4", default=DEFAULT_PQM4)
    p.set_defaults(handler=cmd_schemes)

    p = sub.add_parser("info", help="show the scheme binding and memory map")
    add_elf(p)
    p.set_defaults(handler=cmd_info)

    p = sub.add_parser("symbols", help="list symbols in the firmware")
    p.add_argument("elf")
    p.add_argument("pattern", nargs="?", default="*")
    p.add_argument("--all", action="store_true", help="include data symbols")
    p.set_defaults(handler=cmd_symbols)

    p = sub.add_parser("run", help="boot the firmware and print its output")
    p.add_argument("elf")
    p.add_argument("--platform", default="mps2-an386", choices=sorted(PLATFORMS))
    p.add_argument("--max-insns", type=int, default=0, dest="max_insns")
    p.add_argument("--stream", action="store_true", help="print UART output live")
    p.set_defaults(handler=cmd_run)

    p = sub.add_parser("roundtrip", help="run one keygen/sign/verify (or KEM) cycle")
    add_elf(p)
    p.set_defaults(handler=cmd_roundtrip)

    p = sub.add_parser("profile", help="instruction counts per function")
    add_elf(p, op_default="sign")
    p.add_argument("--top", type=int, default=25)
    p.set_defaults(handler=cmd_profile)

    p = sub.add_parser("calls", help="call tree with per-call instruction cost")
    add_elf(p, op_default="sign")
    p.add_argument("--depth", type=int, default=6)
    p.add_argument("--lines", type=int, default=60)
    p.add_argument("--min-cost", type=int, default=0, dest="min_cost")
    p.set_defaults(handler=cmd_calls)

    p = sub.add_parser("trace", help="instruction or memory trace of one function")
    add_elf(p, op_default="sign")
    p.add_argument("--func", help="restrict to this function (or a landmark: ntt, keccak, ...)")
    p.add_argument("--mem", action="store_true", help="trace memory accesses instead")
    p.add_argument("--regs", action="store_true", help="include register state")
    p.add_argument("--limit", type=int, default=200_000)
    p.add_argument("--lines", type=int, default=60)
    p.add_argument(
        "--scope",
        default="call",
        choices=("call", "body"),
        help="call: everything run while inside --func, including callees; "
        "body: only the function's own instructions (much faster)",
    )
    p.add_argument("--csv")
    p.set_defaults(handler=cmd_trace)

    p = sub.add_parser("fault", help="run a fault-injection campaign")
    add_elf(p)
    p.add_argument("--func", required=True, help="function to attack (or a landmark)")
    p.add_argument("--model", default=faultmod.SKIP, choices=faultmod.MODELS)
    p.add_argument("--stride", type=int, default=1, help="step between fault sites")
    p.add_argument(
        "--hit",
        type=int,
        default=1,
        help="which execution of each fault site to hit (1 = the first)",
    )
    p.add_argument("--count", type=int, default=1, help="instructions skipped per fault")
    p.add_argument("--regs", default="r0,r1,r2,r3", help="registers for bitflip_reg")
    p.add_argument("--budget", type=int, default=100_000_000)
    p.add_argument("--progress", type=int, default=25)
    p.add_argument("--csv")
    p.add_argument(
        "--no-check",
        dest="check",
        action="store_false",
        help="do not verify the faulty output (faster, fewer classifications)",
    )
    p.set_defaults(handler=cmd_fault)

    p = sub.add_parser("sweep", help="whole-call fault sweep over the signing loop "
                       "(ALAFA-style two-key leak test)")
    add_elf(p)
    p.add_argument("--n", type=int, default=24, help="signatures per key")
    p.add_argument("--detector", default="per_coord",
                   choices=("two_key", "per_coord", "subspace", "structural", "mmd",
                            "differential", "sifa", "uniformity", "spec_aware", "r0_reject"))
    p.add_argument("--profile", help="force an analysis profile (default: auto from scheme)")
    p.add_argument("--plot", help="directory to write the result bar chart into")
    p.add_argument("--dump", nargs="?", const="dump", default=None, metavar="DIR",
                   help="also write the golden + faulty runs (artifact + challenge per "
                        "item) as JSON to DIR (default 'dump'), for offline replay with "
                        "`ucpqc detect` -- no re-emulation")
    _add_calibration_flags(p)
    p.set_defaults(handler=cmd_sweep)

    p = sub.add_parser("detect", help="re-run a detector on a dumped sweep or funcskip "
                       "capture (`--dump`) offline -- no emulator")
    p.add_argument("dumpdir", help="dump directory written by `sweep --dump` or `funcskip --dump`")
    p.add_argument("--detector", default=None, choices=assessmod.DUMP_DETECTORS,
                   help="detector to score the dump with (default: per_coord/TVLA for a "
                        "sweep dump, the captured detector for a funcskip dump)")
    p.add_argument("--plot", help="directory to write the result bar chart into")
    _add_scoring_flags(p)
    p.set_defaults(handler=cmd_detect)

    p = sub.add_parser("funcskip", help="instruction-skip sweep inside one function "
                       "(capture-and-replay)")
    add_elf(p)
    p.add_argument("--target", help="named funcskip target (default: the profile's)")
    p.add_argument("--n", type=int, default=24, help="signatures per key")
    p.add_argument("--detector", default=None,
                   choices=("two_key", "per_coord", "subspace", "structural",
                            "mmd", "uniformity", "spec_aware"),
                   help="override the profile's detector for the target")
    p.add_argument("--backend", default="call", choices=("call", "snapshot"))
    p.add_argument("--replay-budget", type=int, default=5_000_000, dest="replay_budget",
                   metavar="INSNS",
                   help="max instructions per skip-replay (default 5e6). A skip that breaks "
                        "the target's loop control makes an isolated replay run to this cap "
                        "before it is killed as a crash; since a runaway produces no usable "
                        "output anyway, lowering this to ~10x the function's natural length "
                        "(tens of k) kills runaways far sooner with identical verdicts")
    p.add_argument("-j", "--jobs", type=int, default=1,
                   help="worker threads (1=serial; >1 parallelizes capture + replay, "
                        "best on the free-threaded 3.14t interpreter)")
    p.add_argument("--profile", help="force an analysis profile (default: auto from scheme)")
    p.add_argument("--plot", help="directory to write the result bar chart into")
    p.add_argument("--dump", nargs="?", const="__auto__", default=None, metavar="DIR",
                   help="also write per-item challenge + every skip site's faulted outputs "
                        "to DIR (default <target>_instrskip/), for offline replay with "
                        "`ucpqc detect` -- no re-capture")
    p.add_argument("--dumpdir", metavar="BASE",
                   help="dump into BASE/<target>_instrskip/ (a clean base-dir form of "
                        "--dump; implies dumping -- good for sweeping many targets into one dir)")
    _add_calibration_flags(p)
    p.set_defaults(handler=cmd_funcskip)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (EmulationError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
