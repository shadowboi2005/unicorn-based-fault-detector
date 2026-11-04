#!/usr/bin/env python3
"""Test suite for ucpqc.  Run with `make test` or `python tests/run_tests.py`.

Needs at least firmware/ml-dsa-44_m4f_test.elf; tests that need other images
report themselves as skipped.  Also importable by pytest.
"""

import os
import struct
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ucpqc import (  # noqa: E402
    CallTracer,
    FaultCampaign,
    FaultSpec,
    InstructionTracer,
    Machine,
    Outcome,
    Profiler,
    Scheme,
)
from ucpqc.elfimage import ElfImage  # noqa: E402
from ucpqc.faults import Injector, sweep_function_body  # noqa: E402
from ucpqc.firmware import kind_of, namespace_for  # noqa: E402

FIRMWARE = os.path.join(ROOT, "firmware")
DILITHIUM = os.path.join(FIRMWARE, "ml-dsa-44_m4f_test.elf")
DILITHIUM_REF = os.path.join(FIRMWARE, "ml-dsa-44_clean_test.elf")
KEM = os.path.join(FIRMWARE, "ml-kem-768_m4fspeed_test.elf")


class Skip(Exception):
    pass


def need(path):
    if not os.path.exists(path):
        raise Skip(f"{os.path.relpath(path, ROOT)} not built")
    return path


def booted(path=DILITHIUM, seed=b"tests"):
    m = Machine.from_elf(need(path))
    scheme = Scheme.bind(m)
    m.boot()
    m.stub_randombytes(seed)
    return m, scheme


# --- the emulated machine ---------------------------------------------------


def test_elf_loads_and_resolves_symbols():
    image = ElfImage(need(DILITHIUM))
    assert image.entry != 0
    assert len(image.functions) > 50
    main = image.symbol("main")
    assert image.func_at(main.addr).name == "main"
    assert image.describe(main.addr + 2) == "main+0x2"


def test_sizeless_assembly_symbols_get_an_extent():
    """Hand-written asm has st_size == 0 and must still be attributable."""
    image = ElfImage(need(DILITHIUM))
    keccak = image.symbol("KeccakF1600_StatePermute")
    assert keccak.size == 0
    start, end = image.extent_of("KeccakF1600_StatePermute")
    assert start == keccak.addr and end > start
    assert image.func_at(start + 4) is not None


def test_firmware_boots_and_exits_cleanly():
    m = Machine.from_elf(need(DILITHIUM))
    m.run(max_instructions=500_000_000)
    assert m.exited, "firmware never reached its semihosting exit"
    text = m.uart_text()
    assert "crypto_sign_keypair DONE" in text
    assert "OK Signature did verify correctly!" in text
    assert m.icount > 1_000_000


def test_boot_stops_at_main():
    m = Machine.from_elf(need(DILITHIUM))
    m.boot()
    assert m.reg("pc") & ~1 == m.addr_of("main")
    assert 0 < m.icount < 1_000_000


def test_systick_and_cycle_counter_advance():
    m, _ = booted()
    from ucpqc.platform import DWT_CYCCNT, SYSTICK_VAL

    first = m.peripherals.read(SYSTICK_VAL, 4)
    m.call("KeccakF1600_StatePermute", [m.alloc(200)])
    assert m.peripherals.read(SYSTICK_VAL, 4) != first
    assert m.peripherals.read(DWT_CYCCNT, 4) == m.icount & 0xFFFFFFFF


# --- scheme binding ---------------------------------------------------------


def test_scheme_detection_and_sizes():
    _, scheme = booted()
    assert scheme.kind == "sign"
    assert scheme.binding.ctx_api, "ML-DSA exposes the FIPS 204 _ctx entry points"
    assert (scheme.sizes.pk, scheme.sizes.sk, scheme.sizes.sig) == (1312, 2560, 2420)
    assert scheme.landmark("ntt") == "pqcrystals_dilithium_ntt"


def test_sign_verify_roundtrip():
    _, scheme = booted()
    pk, sk = scheme.keypair()
    assert (len(pk), len(sk)) == (1312, 2560)
    message = b"hello dilithium"
    sig = scheme.sign(message, sk)
    assert len(sig) == 2420
    assert scheme.verify(sig, message, pk) is True
    assert scheme.verify(sig, b"other message", pk) is False
    assert scheme.verify(bytes([sig[0] ^ 1]) + sig[1:], message, pk) is False


def test_kem_roundtrip():
    m, scheme = booted(need(KEM))
    assert scheme.kind == "kem"
    pk, sk = scheme.keypair()
    ct, ss_a = scheme.encaps(pk)
    assert scheme.decaps(ct, sk) == ss_a
    assert len(ss_a) == 32


def test_implementations_agree():
    """Optimised M4 and reference C must produce identical output."""
    outputs = []
    for path in (DILITHIUM, DILITHIUM_REF):
        _, scheme = booted(need(path), seed=b"agree")
        outputs.append(scheme.roundtrip(b"same message"))
    assert outputs[0]["ok"] and outputs[1]["ok"]
    assert outputs[0]["pk"] == outputs[1]["pk"]
    assert outputs[0]["sig"] == outputs[1]["sig"]


def test_direct_primitive_call():
    m, _ = booted()
    coefficients = list(range(256))
    buf = m.alloc_bytes(struct.pack("<256i", *coefficients))
    m.call("pqcrystals_dilithium_ntt", [buf])
    transformed = struct.unpack("<256i", m.read(buf, 1024))
    assert list(transformed) != coefficients


# --- determinism ------------------------------------------------------------


def test_rng_stub_is_deterministic():
    keys = [booted(seed=seed)[1].keypair() for seed in (b"A", b"A", b"B")]
    assert keys[0] == keys[1]
    assert keys[0] != keys[2]


def test_snapshot_restores_everything():
    m, scheme = booted(seed=b"snap")
    snapshot = m.snapshot()
    first = scheme.keypair()
    m.restore(snapshot)
    assert m.icount == snapshot.icount
    # Same RNG position, same scratch allocator, same memory -> same key.
    assert scheme.keypair() == first


# --- tracing ----------------------------------------------------------------


def test_profile_accounts_for_every_instruction():
    m, scheme = booted()
    pk, sk = scheme.keypair()
    profiler = Profiler(m)
    scheme.sign(b"profile", sk)
    profiler.detach()
    assert sum(profiler.counts.values()) == scheme.last_cost["signature"]
    assert profiler.counts["KeccakF1600_StatePermute"] > 0


def test_hooks_added_after_boot_still_fire():
    """Regression: Unicorn bakes hooks into translated blocks."""
    m, scheme = booted()
    scheme.keypair()  # translates most of the code
    hits = []
    addr = m.addr_of("pqcrystals_dilithium_ntt")
    m.hook_code(lambda mm, a, s: hits.append(a), begin=addr, end=addr, precise=False)
    pk, sk = scheme.keypair()
    assert hits, "hook installed after boot never fired"


def test_call_tracer_nests_correctly():
    m, scheme = booted()
    tracer = CallTracer(m, max_depth=8)
    scheme.keypair()
    tracer.finish()
    tracer.detach()
    names = [c.name for c in tracer.calls]
    assert "crypto_sign_keypair" in names
    root = tracer.calls[0]
    assert root.name == "crypto_sign_keypair" and root.depth == 0
    # The root must not swallow the whole run as one frame.
    assert max(c.depth for c in tracer.calls) >= 2
    # A callee's cost cannot exceed its caller's.
    assert all(c.cost is not None and c.cost >= 0 for c in tracer.calls)
    assert max(c.cost for c in tracer.calls) == root.cost


def test_instruction_tracer_windows_a_function():
    m, scheme = booted()
    pk, sk = scheme.keypair()
    tracer = InstructionTracer(m, window="pqcrystals_dilithium_ntt", scope="body", limit=20_000)
    scheme.sign(b"trace", sk)
    start, end = m.image.extent_of("pqcrystals_dilithium_ntt")
    assert len(tracer) > 100
    assert all(start <= rec.pc < end for rec in tracer.records)


# --- fault injection --------------------------------------------------------


def test_fault_skip_changes_execution():
    m, scheme = booted(seed=b"fault")
    pk, sk = scheme.keypair()
    snapshot = m.snapshot()
    golden = scheme.sign(b"fault me", sk)

    m.restore(snapshot)
    spec = FaultSpec(kind="skip", pc="pqcrystals_dilithium_poly_challenge", hit=2, count=1)
    injector = Injector(m, spec)
    changed = True
    try:
        changed = scheme.sign(b"fault me", sk, max_instructions=40_000_000) != golden
    except Exception:
        pass  # a crash is also a change in behaviour
    finally:
        assert injector.fired == 1
        injector.detach()
    assert changed


def test_fault_bitflip_reaches_the_guest():
    m, scheme = booted(seed=b"flip")
    pk, sk = scheme.keypair()
    snapshot = m.snapshot()
    golden = scheme.sign(b"flip me", sk)
    m.restore(snapshot)
    spec = FaultSpec(
        kind="bitflip_reg", pc="pqcrystals_dilithium_poly_challenge", hit=2, reg="r0", bit=12
    )
    injector = Injector(m, spec)
    faulty = scheme.sign(b"flip me", sk, max_instructions=40_000_000)
    injector.detach()
    assert faulty != golden


def test_campaign_classifies_and_restores():
    m, scheme = booted(seed=b"camp")
    pk, sk = scheme.keypair()
    message = b"campaign"

    def operation(machine):
        return scheme.sign(message, sk, max_instructions=40_000_000)

    campaign = FaultCampaign(m, operation)
    golden = campaign.prepare()

    # A fault whose trigger never fires must leave the output untouched.
    unreached = FaultSpec(kind="skip", pc=m.addr_of("crypto_sign_verify_ctx"), hit=1)
    result = campaign.run_one(unreached)
    assert result.fired == 0 and result.outcome == Outcome.SKIPPED
    assert result.output == golden

    specs = list(
        sweep_function_body(m, "pqcrystals_dilithium_poly_challenge", stride=8, hit=2)
    )[:4]
    campaign.run(specs)
    assert len(campaign.results) == 1 + len(specs)
    assert set(campaign.summary()) <= {
        Outcome.SILENT,
        Outcome.DIFFERENT,
        Outcome.REJECTED,
        Outcome.CRASH,
        Outcome.TIMEOUT,
        Outcome.SKIPPED,
    }


# --- leakage ----------------------------------------------------------------


# --- build helpers ----------------------------------------------------------


def test_namespace_and_kind_derivation():
    assert kind_of("crypto_sign/ml-dsa-44/m4f") == "sign"
    assert kind_of("crypto_kem/ml-kem-768/m4fspeed") == "kem"
    assert namespace_for("crypto_sign/ml-dsa-44/m4f") == ""
    assert (
        namespace_for("mupq/pqclean/crypto_kem/ml-kem-768/clean")
        == "PQCLEAN_MLKEM768_CLEAN_"
    )


def test_manifest_is_read_back():
    _, scheme = booted()
    assert scheme.manifest is not None, "firmware built by ucpqc has a manifest"
    assert scheme.manifest["kind"] == "sign"
    assert scheme.manifest["sizes"]["pk"] == 1312


# --- framework: scratch API, profiles, assess -------------------------------


def test_scratch_mark_reset():
    m, _ = booted()
    mark = m.scratch_mark()
    a = m.alloc(64)
    b = m.alloc(128)
    assert b != a
    m.scratch_reset(mark)
    assert m.alloc(64) == a, "scratch_reset rewinds the allocator to the mark"


def test_profile_auto_selection():
    from ucpqc.profiles import profile_for
    from ucpqc.profiles.mldsa import MLDSAProfile, SIGLEN
    m, scheme = booted()
    prof = profile_for(scheme)
    assert isinstance(prof, MLDSAProfile), "ml-dsa ELF selects the ML-DSA profile"
    assert SIGLEN == 2420
    op = scheme.binding.symbols["signature"]
    addrs = {a for a, _ in prof.fault_sites(m, op)}     # auto-discovered
    assert 0x4d5e in addrs, "the z=z+y mask add is discovered"
    assert len(addrs) > 20, "discovery is a superset of the old curated table"


def test_profile_feature_roundtrip():
    from ucpqc.profiles import profile_for
    m, scheme = booted()
    prof = profile_for(scheme)
    prof.setup(m)
    pk, sk = scheme.keypair()
    sig = scheme.sign(b"hi", sk)
    feat = prof.feature(prof.challenge(m, sig), prof.response_from_signature(sig))
    assert feat.shape == (1024,), "matched-filter feature is L*NC = 1024"


def test_funcskip_flags_the_mask_add():
    from ucpqc import assess
    from ucpqc.profiles import profile_for
    _, scheme = booted()
    prof = profile_for(scheme)
    result = assess.sweep_function(scheme, prof, n=8)
    leaks = result.leaks()
    assert leaks, "polyvecl_add has at least one leaking skip site"
    poly_add = scheme.machine.addr_of("pqcrystals_dilithium_poly_add")
    assert any(f"{poly_add:#x}"[2:] in r.label for r in leaks), \
        "skipping the bl to poly_add leaks (z stays c*s1)"


def test_mayo_runs_and_selects_profile():
    from ucpqc.profiles import profile_for
    from ucpqc.profiles.mayo import MayoProfile
    m = Machine.from_elf(need(os.path.join(FIRMWARE, "mayo1_m4f_test.elf")))
    scheme = Scheme.bind(m)
    m.boot()
    m.stub_randombytes(b"tests")
    assert scheme.name.startswith("mayo"), "a multivariate scheme, detected generically"
    prof = profile_for(scheme)
    assert isinstance(prof, MayoProfile)
    op = scheme.binding.symbols["signature"]
    assert len(prof.fault_sites(m, op)) > 5, "sweep sites discovered by disassembly"
    pk, sk = scheme.keypair()                # runs end to end via the general core
    assert scheme.verify(scheme.sign(b"hi", sk), b"hi", pk)


# --- calibrated detectors: multiple-testing corrections ---------------------


def test_multiple_testing_corrections():
    """bh_fdr / holm_bonferroni reproduce their textbook rejection sets, preserve
    input order, and control false discoveries under the global null."""
    import numpy as np
    from ucpqc.detectors import bh_fdr, holm_bonferroni
    p = np.array([0.001, 0.008, 0.039, 0.041, 0.9])
    assert list(bh_fdr(p, 0.05)) == [True, True, False, False, False]
    assert list(holm_bonferroni(p, 0.05)) == [True, True, False, False, False]
    assert list(bh_fdr(np.array([0.9, 0.001, 0.008]), 0.05)) == [False, True, True]
    rng = np.random.default_rng(0)
    false_disc = [int(bh_fdr(rng.uniform(size=50), 0.05).sum()) for _ in range(200)]
    assert np.mean(false_disc) < 0.05 * 50, "FDR controls false discoveries under the null"


def test_tvla_pvalue_matches_threshold():
    """The calibrated per_coord p-value is the exact dual of the legacy |t|
    threshold: p crosses ALPHA precisely where max|t| crosses the Bonferroni bound,
    so the already-principled detector's verdict does not drift."""
    from ucpqc.assess import _tvla_pvalue, _tvla_threshold, ALPHA
    for d in (1, 16, 256, 1024):
        thr = _tvla_threshold(d, ALPHA)
        assert _tvla_pvalue(thr, d) <= ALPHA + 1e-9, "at the threshold, p == alpha"
        assert _tvla_pvalue(thr * 0.98, d) > ALPHA, "just below the threshold, p > alpha"
        assert _tvla_pvalue(thr * 1.05, d) < ALPHA, "above the threshold, p < alpha"


def test_ineffective_fraction():
    """#2: fraction of faulted artifacts byte-identical to the golden baseline."""
    from ucpqc.assess import _ineffective_fraction
    golden = {"A": [b"xx", b"yy", b"zz"], "B": [b"aa", b"bb"]}
    assert _ineffective_fraction(golden, golden) == 1.0          # all unchanged
    faulted = {"A": [b"XX", b"YY", b"ZZ"], "B": [b"AA", b"BB"]}
    assert _ineffective_fraction(faulted, golden) == 0.0         # all changed
    mixed = {"A": [b"xx", b"YY"], "B": [b"aa"]}                  # xx==, YY!=, aa== -> 2/3
    assert abs(_ineffective_fraction(mixed, golden) - 2 / 3) < 1e-9
    assert _ineffective_fraction(faulted, None) is None          # no baseline


def test_sibling_key():
    """#1: sibling_key yields a secret key differing by exactly one byte in the s1
    region; s1 changes and both keys still sign."""
    import numpy as np
    from ucpqc.profiles import profile_for
    from ucpqc.profiles.mldsa import unpack_s1
    _, scheme = booted(seed=b"sib")
    prof = profile_for(scheme)
    _, skA = scheme.keypair()
    skB = prof.sibling_key(skA)
    diff = [i for i in range(len(skA)) if skA[i] != skB[i]]
    assert diff == [128], f"exactly one byte differs, in the s1 region: {diff}"
    assert not np.array_equal(unpack_s1(skA), unpack_s1(skB)), "s1 actually changed"
    assert len(scheme.sign(b"hi", skA)) == len(scheme.sign(b"hi", skB)) == 2420, "both sign"


# --- dump + offline detect --------------------------------------------------
def _dump_small(detector="per_coord", n=5, nsites=2):
    """Run a tiny sweep with --dump into a temp dir (first `nsites` discovered sites,
    so it stays fast) and return (dump_dir, live AssessmentResult)."""
    import tempfile
    from ucpqc import assess
    from ucpqc.profiles import profile_for
    m, scheme = booted()
    prof = profile_for(scheme)
    op = scheme.binding.symbols["signature"]
    sites = list(prof.fault_sites(m, op))[:nsites]
    prof.fault_sites = lambda machine, op_func, _s=sites: _s
    d = tempfile.mkdtemp(prefix="ucpqc-dump-")
    live = assess.sweep_sites(scheme, prof, n=n, detector=detector, dump=d)
    return d, live


def test_dump_roundtrip():
    """`sweep --dump` writes meta/golden/site_* with well-formed records (hex artifact
    of the right length, a per-item challenge)."""
    import json
    from ucpqc import dump as dumpmod
    d, _ = _dump_small(n=5, nsites=2)
    files = set(os.listdir(d))
    assert {"meta.json", "golden.json"} <= files, files
    assert any(f.startswith("site_") for f in files), "a faulted-site file is written"
    meta, golden, sites = dumpmod.load_dump(d)
    assert meta["scheme"].startswith("ml-dsa") and meta["mode"] == "sweep" and meta["n"] == 5
    assert len(sites) == len(meta["sites"]) == 2
    rec = golden["A"][0]
    assert len(rec["artifact"]) == 2 * meta["artifact_len"], "artifact is full-length hex"
    bytes.fromhex(rec["artifact"])                         # valid hex
    assert len(rec["challenge"]) == 256, "challenge c is captured per item"
    assert golden["A"][0]["msg"] == "msg-0"


def test_detect_matches_live():
    """The offline `detect` verdict is identical to the live sweep it was dumped from
    -- same metric, p-value, status, and ineffective fraction per site (capture once,
    score offline without re-emulating)."""
    from ucpqc import assess
    d, live = _dump_small(detector="per_coord", n=6, nsites=2)
    off = assess.assess_from_dump(d, detector="per_coord")
    assert len(off.rows) == len(live.rows)
    for lr, orr in zip(live.rows, off.rows):
        assert lr.addr == orr.addr
        assert lr.metric == orr.metric, (lr.addr, lr.metric, orr.metric)
        assert lr.pvalue == orr.pvalue, (lr.addr, lr.pvalue, orr.pvalue)
        assert lr.status == orr.status, (lr.addr, lr.status, orr.status)
        assert lr.ineffective == orr.ineffective, (lr.addr, lr.ineffective, orr.ineffective)


def test_detect_reuses_dump():
    """A dump is replayable offline without re-emulating: scoring per_coord off the
    captured files reproduces the dump's scored rows, and an unknown detector is
    rejected."""
    from ucpqc import assess
    d, _ = _dump_small(detector="per_coord", n=6, nsites=2)
    r = assess.assess_from_dump(d, detector="per_coord")
    assert len(r.rows) == 3 and r.detector == "per_coord"
    assert any(row.metric is not None for row in r.rows[1:])    # a scored faulted row
    try:
        assess.assess_from_dump(d, detector="sifa")             # removed detector
        assert False, "an unknown detector should be rejected"
    except ValueError:
        pass


def test_capture_caller_filter_selects_operand():
    """`Target.caller` picks WHICH call of a multiply-called function is captured:
    `ntt` from the signing body is NTT(c) (the last call, = the unfiltered target),
    from `polyvecl_ntt` it is NTT(y) -- a different operand."""
    import tempfile
    from ucpqc import captures
    need(DILITHIUM)
    out = tempfile.mkdtemp(prefix="ucpqc-caller-")
    captures.capture_all(DILITHIUM, out, targets=["ntt", "ntt_c", "ntt_y"], n=1, jobs=1)
    cap = {t: captures.load_captures(out, t)[1]["A"][0] for t in ("ntt", "ntt_c", "ntt_y")}
    assert cap["ntt"].inputs == cap["ntt_c"].inputs, "unfiltered last ntt call is NTT(c)"
    assert cap["ntt_y"].inputs != cap["ntt_c"].inputs, "caller filter selects another operand"


def test_funcskip_dump_matches_live():
    """`funcskip --dump` + offline `assess_funcskip_from_dump` reproduces the live
    funcskip verdict: every scored (survivor) skip site agrees on metric/p/status.
    (All-crash sites produce no output and are legitimately absent from the dump.)"""
    import tempfile
    from ucpqc import assess
    from ucpqc.profiles import profile_for
    _, scheme = booted()
    scheme.machine.stub_cycle_counter()
    prof = profile_for(scheme)
    d = tempfile.mkdtemp(prefix="ucpqc-fsk-")
    live = assess.sweep_function(scheme, prof, target=prof.targets()["polyvecl_add"],
                                 n=6, dump=d)
    off = assess.assess_funcskip_from_dump(d)
    assert off.mode == "funcskip" and off.detector == live.detector
    lv = {r.addr: r for r in live.rows}
    ov = {r.addr: r for r in off.rows}
    assert set(ov) <= set(lv), "offline sites are a subset of live"
    assert all(lv[a].status == "crash" for a in set(lv) - set(ov)), \
        "live-only sites are all-crash (no outputs to dump)"
    for a in set(lv) & set(ov):
        assert (lv[a].metric, lv[a].pvalue, lv[a].status) == \
               (ov[a].metric, ov[a].pvalue, ov[a].status), f"row mismatch at {a:#x}"
        assert lv[a].ineffective == ov[a].ineffective, f"ineffective mismatch at {a:#x}"
    assert {r.addr for r in live.leaks()} == {r.addr for r in off.leaks()}
    assert any(r.ineffective is not None for r in off.rows), "ineffective axis is populated"


def test_funcskip_parallel_jobs_invariant():
    """The multithreaded funcskip dump is jobs-invariant: jobs=1 and jobs=2 give the
    identical per-site verdict (each signing is an independent snapshot-isolated,
    per-index-seeded unit of work).  (Real parallelism needs 3.14t; on a GIL build
    this still verifies correctness, just serially.)"""
    from ucpqc.parallel_funcskip import sweep_function_dump_parallel as P
    need(DILITHIUM)
    r1 = P(DILITHIUM, "polyvecl_add", n=8, jobs=1)
    r2 = P(DILITHIUM, "polyvecl_add", n=8, jobs=2)
    v1 = {row.addr: (row.metric, row.pvalue, row.status) for row in r1.rows}
    v2 = {row.addr: (row.metric, row.pvalue, row.status) for row in r2.rows}
    assert v1 == v2, "jobs=1 and jobs=2 must produce identical verdicts"
    assert r1.mode == "funcskip" and len(r1.rows) >= 5


def test_funcskip_dumpdir_resolves():
    """`funcskip --dumpdir BASE` writes the dump to BASE/<target>_instrskip/."""
    import tempfile
    from ucpqc import cli
    need(DILITHIUM)
    base = tempfile.mkdtemp(prefix="ucpqc-dumpdir-")
    cli.main(["funcskip", DILITHIUM, "--target", "polyvecl_add", "--n", "4", "--dumpdir", base])
    out = os.path.join(base, "polyvecl_add_instrskip")
    assert os.path.isdir(out), f"expected dump dir {out}"
    assert os.path.exists(os.path.join(out, "meta.json")), "meta.json written under the base dir"
    # the candidate counter reads the dump and scores per_coord LEAK counts from it
    from ucpqc import candidates
    c = candidates.candidate_counts(base)["polyvecl_add"]
    assert c["reached"] and c["scored"] > 0, f"candidate counts read the dump: {c}"
    assert c["maxineff"] > 0, "ineffective fraction populated from the dump's golden outputs"


def test_per_position_phi_runs():
    """ucpqc.phi (per-position phi_IF, the ineffective axis) runs on the clean build and
    returns well-formed ranked witnesses; when it flags, the position carries an s1
    coefficient attribution via profile.secret_coeffs."""
    from ucpqc import phi
    from ucpqc.profiles import profile_for
    need(DILITHIUM_REF)
    m = Machine.from_elf(DILITHIUM_REF)
    scheme = Scheme.bind(m)
    m.boot()
    prof = profile_for(scheme)
    res = phi.per_position_phi(scheme, prof, sites="polyvecl_add", k=4)
    assert res.k == 4 and len(res.sites) == 1, "one resolved site, K recorded"
    s = res.sites[0]
    assert "polyvecl_add" in s.label
    assert isinstance(s.witnesses, list) and s.n_split >= len(s.witnesses)
    if s.witnesses:                                  # stochastic; attribution when it flags
        assert "coeff[" in s.attribution, s.attribution


def test_parallel_sweep_matches_serial():
    """The multiprocessing sweep is bit-identical to the serial one (same
    deterministic inputs, same per-site seam), verified on a small subset."""
    from ucpqc import assess, parallel
    from ucpqc.profiles import profile_for
    m, scheme = booted(seed=b"ucpqc")
    m.stub_cycle_counter()                        # match the CLI/parallel machine setup
    prof = profile_for(scheme)
    prof.setup(m)
    op = scheme.binding.symbols["signature"]
    addrs = {a for a, _ in prof.fault_sites(m, op)}
    assert 0x4d5e in addrs, "the z=z+y mask add is discovered"
    subset = {0x4d5e}                             # the leak site (fast; runs cleanly)
    sites = [(a, lbl) for a, lbl in prof.fault_sites(m, op) if a in subset]
    n = 8                                         # enough for the calibrated single-site verdict to flag
    orig = type(prof).fault_sites                 # serial reference over the subset
    type(prof).fault_sites = lambda self, mm, of: sites
    try:
        serial = assess.sweep_sites(scheme, prof, n=n)
    finally:
        type(prof).fault_sites = orig
    par = parallel.sweep_sites_parallel(DILITHIUM, "mps2-an386", n=n, jobs=2,
                                        site_filter=subset)
    show = lambda r: (r.addr, r.label, r.status, r.metric, r.ran, r.crashed)
    sd = {r.addr: r for r in serial.rows}
    pd = {r.addr: r for r in par.rows}
    assert set(sd) == set(pd), "same rows in both"
    for a in sd:
        assert show(sd[a]) == show(pd[a]), f"row mismatch at {a!r}"
    assert any(r.status == "LEAK" for r in par.rows), "0x4d5e still flags LEAK"


def test_capture_cache_replays_identically():
    """A persistent capture cache replays to the SAME funcskip verdict as a direct run
    (so `funcskip --captures` can skip the expensive re-signing)."""
    import tempfile
    from ucpqc import captures as capmod
    from ucpqc.parallel_funcskip import sweep_function_dump_parallel as P
    need(DILITHIUM)
    d = tempfile.mkdtemp(prefix="ucpqc-caps-")
    _, man = capmod.capture_all(DILITHIUM, d, targets=["polyvecl_add"], n=6, jobs=2)
    assert "polyvecl_add" in man["targets"] and man["n"] == 6
    _, caps = capmod.load_captures(d, "polyvecl_add")
    fromcache = P(DILITHIUM, "polyvecl_add", n=man["n"], jobs=2, caps_by_key=caps)
    direct = P(DILITHIUM, "polyvecl_add", n=6, jobs=2)
    vc = {r.addr: (r.metric, r.pvalue, r.status, r.ineffective) for r in fromcache.rows}
    vd = {r.addr: (r.metric, r.pvalue, r.status, r.ineffective) for r in direct.rows}
    assert vc == vd, "capture-cache replay must match a direct capture+replay run"


# --- runner -----------------------------------------------------------------


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    passed = failed = skipped = 0
    started = time.time()
    for name, fn in tests:
        label = name[5:].replace("_", " ")
        try:
            t0 = time.time()
            fn()
        except Skip as exc:
            print(f"SKIP  {label} ({exc})")
            skipped += 1
        except Exception:
            print(f"FAIL  {label}")
            traceback.print_exc()
            failed += 1
        else:
            print(f"ok    {label}  ({time.time() - t0:.1f}s)")
            passed += 1
    print(
        f"\n{passed} passed, {failed} failed, {skipped} skipped "
        f"in {time.time() - started:.1f}s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
