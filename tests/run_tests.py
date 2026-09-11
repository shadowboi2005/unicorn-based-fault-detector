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
    LeakageTracer,
    Machine,
    Outcome,
    Profiler,
    Scheme,
    hamming_distance,
    hamming_weight,
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


def test_hamming_helpers():
    assert hamming_weight(0) == 0
    assert hamming_weight(0xFFFFFFFF) == 32
    assert hamming_weight(0x1FF, width=8) == 8
    assert hamming_distance(0xF0, 0x0F) == 8


def test_leakage_trace_is_aligned_across_calls():
    m, _ = booted()
    buf = m.alloc(1024)
    tracer = LeakageTracer(m, model="hd_reg", window="pqcrystals_dilithium_ntt", scope="body")
    lengths = []
    mark = 0
    for i in range(3):
        m.write(buf, struct.pack("<256i", *([i * 7 + 1] * 256)))
        m.call("pqcrystals_dilithium_ntt", [buf])
        lengths.append(len(tracer.samples) - mark)
        mark = len(tracer.samples)
    assert len(set(lengths)) == 1, f"traces of unequal length: {lengths}"
    assert all(0 <= s <= 13 * 32 for s in tracer.samples)


def test_memory_leakage_model():
    m, _ = booted()
    buf = m.alloc(1024)
    tracer = LeakageTracer(m, model="hw_mem", mem_range=(buf, buf + 1023))
    m.write(buf, struct.pack("<256i", *range(256)))
    m.call("pqcrystals_dilithium_ntt", [buf])
    assert len(tracer) > 100


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
    _, scheme = booted()
    prof = profile_for(scheme)
    assert isinstance(prof, MLDSAProfile), "ml-dsa ELF selects the ML-DSA profile"
    assert SIGLEN == 2420
    assert len(prof.fault_sites(None)) == 20
    assert prof.detector_for(prof.default_target()) == "two_key"


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
    assert len(prof.fault_sites(m)) > 5, "sweep sites discovered by disassembly"
    pk, sk = scheme.keypair()                # runs end to end via the general core
    assert scheme.verify(scheme.sign(b"hi", sk), b"hi", pk)


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
