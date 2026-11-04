"""ucpqc - a Unicorn-based fault-analysis platform for post-quantum crypto firmware.

Built for CRYSTALS-Dilithium (ML-DSA) on Cortex-M4, but the emulator, the
tracers, the fault injector and the analysis engine are scheme-agnostic: only
:mod:`ucpqc.scheme` knows what a signature or a KEM is, and it discovers that
from the ELF.

    from ucpqc import Machine, Scheme

    m = Machine.from_elf("firmware/ml-dsa-44_m4f_test.elf")
    s = Scheme.bind(m)
    pk, sk = s.keypair()
    sig = s.sign(b"hello", sk)
    assert s.verify(sig, b"hello", pk)
"""

from .elfimage import ElfImage, Symbol
from .faults import (
    BITFLIP_MEM,
    BITFLIP_REG,
    FLIP_FLAGS,
    SET_MEM,
    SET_REG,
    SKIP,
    FaultCampaign,
    FaultSpec,
    Injector,
    Outcome,
    TrialResult,
    sweep_function_body,
    sweep_hits,
    sweep_instructions,
    sweep_memory_bits,
    sweep_register_bits,
)
from .machine import EmulationError, Machine
from .platform import MPS2_AN386, PLATFORMS, Platform, Region
from .scheme import KEM, SIGN, Scheme, SchemeError, detect
from .tracing import CallTracer, InstructionTracer, MemoryTracer, Profiler, Trigger
from .replay import Capture, Recorder, Target, benchmark_backends, replay, skip_sweep
from . import assess, detectors, parallel, profiles, report

__version__ = "0.1.0"

__all__ = [
    "BITFLIP_MEM",
    "BITFLIP_REG",
    "CallTracer",
    "Capture",
    "ElfImage",
    "EmulationError",
    "Recorder",
    "Target",
    "benchmark_backends",
    "detectors",
    "replay",
    "skip_sweep",
    "FLIP_FLAGS",
    "FaultCampaign",
    "FaultSpec",
    "Injector",
    "InstructionTracer",
    "KEM",
    "MPS2_AN386",
    "Machine",
    "MemoryTracer",
    "Outcome",
    "PLATFORMS",
    "Platform",
    "Profiler",
    "Region",
    "SET_MEM",
    "SET_REG",
    "SIGN",
    "SKIP",
    "Scheme",
    "SchemeError",
    "Symbol",
    "TrialResult",
    "Trigger",
    "assess",
    "detect",
    "parallel",
    "profiles",
    "report",
    "sweep_function_body",
    "sweep_hits",
    "sweep_instructions",
    "sweep_memory_bits",
    "sweep_register_bits",
]
