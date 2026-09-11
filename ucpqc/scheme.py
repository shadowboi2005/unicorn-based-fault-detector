"""Binding from an emulated firmware to a PQC scheme's API.

This is the only scheme-aware layer in the framework.  Everything below it
(machine, tracing, faults, leakage) works on instructions and memory and does
not care which algorithm is running.

Three things are needed to drive a scheme: the entry-point symbols, the buffer
sizes, and whether it is a signature or a KEM.  All three are discovered
automatically -- symbols by pattern-matching the ELF symbol table, sizes from
the manifest the firmware build writes next to the ELF, falling back to a
built-in table and finally to over-allocation with size probing.
"""

import json
import os
from dataclasses import dataclass, field

SIGN = "sign"
KEM = "kem"

# Entry points, in priority order.  The `*_` alternatives cover PQClean-style
# namespaced builds (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair) and the
# pq-crystals reference API (pqcrystals_dilithium2_ref_keypair).
SIGN_SYMBOLS = {
    "keypair": ("crypto_sign_keypair", "*_crypto_sign_keypair", "pqcrystals_*_keypair"),
    "signature": (
        "crypto_sign_signature_ctx",
        "crypto_sign_signature",
        "*_crypto_sign_signature_ctx",
        "*_crypto_sign_signature",
        "pqcrystals_*_signature_ctx",
        "pqcrystals_*_signature",
    ),
    "verify": (
        "crypto_sign_verify_ctx",
        "crypto_sign_verify",
        "*_crypto_sign_verify_ctx",
        "*_crypto_sign_verify",
        "pqcrystals_*_verify_ctx",
        "pqcrystals_*_verify",
    ),
    "sign": ("crypto_sign_ctx", "crypto_sign", "*_crypto_sign_ctx"),
    "open": ("crypto_sign_open_ctx", "crypto_sign_open", "*_crypto_sign_open_ctx"),
}

KEM_SYMBOLS = {
    "keypair": ("crypto_kem_keypair", "*_crypto_kem_keypair", "pqcrystals_*_keypair"),
    "enc": ("crypto_kem_enc", "*_crypto_kem_enc", "pqcrystals_*_enc"),
    "dec": ("crypto_kem_dec", "*_crypto_kem_dec", "pqcrystals_*_dec"),
}

RNG_SYMBOLS = ("randombytes", "PQCLEAN_randombytes")

# Fallback sizes for schemes the manifest does not cover, keyed by a
# lowercase substring of the firmware name.  Sizes are (pk, sk, sig) for
# signatures and (pk, sk, ct, ss) for KEMs.
KNOWN_SIZES = {
    # ML-DSA / Dilithium (FIPS 204 and the round-3 parameter sets)
    "ml-dsa-44": dict(kind=SIGN, pk=1312, sk=2560, sig=2420),
    "ml-dsa-65": dict(kind=SIGN, pk=1952, sk=4032, sig=3309),
    "ml-dsa-87": dict(kind=SIGN, pk=2592, sk=4896, sig=4627),
    "dilithium2": dict(kind=SIGN, pk=1312, sk=2560, sig=2420),
    "dilithium3": dict(kind=SIGN, pk=1952, sk=4032, sig=3293),
    "dilithium5": dict(kind=SIGN, pk=2592, sk=4864, sig=4595),
    # ML-KEM / Kyber
    "ml-kem-512": dict(kind=KEM, pk=800, sk=1632, ct=768, ss=32),
    "ml-kem-768": dict(kind=KEM, pk=1184, sk=2400, ct=1088, ss=32),
    "ml-kem-1024": dict(kind=KEM, pk=1568, sk=3168, ct=1568, ss=32),
    "kyber512": dict(kind=KEM, pk=800, sk=1632, ct=768, ss=32),
    "kyber768": dict(kind=KEM, pk=1184, sk=2400, ct=1088, ss=32),
    "kyber1024": dict(kind=KEM, pk=1568, sk=3168, ct=1568, ss=32),
    # A few other pqm4 signature schemes
    "falcon-512": dict(kind=SIGN, pk=897, sk=1281, sig=752),
    "falcon-1024": dict(kind=SIGN, pk=1793, sk=2305, sig=1462),
    "sphincs-sha2-128f": dict(kind=SIGN, pk=32, sk=64, sig=17088),
    "sphincs-sha2-128s": dict(kind=SIGN, pk=32, sk=64, sig=7856),
}

# Interesting functions per scheme family.  Purely a convenience for the CLI
# and the examples ("trace the NTT") -- nothing depends on these being right.
LANDMARKS = {
    "dilithium": {
        "ntt": ("pqcrystals_dilithium_ntt", "ntt", "*_ntt"),
        "invntt": ("pqcrystals_dilithium_invntt_tomont", "invntt_tomont"),
        "challenge": ("pqcrystals_dilithium_poly_challenge", "poly_challenge"),
        "decompose": ("pqcrystals_dilithium_poly_decompose", "poly_decompose"),
        "keccak": ("KeccakF1600_StatePermute", "keccak_f1600_state_permute"),
    },
    "kyber": {
        "ntt": ("ntt", "*_ntt"),
        "invntt": ("invntt", "*_invntt"),
        "keccak": ("KeccakF1600_StatePermute",),
    },
}

# Sentinel written into output buffers before a call so that probe_sizes can
# tell how much of them the implementation actually filled in.
FILL = b"\xa5"


class SchemeError(RuntimeError):
    pass


@dataclass
class Sizes:
    pk: int = None
    sk: int = None
    sig: int = None
    ct: int = None
    ss: int = None
    probed: bool = False


@dataclass
class Binding:
    """Which guest functions implement the scheme's API."""

    kind: str
    symbols: dict
    ctx_api: bool = False  # FIPS 204 style entry points taking (ctx, ctxlen)
    rng: str = None
    extras: dict = field(default_factory=dict)


def _first(image, patterns):
    for pattern in patterns:
        if "*" in pattern:
            found = image.find(pattern, kind="STT_FUNC")
            if found:
                return found[0].name
        else:
            try:
                return image.symbol(pattern).name
            except KeyError:
                continue
    return None


def detect(image):
    """Work out what API the firmware exposes, from its symbol table alone."""
    sign = {k: _first(image, pats) for k, pats in SIGN_SYMBOLS.items()}
    kem = {k: _first(image, pats) for k, pats in KEM_SYMBOLS.items()}

    if sign["keypair"] and sign["signature"]:
        ctx_api = sign["signature"].endswith("_ctx")
        binding = Binding(SIGN, {k: v for k, v in sign.items() if v}, ctx_api)
    elif kem["keypair"] and kem["enc"]:
        binding = Binding(KEM, {k: v for k, v in kem.items() if v})
    else:
        raise SchemeError(
            "no crypto_sign_* or crypto_kem_* entry points in "
            f"{os.path.basename(image.path)}; pass symbols explicitly"
        )

    binding.rng = _first(image, RNG_SYMBOLS)
    for family, marks in LANDMARKS.items():
        if any(image.find(pat) for pats in marks.values() for pat in pats[:1]):
            binding.extras = {
                key: name
                for key, pats in marks.items()
                if (name := _first(image, pats))
            }
            break
    return binding


def load_manifest(elf_path):
    """Read the JSON manifest the firmware build writes next to the ELF."""
    candidates = [
        os.path.splitext(elf_path)[0] + ".json",
        os.path.join(os.path.dirname(elf_path), "manifest.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path) as fh:
                data = json.load(fh)
            return data.get(os.path.basename(elf_path), data)
    return None


def sizes_for(elf_path, manifest=None):
    """Buffer sizes from the manifest, else from the built-in table."""
    if manifest:
        s = manifest.get("sizes", {})
        if s:
            return Sizes(**{k: v for k, v in s.items() if k in Sizes.__annotations__})
    name = os.path.basename(elf_path).lower()
    for key, entry in KNOWN_SIZES.items():
        if key in name:
            return Sizes(**{k: v for k, v in entry.items() if k != "kind"})
    return Sizes()


class Scheme:
    """Drives a PQC implementation inside the emulator, one call at a time.

    ::

        m = Machine.from_elf("firmware/ml-dsa-44_m4f_test.elf")
        s = Scheme.bind(m)
        pk, sk = s.keypair()
        sig = s.sign(b"hello", sk)
        assert s.verify(sig, b"hello", pk)

    Each method is a single :meth:`Machine.call`, so any hook, tracer or fault
    installed on the machine applies to exactly that operation.
    """

    # Used when the sizes are unknown; implementations write far less.
    OVERALLOC = 64 * 1024

    def __init__(self, machine, binding=None, sizes=None, manifest=None):
        self.machine = machine
        self.manifest = manifest if manifest is not None else load_manifest(machine.image.path)
        self.binding = binding or detect(machine.image)
        self.sizes = sizes or sizes_for(machine.image.path, self.manifest)
        self.last_cost = {}

    @classmethod
    def bind(cls, machine, **kwargs):
        return cls(machine, **kwargs)

    # -- introspection ------------------------------------------------------

    @property
    def kind(self):
        return self.binding.kind

    @property
    def name(self):
        if self.manifest and self.manifest.get("algname"):
            return self.manifest["algname"]
        return os.path.basename(self.machine.image.path)

    def landmark(self, key):
        """Symbol name for a well-known internal function, or None."""
        return self.binding.extras.get(key)

    def describe(self):
        lines = [f"scheme:   {self.name} ({self.kind})"]
        for key, sym in sorted(self.binding.symbols.items()):
            lines.append(f"  {key:<10} -> {sym}")
        if self.binding.rng:
            lines.append(f"  {'rng':<10} -> {self.binding.rng}")
        for key, sym in sorted(self.binding.extras.items()):
            lines.append(f"  {key:<10} -> {sym}   (landmark)")
        sizes = {k: v for k, v in vars(self.sizes).items() if k != "probed" and v}
        lines.append(f"  sizes      {sizes or 'unknown (over-allocating)'}")
        return "\n".join(lines)

    # -- helpers ------------------------------------------------------------

    def _out_buffer(self, size):
        size = size or self.OVERALLOC
        return self.machine.alloc(size, fill=FILL), size

    def _used(self, addr, size):
        """How many bytes of an output buffer were actually written."""
        data = self.machine.read(addr, size)
        end = size
        while end > 0 and data[end - 1] == FILL[0]:
            end -= 1
        return end

    def _call(self, key, args, **kwargs):
        sym = self.binding.symbols.get(key)
        if sym is None:
            raise SchemeError(f"firmware has no {key!r} entry point")
        before = self.machine.icount
        ret = self.machine.call(sym, args, **kwargs)
        self.last_cost[key] = self.machine.icount - before
        return ret

    # -- signature API ------------------------------------------------------

    def keypair(self, **kwargs):
        """Generate a key pair; returns (pk, sk) as bytes."""
        pk_addr, pk_size = self._out_buffer(self.sizes.pk)
        sk_addr, sk_size = self._out_buffer(self.sizes.sk)
        ret = self._call("keypair", [pk_addr, sk_addr], **kwargs)
        if ret != 0:
            raise SchemeError(f"keypair() returned {ret}")
        pk_len = self.sizes.pk or self._used(pk_addr, pk_size)
        sk_len = self.sizes.sk or self._used(sk_addr, sk_size)
        return self.machine.read(pk_addr, pk_len), self.machine.read(sk_addr, sk_len)

    def sign(self, msg, sk, ctx=b"", **kwargs):
        """Detached signature over `msg`; returns the signature bytes."""
        m = self.machine
        sig_addr, sig_size = self._out_buffer(self.sizes.sig)
        siglen_addr = m.alloc(4)
        msg_addr = m.alloc_bytes(msg) if msg else 0
        args = [sig_addr, siglen_addr, msg_addr, len(msg)]
        if self.binding.ctx_api:
            args += [m.alloc_bytes(ctx) if ctx else 0, len(ctx)]
        elif ctx:
            raise SchemeError("this firmware's API takes no context string")
        args.append(m.alloc_bytes(sk))
        ret = self._call("signature", args, **kwargs)
        if ret != 0:
            raise SchemeError(f"signature() returned {ret}")
        siglen = m.read_u32(siglen_addr)
        if siglen > sig_size:
            raise SchemeError(f"signature length {siglen} exceeds buffer {sig_size}")
        return m.read(sig_addr, siglen)

    def verify(self, sig, msg, pk, ctx=b"", **kwargs):
        """Verify a detached signature; returns True/False."""
        m = self.machine
        args = [m.alloc_bytes(sig), len(sig), m.alloc_bytes(msg) if msg else 0, len(msg)]
        if self.binding.ctx_api:
            args += [m.alloc_bytes(ctx) if ctx else 0, len(ctx)]
        args.append(m.alloc_bytes(pk))
        return self._call("verify", args, **kwargs) == 0

    # -- KEM API ------------------------------------------------------------

    def encaps(self, pk, **kwargs):
        """KEM encapsulation; returns (ciphertext, shared secret)."""
        m = self.machine
        ct_addr, ct_size = self._out_buffer(self.sizes.ct)
        ss_addr, ss_size = self._out_buffer(self.sizes.ss or 32)
        ret = self._call("enc", [ct_addr, ss_addr, m.alloc_bytes(pk)], **kwargs)
        if ret != 0:
            raise SchemeError(f"enc() returned {ret}")
        ct_len = self.sizes.ct or self._used(ct_addr, ct_size)
        ss_len = self.sizes.ss or self._used(ss_addr, ss_size)
        return m.read(ct_addr, ct_len), m.read(ss_addr, ss_len)

    def decaps(self, ct, sk, **kwargs):
        """KEM decapsulation; returns the shared secret."""
        m = self.machine
        ss_addr, ss_size = self._out_buffer(self.sizes.ss or 32)
        ret = self._call("dec", [ss_addr, m.alloc_bytes(ct), m.alloc_bytes(sk)], **kwargs)
        if ret != 0:
            raise SchemeError(f"dec() returned {ret}")
        return m.read(ss_addr, self.sizes.ss or self._used(ss_addr, ss_size))

    # -- generic round trip -------------------------------------------------

    def roundtrip(self, msg=b"ucpqc", **kwargs):
        """One full operation cycle, whatever kind of scheme this is.

        Returns a dict with the artefacts, the per-operation instruction
        counts and whether the result verified/matched.
        """
        if self.kind == SIGN:
            pk, sk = self.keypair(**kwargs)
            sig = self.sign(msg, sk, **kwargs)
            ok = self.verify(sig, msg, pk, **kwargs)
            return {
                "kind": SIGN,
                "pk": pk,
                "sk": sk,
                "sig": sig,
                "ok": ok,
                "cost": dict(self.last_cost),
            }
        pk, sk = self.keypair(**kwargs)
        ct, ss_a = self.encaps(pk, **kwargs)
        ss_b = self.decaps(ct, sk, **kwargs)
        return {
            "kind": KEM,
            "pk": pk,
            "sk": sk,
            "ct": ct,
            "ss": ss_a,
            "ok": ss_a == ss_b,
            "cost": dict(self.last_cost),
        }

    def probe_sizes(self, **kwargs):
        """Discover the buffer sizes by running the scheme with fill patterns.

        Useful for firmware with no manifest and an unknown algorithm; the
        result is a best effort, since trailing zero bytes in a key are
        indistinguishable from untouched buffer.
        """
        saved = self.sizes
        self.sizes = Sizes(probed=True)
        try:
            result = self.roundtrip(**kwargs)
        finally:
            self.sizes = saved
        sizes = Sizes(pk=len(result["pk"]), sk=len(result["sk"]), probed=True)
        if result["kind"] == SIGN:
            sizes.sig = len(result["sig"])
        else:
            sizes.ct, sizes.ss = len(result["ct"]), len(result["ss"])
        return sizes
