"""Building firmware to emulate, and describing it in a manifest.

The emulator can run any bare-metal Cortex-M ELF, but the usual source is a
pqm4 tree: this module drives its Makefile for one scheme, stages the ELF into
`firmware/`, and writes a JSON manifest beside it with the buffer sizes the
scheme's headers declare.

Pointing the framework at a different PQC scheme is exactly this:

    python -m ucpqc build crypto_sign/ml-dsa-44/m4f     # Dilithium (default)
    python -m ucpqc build crypto_kem/ml-kem-768/m4fspeed
    python -m ucpqc build mupq/pqclean/crypto_sign/sphincs-sha2-128f-simple/clean

Nothing else in the framework needs to change.
"""

import json
import os
import re
import shutil
import subprocess
import sys

DEFAULT_PLATFORM = "mps2-an386"
DEFAULT_TESTS = ("test",)
CPP = os.environ.get("UCPQC_CPP", "arm-none-eabi-cpp")

# Values we try to read out of the scheme's headers.  Every one is optional;
# a scheme that does not define a field simply has it missing.
SIZE_MACROS = {
    "pk": "CRYPTO_PUBLICKEYBYTES",
    "sk": "CRYPTO_SECRETKEYBYTES",
    "sig": "CRYPTO_BYTES",  # signature length for sign, shared secret for KEM
    "ct": "CRYPTO_CIPHERTEXTBYTES",
}

PROBE = """
#include "api.h"
#define UCPQC_CAT_(a, b) a##b
#define UCPQC_CAT(a, b) UCPQC_CAT_(a, b)
%s
"""


def kind_of(scheme_path):
    """"sign" or "kem", from the scheme's location in the tree."""
    return "kem" if "crypto_kem" in scheme_path.replace("\\", "/") else "sign"


def impl_name(scheme_path):
    """pqm4's name for a scheme: the path with separators turned into _."""
    return scheme_path.strip("/").replace("/", "_")


def namespace_for(scheme_path):
    """The symbol prefix pqm4 compiles a scheme with (empty unless PQClean).

    Mirrors the `namespace` macro in mupq/mk/schemes.mk so that manifests
    describe the symbols that actually end up in the ELF.
    """
    name = impl_name(scheme_path)
    kind = kind_of(scheme_path)
    prefix = f"mupq_pqclean_crypto_{kind}_"
    if not name.startswith(prefix):
        return ""
    return ("pqclean_" + name[len(prefix) :] + "_").upper().replace("-", "")


def probe_sizes(scheme_dir, namespace="", extra_includes=()):
    """Read the CRYPTO_* sizes out of a scheme's headers with the preprocessor.

    pqm4 schemes define these as expressions over their parameter set
    (CRYPTO_BYTES = CTILDEBYTES + L*POLYZ_PACKEDBYTES + ...), and PQClean ones
    namespace them, so the values cannot simply be grepped out; the
    preprocessor does the work and we evaluate the arithmetic it leaves.
    """
    lines = []
    for key, macro in SIZE_MACROS.items():
        lines.append(f"#ifdef {namespace}{macro}")
        lines.append(f"UCPQC_SIZE {key} = UCPQC_CAT({namespace or ''}, {macro}) ;")
        lines.append("#endif")
    source = PROBE % "\n".join(lines)

    cmd = [CPP, "-P", "-I", scheme_dir]
    for inc in extra_includes:
        cmd += ["-I", inc]
    cmd += ["-x", "c", "-"]
    try:
        out = subprocess.run(
            cmd, input=source, capture_output=True, text=True, check=True
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    sizes = {}
    for key, expr in re.findall(r"UCPQC_SIZE\s+(\w+)\s*=\s*([^;]+);", out):
        expr = expr.strip()
        # Only arithmetic over integers may be evaluated; anything else means
        # a macro did not expand and the value stays unknown.
        if not re.fullmatch(r"[\d\s()+\-*/]+", expr):
            continue
        try:
            sizes[key] = int(eval(expr))  # noqa: S307 - validated above
        except (SyntaxError, ZeroDivisionError, TypeError):
            continue
    return sizes


def manifest_for(scheme_path, pqm4_root, elf_name, platform=DEFAULT_PLATFORM):
    """Everything the framework wants to know about a firmware image."""
    scheme_dir = os.path.join(pqm4_root, scheme_path)
    namespace = namespace_for(scheme_path)
    kind = kind_of(scheme_path)
    sizes = probe_sizes(
        scheme_dir,
        namespace,
        extra_includes=[os.path.join(pqm4_root, "common"), os.path.join(pqm4_root, "mupq", "common")],
    )
    if kind == "kem":
        # For a KEM, CRYPTO_BYTES is the shared secret, not a signature.
        sizes = dict(sizes)
        if "sig" in sizes:
            sizes["ss"] = sizes.pop("sig")
    else:
        sizes.pop("ct", None)

    parts = scheme_path.strip("/").split("/")
    return {
        "scheme": scheme_path,
        "algname": "/".join(parts[-2:]),
        "kind": kind,
        "platform": platform,
        "namespace": namespace,
        "sizes": sizes,
        "elf": elf_name,
        "source": "pqm4",
    }


def build(
    scheme_path,
    pqm4_root,
    out_dir="firmware",
    platform=DEFAULT_PLATFORM,
    tests=DEFAULT_TESTS,
    jobs=None,
    quiet=False,
):
    """Build one scheme with pqm4 and stage the ELFs plus manifests.

    Returns the list of staged ELF paths.
    """
    pqm4_root = os.path.abspath(pqm4_root)
    if not os.path.isdir(os.path.join(pqm4_root, scheme_path)):
        raise FileNotFoundError(f"no such scheme in pqm4: {scheme_path}")

    name = impl_name(scheme_path)
    targets = [f"elf/{name}_{test}.elf" for test in tests]
    cmd = [
        "make",
        f"-j{jobs or os.cpu_count() or 4}",
        f"PLATFORM={platform}",
        f"IMPLEMENTATION_PATH={scheme_path}",
        *targets,
    ]
    if not quiet:
        print(f"$ {' '.join(cmd)}   (in {pqm4_root})", flush=True)
    result = subprocess.run(
        cmd,
        cwd=pqm4_root,
        text=True,
        capture_output=quiet,
    )
    if result.returncode != 0:
        if quiet:
            sys.stderr.write(result.stdout or "")
            sys.stderr.write(result.stderr or "")
        raise RuntimeError(f"pqm4 build failed for {scheme_path}")

    os.makedirs(out_dir, exist_ok=True)
    staged = []
    short = "_".join(scheme_path.strip("/").split("/")[-2:])
    for test, target in zip(tests, targets):
        src = os.path.join(pqm4_root, target)
        dst = os.path.join(out_dir, f"{short}_{test}.elf")
        shutil.copy2(src, dst)
        manifest = manifest_for(scheme_path, pqm4_root, os.path.basename(dst), platform)
        manifest["test"] = test
        with open(os.path.splitext(dst)[0] + ".json", "w") as fh:
            json.dump(manifest, fh, indent=2)
            fh.write("\n")
        staged.append(dst)
        if not quiet:
            sizes = manifest["sizes"] or "unknown"
            print(f"  staged {dst}  sizes={sizes}", flush=True)
    return staged


def discover(pqm4_root, pattern=""):
    """List the schemes available in a pqm4 tree."""
    found = []
    for kind in ("crypto_sign", "crypto_kem"):
        for root in (kind, os.path.join("mupq", kind), os.path.join("mupq", "pqclean", kind)):
            base = os.path.join(pqm4_root, root)
            if not os.path.isdir(base):
                continue
            for scheme in sorted(os.listdir(base)):
                impl_dir = os.path.join(base, scheme)
                if not os.path.isdir(impl_dir):
                    continue
                for impl in sorted(os.listdir(impl_dir)):
                    if not os.path.isdir(os.path.join(impl_dir, impl)):
                        continue
                    path = f"{root}/{scheme}/{impl}".replace("\\", "/")
                    if pattern.lower() in path.lower():
                        found.append(path)
    return found
