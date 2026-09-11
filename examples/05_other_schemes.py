"""The framework is not Dilithium-specific: same code, other schemes.

Runs whatever firmware images are present in firmware/ through one generic
driver.  A signature scheme gets keygen/sign/verify, a KEM gets
keygen/encaps/decaps, and the API entry points and buffer sizes come from the
ELF and its manifest -- nothing here names an algorithm.

It also cross-checks implementations of the same scheme against each other:
driven from the same seeded RNG, an optimised M4 implementation and the plain
C reference must produce identical keys and signatures.

    python examples/05_other_schemes.py [firmware/*.elf ...]
"""

import glob
import sys

sys.path.insert(0, ".")

from ucpqc import Machine, Scheme

elfs = [a for a in sys.argv[1:] if a.endswith(".elf")] or sorted(glob.glob("firmware/*.elf"))
if not elfs:
    sys.exit("no firmware found; run: make firmware")

SEED = b"cross-check"
results = {}

for path in elfs:
    m = Machine.from_elf(path)
    scheme = Scheme.bind(m)
    m.boot()
    m.stub_randombytes(SEED)

    outcome = scheme.roundtrip(b"same message")
    results[path] = outcome

    costs = "  ".join(f"{k}={v:,}" for k, v in outcome["cost"].items())
    print(f"{scheme.name:<24} {scheme.kind:<5} ok={outcome['ok']}   {costs}")

# Implementations of the same algorithm must agree bit for bit.
print("\ncross-implementation check (same seed, same message):")
by_algorithm = {}
for path, outcome in results.items():
    algorithm = path.split("/")[-1].split("_")[0]
    by_algorithm.setdefault(algorithm, []).append((path, outcome))

for algorithm, group in by_algorithm.items():
    if len(group) < 2:
        continue
    reference_path, reference = group[0]
    for path, outcome in group[1:]:
        keys_match = outcome["pk"] == reference["pk"] and outcome["sk"] == reference["sk"]
        artefact = "sig" if outcome["kind"] == "sign" else "ct"
        output_match = outcome.get(artefact) == reference.get(artefact)
        verdict = "identical" if keys_match and output_match else "DIFFER"
        print(f"  {algorithm}: {reference_path.split('/')[-1]} vs "
              f"{path.split('/')[-1]}  ->  {verdict}")
