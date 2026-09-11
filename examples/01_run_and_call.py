"""Two ways to run Dilithium under the emulator.

1. Boot the pqm4 test firmware and let it run to completion, reading what it
   prints on the UART -- the emulator standing in for `qemu-system-arm`.
2. Take control after the C runtime is up and call the scheme's functions
   directly, which is what every other example builds on.

    python examples/01_run_and_call.py [firmware.elf]
"""

import sys

sys.path.insert(0, ".")

from ucpqc import Machine, Scheme

ELF = sys.argv[1] if len(sys.argv) > 1 else "firmware/ml-dsa-44_m4f_test.elf"


def run_firmware_as_is():
    m = Machine.from_elf(ELF)
    m.run()
    print(m.uart_text().strip()[:400])
    print(f"\n[firmware exited: {m.icount:,} instructions]\n")


def drive_the_api():
    m = Machine.from_elf(ELF)
    scheme = Scheme.bind(m)
    m.boot()  # reset -> SystemInit -> main, then stop

    # Pin the RNG so the whole experiment is reproducible.
    m.stub_randombytes(b"example-seed")

    pk, sk = scheme.keypair()
    sig = scheme.sign(b"attack at dawn", sk)
    ok = scheme.verify(sig, b"attack at dawn", pk)

    print(f"scheme:    {scheme.name}")
    print(f"pk/sk/sig: {len(pk)}/{len(sk)}/{len(sig)} bytes")
    print(f"pk starts: {pk[:16].hex()}")
    print(f"verified:  {ok}")
    print("\ninstructions per operation:")
    for op, cost in scheme.last_cost.items():
        print(f"  {op:<10} {cost:>12,}")

    # Tampering with one bit must make verification fail.
    broken = bytes([sig[0] ^ 1]) + sig[1:]
    print(f"\ntampered signature verifies: {scheme.verify(broken, b'attack at dawn', pk)}")


if __name__ == "__main__":
    print("=== 1. running the firmware as the board would ===")
    run_firmware_as_is()
    print("=== 2. driving the API from Python ===")
    drive_the_api()
