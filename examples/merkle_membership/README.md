# Merkle membership — Achronyme workspace example

Proves that a secret key belongs to a known set without revealing
which element of the set it is, using circomlib
[Poseidon(2)](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
for every commitment and interior hash.

This is the exact construction used by tornado-cash, semaphore, and
worldcoin. The proof produced here is interoperable with any
verifier deployed for those protocols on the same curve (BN254).

```
                    root                        ← public
                  /      \
               n01        n23                   ← level 1
              /    \     /    \
             m0    m1   m2    m3                ← leaf commitments
              ↑     ↑   ↑     ↑
           Poseidon(key_i, 0) for i = 0..3
```

## Layout

```
merkle_membership/
├── achronyme.toml     project manifest + [circom] libs path
├── README.md          this file
└── src/
    └── main.ach       entry: build tree + prove membership
```

## Run

From the Achronyme workspace root:

```sh
ach run examples/merkle_membership/src/main.ach
```

Expected output:

```
=== Merkle Membership (circomlib Poseidon) ===
Club root:    <32-byte field element>
Registered:   4 members

Member 2 proving membership…
Proof generated (Groth16, 855 bytes)
Proof verified — <constraint count>
Membership verified ✓

The verifier learned the root and saw a valid Groth16 proof,
but not which of the four members produced it.
```

## What the prove block constrains

```
my_leaf      = Poseidon(key_2, 0)             // re-derive the leaf
lvl0         = Poseidon(my_leaf, sibling_0)   // member 2 is LEFT child
computed_root = Poseidon(sibling_1, lvl0)     // its subtree is RIGHT child
computed_root === merkle_root                 // public equality
```

`merkle_root` is the only public input. `key_2`, `sibling_0`,
`sibling_1`, and every intermediate hash are private witnesses.

## Parametrization

The depth is hardcoded to 2 (four leaves, two levels) so the prove
block can spell out each step without Circom-side loop unrolling. For
a depth-N tree the same construction scales by repeating the `lvl_k =
Poseidon(left, right)` step N times with the appropriate sibling
ordering dictated by the bits of the leaf index. That scaling is
exactly what tornado-cash's depth-20 deposit tree does.
