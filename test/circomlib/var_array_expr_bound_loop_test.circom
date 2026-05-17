pragma circom 2.0.0;

// Expression-length template-local `var` array, read inside a loop
// whose bound is a parameter *expression* (`2*k-1`, not a bare
// param). An expression bound routes the loop through the memoized
// unroll path, which holds the loop variable as a placeholder during
// body capture; the index resolver therefore emits a symbolic
// `acc[<placeholder>]` rather than the flat-scalar `acc_<i>` the
// direct-unroll path produces. A template-local `var` array carries
// no array binding past lowering (only per-element zero-init `Let`s),
// so the post-substitution fold must collapse `acc[<const>]` to
// `acc_<i>` or the read dangles at instantiate (`… is not an array`).
//
// This mirrors the circomlib BigMultNoCarry `out_poly` /
// LongToShortNoEndCarry `split[k][3]` shape that the secp256k1
// boss-fight exercises, minimally.
template Poly(k) {
    signal input  a[k];
    signal output out[2 * k - 1];

    var acc[2 * k - 1];
    for (var i = 0; i < 2 * k - 1; i++) {
        acc[i] = 0;
        for (var j = 0; j < k; j++) {
            acc[i] = acc[i] + a[j] * (i + 1);
        }
    }
    for (var i = 0; i < 2 * k - 1; i++) {
        out[i] <-- acc[i];
        out[i] === acc[i];
    }
}

component main {public [a]} = Poly(3);
