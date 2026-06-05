//! BN254 field-kernel microbenchmarks.
//!
//! Run scalar controls:
//!     cargo bench -p memory --features field-kernel-bench --bench field_kernel
//!
//! Run machine-native codegen controls:
//!     RUSTFLAGS="-C target-cpu=native" cargo bench -p memory \
//!         --features field-kernel-bench --bench field_kernel

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use memory::field::bench_support::{
    bn254_final_reduce_branchy, bn254_final_reduce_ct, bn254_from_canonical, bn254_from_u64,
    bn254_ifma52_madd8, bn254_ifma52_madd8_unchecked, bn254_limbs4_to_limbs52,
    bn254_limbs52_to_limbs4, bn254_modulus, bn254_montgomery_mul, bn254_montgomery_mul_5x52_hybrid,
    bn254_montgomery_reduce, bn254_mul_wide, bn254_mul_wide_5x52, bn254_mul_wide_bmi2_adx,
    bn254_mul_wide_bmi2_adx_unchecked, bn254_scalar52_madd8,
};
#[cfg(target_arch = "x86_64")]
use memory::field::bench_support::{
    bn254_montgomery_mul_5x52_ifma_hybrid, bn254_montgomery_mul_5x52_ifma_hybrid_unchecked,
    bn254_mul_wide_5x52_ifma, bn254_mul_wide_5x52_ifma_unchecked,
};
use memory::{Bn254Fr, FieldElement};

const STREAM_LEN: usize = 256;

fn seed_stream() -> Vec<([u64; 4], [u64; 4])> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };

    (0..STREAM_LEN)
        .map(|_| {
            let a = [
                next(),
                next() & 0x0fff_ffff_ffff_ffff,
                next(),
                next() & 0x0fff_ffff_ffff_ffff,
            ];
            let b = [
                next(),
                next() & 0x0fff_ffff_ffff_ffff,
                next(),
                next() & 0x0fff_ffff_ffff_ffff,
            ];
            (bn254_from_canonical(a), bn254_from_canonical(b))
        })
        .collect()
}

fn seed_limb52_stream() -> Vec<([u64; 8], [u64; 8])> {
    const MASK: u64 = (1u64 << 52) - 1;
    let mut x = 0x6a09_e667_f3bc_c909u64;
    let mut next = || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d) & MASK
    };

    (0..STREAM_LEN)
        .map(|_| {
            let a = [
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
            ];
            let b = [
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
                next(),
            ];
            (a, b)
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let stream = seed_stream();
    let limb52_stream = seed_limb52_stream();
    let field_limb52_stream: Vec<([u64; 5], [u64; 5])> = stream
        .iter()
        .map(|(a, b)| (bn254_limbs4_to_limbs52(a), bn254_limbs4_to_limbs52(b)))
        .collect();
    let wide_inputs: Vec<[u64; 8]> = stream.iter().map(|(a, b)| bn254_mul_wide(a, b)).collect();
    let final_reduce_inputs = final_reduce_stream(&stream);
    let fe_stream: Vec<(FieldElement<Bn254Fr>, FieldElement<Bn254Fr>)> = stream
        .iter()
        .map(|(a, b)| (FieldElement::from_repr(*a), FieldElement::from_repr(*b)))
        .collect();

    c.bench_function("bn254_field_element_mul_dependent", |b| {
        let base = FieldElement::<Bn254Fr>::from_repr(stream[0].0);
        let rhs = FieldElement::<Bn254Fr>::from_repr(stream[0].1);
        b.iter(|| {
            let mut acc = black_box(base);
            for _ in 0..STREAM_LEN {
                acc = acc.mul(black_box(&rhs));
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_montgomery_mul_dependent", |b| {
        let rhs = stream[0].1;
        b.iter(|| {
            let mut acc = black_box(stream[0].0);
            for _ in 0..STREAM_LEN {
                acc = bn254_montgomery_mul(black_box(&acc), black_box(&rhs));
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_montgomery_mul_independent_stream", |b| {
        b.iter(|| {
            let mut acc = bn254_from_u64(0);
            for (a, rhs) in &stream {
                let product = bn254_montgomery_mul(black_box(a), black_box(rhs));
                acc[0] ^= product[0];
                acc[1] ^= product[1];
                acc[2] ^= product[2];
                acc[3] ^= product[3];
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_field_element_mul_independent_stream", |b| {
        b.iter(|| {
            let mut acc = FieldElement::<Bn254Fr>::zero();
            for (a, rhs) in &fe_stream {
                let product = a.mul(black_box(rhs));
                acc = FieldElement::from_repr([
                    acc.into_repr()[0] ^ product.into_repr()[0],
                    acc.into_repr()[1] ^ product.into_repr()[1],
                    acc.into_repr()[2] ^ product.into_repr()[2],
                    acc.into_repr()[3] ^ product.into_repr()[3],
                ]);
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_mul_wide_independent_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 8];
            for (a, rhs) in &stream {
                let wide = bn254_mul_wide(black_box(a), black_box(rhs));
                for (dst, src) in acc.iter_mut().zip(wide) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_limb52_pack_roundtrip_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 4];
            for (a, _) in &stream {
                let packed = bn254_limbs4_to_limbs52(black_box(a));
                let unpacked = bn254_limbs52_to_limbs4(black_box(&packed));
                for (dst, src) in acc.iter_mut().zip(unpacked) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_mul_wide_5x52_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 10];
            for (a, rhs) in &field_limb52_stream {
                let wide = bn254_mul_wide_5x52(black_box(a), black_box(rhs));
                for (dst, src) in acc.iter_mut().zip(wide) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    #[cfg(target_arch = "x86_64")]
    if bn254_mul_wide_5x52_ifma(&field_limb52_stream[0].0, &field_limb52_stream[0].1).is_some() {
        c.bench_function("bn254_mul_wide_5x52_ifma_stream", |b| {
            b.iter(|| {
                let mut acc = [0u64; 10];
                for (a, rhs) in &field_limb52_stream {
                    // SAFETY: Benchmark registration checks AVX-512 IFMA before this timed path.
                    let wide =
                        unsafe { bn254_mul_wide_5x52_ifma_unchecked(black_box(a), black_box(rhs)) };
                    for (dst, src) in acc.iter_mut().zip(wide) {
                        *dst ^= src;
                    }
                }
                black_box(acc)
            });
        });
    }

    c.bench_function("bn254_montgomery_mul_5x52_hybrid_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 4];
            for (a, rhs) in &field_limb52_stream {
                let product = bn254_montgomery_mul_5x52_hybrid(black_box(a), black_box(rhs));
                for (dst, src) in acc.iter_mut().zip(product) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    #[cfg(target_arch = "x86_64")]
    if bn254_montgomery_mul_5x52_ifma_hybrid(&field_limb52_stream[0].0, &field_limb52_stream[0].1)
        .is_some()
    {
        c.bench_function("bn254_montgomery_mul_5x52_ifma_hybrid_stream", |b| {
            b.iter(|| {
                let mut acc = [0u64; 4];
                for (a, rhs) in &field_limb52_stream {
                    // SAFETY: Benchmark registration checks AVX-512 IFMA before this timed path.
                    let product = unsafe {
                        bn254_montgomery_mul_5x52_ifma_hybrid_unchecked(
                            black_box(a),
                            black_box(rhs),
                        )
                    };
                    for (dst, src) in acc.iter_mut().zip(product) {
                        *dst ^= src;
                    }
                }
                black_box(acc)
            });
        });
    }

    if bn254_mul_wide_bmi2_adx(&stream[0].0, &stream[0].1).is_some() {
        c.bench_function("bn254_mul_wide_bmi2_adx_independent_stream", |b| {
            b.iter(|| {
                let mut acc = [0u64; 8];
                for (a, rhs) in &stream {
                    // SAFETY: Benchmark registration checks BMI2/ADX once before this timed path.
                    let wide =
                        unsafe { bn254_mul_wide_bmi2_adx_unchecked(black_box(a), black_box(rhs)) };
                    for (dst, src) in acc.iter_mut().zip(wide) {
                        *dst ^= src;
                    }
                }
                black_box(acc)
            });
        });
    }

    c.bench_function("bn254_scalar52_madd8_stream", |b| {
        b.iter(|| {
            let mut lo_acc = [0u64; 8];
            let mut hi_acc = [0u64; 8];
            for (a, rhs) in &limb52_stream {
                let (lo, hi) = bn254_scalar52_madd8(black_box(a), black_box(rhs));
                for ((lo_dst, hi_dst), (lo_src, hi_src)) in lo_acc
                    .iter_mut()
                    .zip(hi_acc.iter_mut())
                    .zip(lo.into_iter().zip(hi))
                {
                    *lo_dst ^= lo_src;
                    *hi_dst ^= hi_src;
                }
            }
            black_box((lo_acc, hi_acc))
        });
    });

    if bn254_ifma52_madd8(&limb52_stream[0].0, &limb52_stream[0].1).is_some() {
        c.bench_function("bn254_ifma52_madd8_stream", |b| {
            b.iter(|| {
                let mut lo_acc = [0u64; 8];
                let mut hi_acc = [0u64; 8];
                for (a, rhs) in &limb52_stream {
                    // SAFETY: Benchmark registration checks AVX-512 IFMA once before this timed path.
                    let (lo, hi) =
                        unsafe { bn254_ifma52_madd8_unchecked(black_box(a), black_box(rhs)) };
                    for ((lo_dst, hi_dst), (lo_src, hi_src)) in lo_acc
                        .iter_mut()
                        .zip(hi_acc.iter_mut())
                        .zip(lo.into_iter().zip(hi))
                    {
                        *lo_dst ^= lo_src;
                        *hi_dst ^= hi_src;
                    }
                }
                black_box((lo_acc, hi_acc))
            });
        });
    }

    c.bench_function("bn254_montgomery_reduce_independent_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 4];
            for wide in &wide_inputs {
                let reduced = bn254_montgomery_reduce(black_box(wide));
                for (dst, src) in acc.iter_mut().zip(reduced) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_final_reduce_ct_mixed_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 4];
            for limbs in &final_reduce_inputs {
                let reduced = bn254_final_reduce_ct(black_box(*limbs));
                for (dst, src) in acc.iter_mut().zip(reduced) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });

    c.bench_function("bn254_final_reduce_branchy_mixed_stream", |b| {
        b.iter(|| {
            let mut acc = [0u64; 4];
            for limbs in &final_reduce_inputs {
                let reduced = bn254_final_reduce_branchy(black_box(*limbs));
                for (dst, src) in acc.iter_mut().zip(reduced) {
                    *dst ^= src;
                }
            }
            black_box(acc)
        });
    });
}

fn final_reduce_stream(stream: &[([u64; 4], [u64; 4])]) -> Vec<[u64; 4]> {
    stream
        .iter()
        .enumerate()
        .map(|(idx, (a, b))| {
            let wide = bn254_mul_wide(a, b);
            let mut limbs = final_reduce_candidate([wide[0], wide[1], wide[2], wide[3]]);
            if idx % 2 == 1 {
                limbs = add_modulus_without_overflow(limbs);
            }
            limbs
        })
        .collect()
}

fn final_reduce_candidate(mut limbs: [u64; 4]) -> [u64; 4] {
    limbs[0] &= 0x0000_0000_ffff_ffff;
    limbs[1] &= 0x0000_0000_ffff_ffff;
    limbs[2] &= 0x0000_0000_ffff_ffff;
    limbs[3] &= 0x0000_0000_0000_ffff;
    limbs
}

fn add_modulus_without_overflow(limbs: [u64; 4]) -> [u64; 4] {
    let modulus = bn254_modulus();
    let (r0, carry) = limbs[0].overflowing_add(modulus[0]);
    let (r1a, carry1) = limbs[1].overflowing_add(modulus[1]);
    let (r1, carry2) = r1a.overflowing_add(carry as u64);
    let (r2a, carry3) = limbs[2].overflowing_add(modulus[2]);
    let (r2, carry4) = r2a.overflowing_add((carry1 || carry2) as u64);
    let (r3a, carry5) = limbs[3].overflowing_add(modulus[3]);
    let (r3, carry6) = r3a.overflowing_add((carry3 || carry4) as u64);
    debug_assert!(!carry5 && !carry6);
    [r0, r1, r2, r3]
}

criterion_group!(benches, bench);
criterion_main!(benches);
