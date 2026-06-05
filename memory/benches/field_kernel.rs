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
    bn254_from_canonical, bn254_from_u64, bn254_montgomery_mul, bn254_montgomery_reduce,
    bn254_mul_wide, bn254_mul_wide_bmi2_adx, bn254_mul_wide_bmi2_adx_unchecked,
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

fn bench(c: &mut Criterion) {
    let stream = seed_stream();
    let wide_inputs: Vec<[u64; 8]> = stream.iter().map(|(a, b)| bn254_mul_wide(a, b)).collect();
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
}

criterion_group!(benches, bench);
criterion_main!(benches);
