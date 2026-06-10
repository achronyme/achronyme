//! u64-limb big-integer math backing the native intrinsics.
//!
//! Two representations:
//!
//! - **digits** — the bytecode-facing boundary: little-endian base-2^n
//!   (`n <= 64`), one digit per `u64`, each digit `< 2^n`. This is the
//!   register layout the `bigint_func` family reads and writes.
//! - **words** — internal arithmetic: little-endian base-2^64.
//!
//! The intrinsic entry points (`prod_digits`, `longdiv_digits`,
//! `modexp_digits`, `modinv_digits`) take digit slices and return
//! digit vectors. `None` means a precondition of the reference
//! algorithm does not hold — the caller must fall back to interpreting
//! the subprogram body, never guess.
//!
//! Equivalence contract: for inputs satisfying the guards (digits in
//! range, divisor's leading digit nonzero, `k <= 2^n` so the reference
//! carry splits are lossless), each entry point returns exactly the
//! digits the corresponding `bigint_func` reference produces. The
//! exponentiation pair mirrors the reference loop structure literally
//! (multiply-then-square per exponent bit, square skipped on the last
//! bit) so even degenerate moduli match bit for bit.

/// Drop leading zero words. Zero collapses to an empty slice.
fn trim(words: &mut Vec<u64>) {
    while words.last() == Some(&0) {
        words.pop();
    }
}

fn is_zero(words: &[u64]) -> bool {
    words.iter().all(|&w| w == 0)
}

/// Bit length of the value (0 for zero).
fn bit_len(words: &[u64]) -> u64 {
    for (i, &w) in words.iter().enumerate().rev() {
        if w != 0 {
            return i as u64 * 64 + (64 - w.leading_zeros() as u64);
        }
    }
    0
}

fn get_bit(words: &[u64], bit: u64) -> u64 {
    let w = (bit / 64) as usize;
    let off = bit % 64;
    (words.get(w).copied().unwrap_or(0) >> off) & 1
}

/// `a < b`, `a == b`, `a > b` on trimmed-or-not word slices.
fn cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let la = bit_len(a);
    let lb = bit_len(b);
    if la != lb {
        return la.cmp(&lb);
    }
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let wa = a.get(i).copied().unwrap_or(0);
        let wb = b.get(i).copied().unwrap_or(0);
        if wa != wb {
            return wa.cmp(&wb);
        }
    }
    std::cmp::Ordering::Equal
}

/// Pack base-2^n digits into base-2^64 words.
pub fn digits_to_words(digits: &[u64], n: u32) -> Vec<u64> {
    let total_bits = digits.len() as u64 * n as u64;
    let n_words = total_bits.div_ceil(64).max(1) as usize;
    let mut words = vec![0u64; n_words];
    for (i, &d) in digits.iter().enumerate() {
        let bit = i as u64 * n as u64;
        let w = (bit / 64) as usize;
        let off = (bit % 64) as u32;
        words[w] |= d << off;
        if off > 0 && off + n > 64 {
            if let Some(slot) = words.get_mut(w + 1) {
                *slot |= d >> (64 - off);
            }
        }
    }
    trim(&mut words);
    words
}

/// Unpack a value into exactly `count` base-2^n digits. `None` when
/// the value does not fit (`bit_len > count * n`) — callers treat that
/// as a guard failure rather than truncating.
pub fn words_to_digits(words: &[u64], n: u32, count: usize) -> Option<Vec<u64>> {
    if bit_len(words) > count as u64 * n as u64 {
        return None;
    }
    let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let bit = i as u64 * n as u64;
        let w = (bit / 64) as usize;
        let off = (bit % 64) as u32;
        let lo = words.get(w).copied().unwrap_or(0) >> off;
        let hi = if off > 0 && off + n > 64 {
            words.get(w + 1).copied().unwrap_or(0) << (64 - off)
        } else {
            0
        };
        out.push((lo | hi) & mask);
    }
    Some(out)
}

/// Schoolbook product.
pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
    if is_zero(a) || is_zero(b) {
        return Vec::new();
    }
    let mut out = vec![0u64; a.len() + b.len()];
    for (i, &wa) in a.iter().enumerate() {
        if wa == 0 {
            continue;
        }
        let mut carry: u64 = 0;
        for (j, &wb) in b.iter().enumerate() {
            let t = wa as u128 * wb as u128 + out[i + j] as u128 + carry as u128;
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        out[i + b.len()] = out[i + b.len()].wrapping_add(carry);
    }
    trim(&mut out);
    out
}

/// `a - b` for `a >= b` (callers check). Trimmed result.
fn sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow: u64 = 0;
    for (i, &wa) in a.iter().enumerate() {
        let wb = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = wa.overflowing_sub(wb);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out.push(d2);
        borrow = (b1 as u64) + (b2 as u64);
    }
    debug_assert_eq!(borrow, 0, "sub underflow: caller must ensure a >= b");
    trim(&mut out);
    out
}

/// Euclidean division: `(a / b, a % b)`. `None` when `b == 0`.
pub fn divrem(a: &[u64], b: &[u64]) -> Option<(Vec<u64>, Vec<u64>)> {
    let mut bv = b.to_vec();
    trim(&mut bv);
    if bv.is_empty() {
        return None;
    }
    let mut av = a.to_vec();
    trim(&mut av);
    if cmp(&av, &bv) == std::cmp::Ordering::Less {
        return Some((Vec::new(), av));
    }
    if bv.len() == 1 {
        let d = bv[0];
        let mut q = vec![0u64; av.len()];
        let mut rem: u64 = 0;
        for i in (0..av.len()).rev() {
            let cur = ((rem as u128) << 64) | av[i] as u128;
            q[i] = (cur / d as u128) as u64;
            rem = (cur % d as u128) as u64;
        }
        trim(&mut q);
        let mut r = vec![rem];
        trim(&mut r);
        return Some((q, r));
    }
    Some(knuth_divrem(&av, &bv))
}

/// Knuth Algorithm D for `b.len() >= 2`, `a >= b`, both trimmed.
fn knuth_divrem(a: &[u64], b: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let n = b.len();
    let m = a.len() - n;
    let s = b[n - 1].leading_zeros();

    // Normalized copies: v = b << s (n words), u = a << s (m + n + 1).
    let shl = |src: &[u64], extra: usize| -> Vec<u64> {
        let mut out = vec![0u64; src.len() + extra];
        if s == 0 {
            out[..src.len()].copy_from_slice(src);
        } else {
            let mut carry = 0u64;
            for (i, &w) in src.iter().enumerate() {
                out[i] = (w << s) | carry;
                carry = w >> (64 - s);
            }
            out[src.len()] = carry;
        }
        out
    };
    let v = shl(b, if s == 0 { 0 } else { 1 });
    let v = &v[..n]; // the shifted divisor still fits n words
    let mut u = shl(a, 1);

    let mut q = vec![0u64; m + 1];
    for j in (0..=m).rev() {
        // Estimate q[j] from the top two dividend words against v[n-1].
        let top = ((u[j + n] as u128) << 64) | u[j + n - 1] as u128;
        let mut qhat = top / v[n - 1] as u128;
        let mut rhat = top % v[n - 1] as u128;
        while qhat >> 64 != 0 || qhat * v[n - 2] as u128 > ((rhat << 64) | u[j + n - 2] as u128) {
            qhat -= 1;
            rhat += v[n - 1] as u128;
            if rhat >> 64 != 0 {
                break;
            }
        }
        // Multiply-subtract qhat * v from u[j .. j+n].
        let mut borrow: i128 = 0;
        let mut carry: u64 = 0;
        for i in 0..n {
            let p = qhat * v[i] as u128 + carry as u128;
            carry = (p >> 64) as u64;
            let t = u[j + i] as i128 - (p as u64) as i128 - borrow;
            u[j + i] = t as u64;
            borrow = if t < 0 { 1 } else { 0 };
        }
        let t = u[j + n] as i128 - carry as i128 - borrow;
        u[j + n] = t as u64;

        if t < 0 {
            // qhat was one too large: add v back.
            qhat -= 1;
            let mut carry: u64 = 0;
            for i in 0..n {
                let t = u[j + i] as u128 + v[i] as u128 + carry as u128;
                u[j + i] = t as u64;
                carry = (t >> 64) as u64;
            }
            u[j + n] = u[j + n].wrapping_add(carry);
        }
        q[j] = qhat as u64;
    }

    // Remainder = u[0..n] >> s.
    let mut r = vec![0u64; n];
    if s == 0 {
        r.copy_from_slice(&u[..n]);
    } else {
        for i in 0..n {
            let hi = if i + 1 < n { u[i + 1] << (64 - s) } else { 0 };
            r[i] = (u[i] >> s) | hi;
        }
    }
    trim(&mut q);
    trim(&mut r);
    (q, r)
}

/// Are all digits below `2^n`?
fn digits_in_range(digits: &[u64], n: u32) -> bool {
    if n == 64 {
        return true;
    }
    let limit = 1u64 << n;
    digits.iter().all(|&d| d < limit)
}

/// The reference carry split (`SplitThreeFn`) is lossless only while a
/// product column fits 3n bits, i.e. `k <= 2^n`. Outside that the
/// reference truncates and the exact native math would diverge.
fn split_lossless(n: u32, k: u32) -> bool {
    n >= 63 || (k as u64) <= (1u64 << n)
}

/// `prod(n, k, a, b)` — exact product as `2k` digits.
///
/// Declines `k < 2`: the reference's carry chain never writes the top
/// digit when `2k - 1 == 1`, so its single-register product truncates
/// — only the interpreted body reproduces that.
pub fn prod_digits(n: u32, k: u32, a: &[u64], b: &[u64]) -> Option<Vec<u64>> {
    let k = k as usize;
    if k < 2 || a.len() < k || b.len() < k {
        return None;
    }
    let (a, b) = (&a[..k], &b[..k]);
    if !digits_in_range(a, n) || !digits_in_range(b, n) || !split_lossless(n, k as u32) {
        return None;
    }
    let p = mul(&digits_to_words(a, n), &digits_to_words(b, n));
    words_to_digits(&p, n, 2 * k)
}

/// `long_div(n, k, m, a, b)` — euclidean quotient (`m + 1` digits) and
/// remainder (`k` digits). `a` supplies `m + k` digits, `b` supplies
/// `k`; the reference requires `b`'s leading digit to be nonzero.
pub fn longdiv_digits(
    n: u32,
    k: u32,
    m: u32,
    a: &[u64],
    b: &[u64],
) -> Option<(Vec<u64>, Vec<u64>)> {
    let (k, m) = (k as usize, m as usize);
    if a.len() < m + k || b.len() < k {
        return None;
    }
    let (a, b) = (&a[..m + k], &b[..k]);
    if !digits_in_range(a, n) || !digits_in_range(b, n) || b[k - 1] == 0 {
        return None;
    }
    let (q, r) = divrem(&digits_to_words(a, n), &digits_to_words(b, n))?;
    // b >= 2^(n(k-1)) because its leading digit is nonzero, so the
    // quotient always fits m + 1 digits; the conversion re-checks.
    let q = words_to_digits(&q, n, m + 1)?;
    let r = words_to_digits(&r, n, k)?;
    Some((q, r))
}

/// The shared `mod_exp` loop, mirroring the reference structure
/// literally: walk exponent bits from `n * k - 1` down to 0,
/// multiply-then-reduce when the bit is set, square-then-reduce unless
/// at the last bit. `a` is intentionally not pre-reduced — the first
/// reduction happens after the first multiplication, exactly like the
/// reference.
fn modexp_words(n: u32, k: u32, a: &[u64], p: &[u64], e: &[u64]) -> Option<Vec<u64>> {
    let mut out = vec![1u64];
    for i in (0..n as u64 * k as u64).rev() {
        if get_bit(e, i) == 1 {
            out = divrem(&mul(&out, a), p)?.1;
        }
        if i > 0 {
            out = divrem(&mul(&out, &out), p)?.1;
        }
    }
    Some(out)
}

/// `mod_exp(n, k, a, p, e)` — `k` digits of the reference modular
/// exponentiation.
pub fn modexp_digits(n: u32, k: u32, a: &[u64], p: &[u64], e: &[u64]) -> Option<Vec<u64>> {
    let k_us = k as usize;
    // k < 2 declines for the same reason as `prod_digits`: the
    // reference exponentiation is built on the truncating
    // single-register product.
    if k_us < 2 || a.len() < k_us || p.len() < k_us || e.len() < k_us {
        return None;
    }
    let (a, p, e) = (&a[..k_us], &p[..k_us], &e[..k_us]);
    if !digits_in_range(a, n)
        || !digits_in_range(p, n)
        || !digits_in_range(e, n)
        || p[k_us - 1] == 0
        || !split_lossless(n, k)
    {
        return None;
    }
    let out = modexp_words(
        n,
        k,
        &digits_to_words(a, n),
        &digits_to_words(p, n),
        &digits_to_words(e, n),
    )?;
    words_to_digits(&out, n, k_us)
}

/// `mod_inv(n, k, a, p)` — `k` digits of the reference Fermat inverse
/// `a^(p-2) mod p`, with the literal all-zero-digit early exit.
pub fn modinv_digits(n: u32, k: u32, a: &[u64], p: &[u64]) -> Option<Vec<u64>> {
    let k_us = k as usize;
    // k < 2 declines — see `prod_digits`.
    if k_us < 2 || a.len() < k_us || p.len() < k_us {
        return None;
    }
    let (a, p) = (&a[..k_us], &p[..k_us]);
    if !digits_in_range(a, n) || !digits_in_range(p, n) || p[k_us - 1] == 0 || !split_lossless(n, k)
    {
        return None;
    }
    if a.iter().all(|&d| d == 0) {
        return Some(vec![0u64; k_us]);
    }
    let p_words = digits_to_words(p, n);
    // The reference computes the exponent as long_sub(p, 2), which
    // requires p >= 2; p's nonzero leading digit guarantees that only
    // for k > 1, so re-check the value itself.
    let two = vec![2u64];
    if cmp(&p_words, &two) == std::cmp::Ordering::Less {
        return None;
    }
    let e_words = sub(&p_words, &two);
    let out = modexp_words(n, k, &digits_to_words(a, n), &p_words, &e_words)?;
    words_to_digits(&out, n, k_us)
}
