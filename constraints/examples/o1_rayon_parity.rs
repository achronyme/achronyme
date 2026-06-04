use constraints::r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable};
use constraints::r1cs_optimize::optimize_linear;
use memory::{Bn254Fr, FieldElement};

type F = Bn254Fr;
type Fe = FieldElement<F>;
type Lc = LinearCombination<F>;

fn lc_var(var: Variable) -> Lc {
    Lc::from_variable(var)
}

fn lc_const(n: u64) -> Lc {
    Lc::from_constant(Fe::from_u64(n))
}

fn add_lc(acc: &mut u64, lc: &Lc) {
    let mut terms = lc.clone().simplify().into_terms();
    terms.sort_unstable_by_key(|(var, _)| var.index());
    add_usize(acc, terms.len());
    for (var, coeff) in terms {
        add_usize(acc, var.index());
        for byte in coeff.to_le_bytes() {
            add_byte(acc, byte);
        }
    }
}

fn add_constraint(acc: &mut u64, c: &Constraint<F>) {
    add_lc(acc, &c.a);
    add_lc(acc, &c.b);
    add_lc(acc, &c.c);
}

fn add_usize(acc: &mut u64, value: usize) {
    for byte in value.to_le_bytes() {
        add_byte(acc, byte);
    }
}

fn add_byte(acc: &mut u64, byte: u8) {
    *acc ^= byte as u64;
    *acc = acc.wrapping_mul(0x100000001b3);
}

fn build_fixture() -> (Vec<Constraint<F>>, usize) {
    let mut cs = ConstraintSystem::<F>::new();
    let public = cs.alloc_input();
    let mut vars = Vec::new();
    for _ in 0..2_048 {
        vars.push(cs.alloc_witness());
    }

    for chunk in vars.chunks_exact(4) {
        cs.enforce_equal(lc_var(chunk[0]), lc_var(chunk[1]));
        cs.enforce_equal(lc_var(chunk[2]), lc_var(chunk[3]));
        cs.enforce(lc_var(chunk[1]), lc_var(chunk[3]), lc_var(public));
        cs.enforce(lc_var(chunk[3]), lc_var(chunk[1]), lc_var(public));
    }
    for (idx, pair) in vars.chunks_exact(2).enumerate() {
        let lhs = lc_var(pair[0]) + lc_const((idx as u64 % 7) + 1);
        cs.enforce_equal(lhs, lc_var(pair[1]));
    }
    for pair in vars.windows(2).take(600) {
        let lhs = lc_var(pair[0]) + lc_const(3);
        cs.enforce_equal(lhs, lc_var(pair[1]));
    }

    (cs.constraints().to_vec(), cs.num_pub_inputs())
}

fn main() {
    let (mut constraints, public_inputs) = build_fixture();
    let (subs, stats) = optimize_linear(&mut constraints, public_inputs);

    let mut acc = 0xcbf29ce484222325;
    add_usize(&mut acc, stats.constraints_before);
    add_usize(&mut acc, stats.constraints_after);
    add_usize(&mut acc, stats.variables_eliminated);
    add_usize(&mut acc, stats.duplicates_removed);
    add_usize(&mut acc, stats.trivial_removed);
    add_usize(&mut acc, stats.rounds);
    for (linear, newly_linear) in stats.round_details {
        add_usize(&mut acc, linear);
        add_usize(&mut acc, newly_linear);
    }
    for c in &constraints {
        add_constraint(&mut acc, c);
    }
    for (var, lc) in &subs {
        add_usize(&mut acc, *var);
        add_lc(&mut acc, lc);
    }

    println!("{acc:016x}");
}
