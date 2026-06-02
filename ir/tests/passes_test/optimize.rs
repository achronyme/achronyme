use ir::passes::optimize;
use ir::types::{Instruction, IrProgram};
use memory::FieldElement;

#[test]
fn optimize_full_pipeline() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(2),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(3),
    });
    // Unused add: 2 + 3 = 5 (will fold, then DCE removes)
    let c = p.fresh_var();
    p.push(Instruction::Add {
        result: c,
        lhs: a,
        rhs: b,
    });

    let before = p.len();
    optimize(&mut p);

    // After fold: 3 Consts. After DCE: all removed (none used).
    assert!(p.len() < before, "optimize should reduce instruction count");
    assert_eq!(p.len(), 0, "all unused consts should be removed");
}
