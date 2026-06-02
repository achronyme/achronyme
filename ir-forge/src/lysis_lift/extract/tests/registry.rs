use super::*;

// -----------------------------------------------------------------
// TemplateRegistry
// -----------------------------------------------------------------

#[test]
fn registry_allocates_unique_ids() {
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let a = reg.allocate_fresh().unwrap();
    let b = reg.allocate_fresh().unwrap();
    let c = reg.allocate_fresh().unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(a.0, 0);
    assert_eq!(b.0, 1);
    assert_eq!(c.0, 2);
}

#[test]
fn registry_iter_is_sorted_by_id() {
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let skel = SymbolicTree::<Bn254Fr>::new();
    let caps = BTreeSet::new();
    let a = extract_template(&skel, &caps, &mut reg).unwrap();
    let b = extract_template(&skel, &caps, &mut reg).unwrap();
    let c = extract_template(&skel, &caps, &mut reg).unwrap();
    let ids: Vec<_> = reg.iter().map(|(id, _)| id.0).collect();
    assert_eq!(ids, vec![a.id.0, b.id.0, c.id.0]);
}
