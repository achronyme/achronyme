use super::*;

#[test]
fn template_tables_are_indexed_by_id_with_binary_offset_ranges() {
    let template = Template {
        id: 7,
        frame_size: 3,
        n_params: 1,
        body_offset: 10,
        body_len: 25,
    };
    let program = offset_program(&[0, 10, 20, 30, 40], vec![template]);

    let (templates, ranges) = build_template_tables(&program);

    assert_eq!(templates[7], Some(template));
    assert_eq!(ranges[7], Some((1, 4)));
}

#[test]
fn template_tables_preserve_first_declared_owner_for_overlaps() {
    let outer = Template {
        id: 1,
        frame_size: 3,
        n_params: 0,
        body_offset: 10,
        body_len: 30,
    };
    let inner = Template {
        id: 2,
        frame_size: 3,
        n_params: 0,
        body_offset: 20,
        body_len: 10,
    };
    let program = offset_program(&[0, 10, 20, 30, 40], vec![outer, inner]);

    let (_, ranges) = build_template_tables(&program);

    assert_eq!(ranges[1], Some((1, 4)));
    assert_eq!(ranges[2], None);
}

#[test]
fn template_lookup_keeps_first_declared_metadata_for_duplicate_ids() {
    let first = Template {
        id: 9,
        frame_size: 3,
        n_params: 0,
        body_offset: 10,
        body_len: 10,
    };
    let second = Template {
        id: 9,
        frame_size: 200,
        n_params: 0,
        body_offset: 30,
        body_len: 10,
    };
    let program = offset_program(&[0, 10, 20, 30, 40], vec![first, second]);

    let (templates, ranges) = build_template_tables(&program);

    assert_eq!(templates[9], Some(first));
    assert_eq!(ranges[9], Some((1, 4)));
}

#[test]
fn offset_index_helpers_match_exact_and_lower_bound_semantics() {
    let program = offset_program(&[0, 10, 20, 30], Vec::new());

    assert_eq!(exact_offset_idx(&program, 20), Some(2));
    assert_eq!(exact_offset_idx(&program, 25), None);
    assert_eq!(lower_bound_offset_idx(&program, 25), 3);
    assert_eq!(lower_bound_offset_idx(&program, 99), program.body.len());
}
