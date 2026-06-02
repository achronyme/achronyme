use super::*;

fn sample_handle(id: u32, name: &str) -> CircomHandle {
    CircomHandle {
        library_id: id,
        template_name: name.to_string(),
        template_args: vec![2, 4],
    }
}

#[test]
fn alloc_and_get_roundtrips() {
    let mut heap = Heap::new();
    let idx = heap
        .alloc_circom_handle(sample_handle(3, "Poseidon"))
        .expect("alloc should succeed");
    let got = heap.get_circom_handle(idx).expect("should be present");
    assert_eq!(got.library_id, 3);
    assert_eq!(got.template_name, "Poseidon");
    assert_eq!(got.template_args, vec![2, 4]);
}

#[test]
fn alloc_charges_bytes_against_heap_budget() {
    let mut heap = Heap::new();
    let before = heap.bytes_allocated;
    heap.alloc_circom_handle(sample_handle(0, "Sigma")).unwrap();
    assert!(heap.bytes_allocated > before, "bytes_allocated should grow");
}

#[test]
fn import_bulk_replaces_arena_contents() {
    let mut heap = Heap::new();
    heap.import_circom_handles(vec![
        sample_handle(0, "Square"),
        sample_handle(1, "Num2Bits"),
        sample_handle(2, "Poseidon"),
    ]);
    assert_eq!(heap.get_circom_handle(0).unwrap().template_name, "Square");
    assert_eq!(heap.get_circom_handle(1).unwrap().template_name, "Num2Bits");
    assert_eq!(heap.get_circom_handle(2).unwrap().template_name, "Poseidon");
}

#[test]
fn gc_trace_marks_circom_handle_as_leaf() {
    // Allocate a handle, keep only a Value reference to it, run
    // trace against that root, and verify the arena slot was
    // marked (not freed on sweep).
    let mut heap = Heap::new();
    let idx = heap.alloc_circom_handle(sample_handle(7, "Sigma")).unwrap();
    let root = Value::circom_handle(idx);

    heap.trace(vec![root]);
    assert!(heap.circom_handles.is_marked(idx));
    heap.sweep();
    // After sweep the slot must still contain the original data
    // (marked → survived), not the reset placeholder.
    let survived = heap.get_circom_handle(idx).expect("should survive");
    assert_eq!(survived.template_name, "Sigma");
}

#[test]
fn gc_sweep_collects_unmarked_circom_handle() {
    let mut heap = Heap::new();
    let idx = heap
        .alloc_circom_handle(sample_handle(9, "Discarded"))
        .unwrap();
    // Do NOT mark via trace — just sweep. The slot should be
    // marked as free and `get_circom_handle` returns None.
    heap.trace(vec![]);
    heap.sweep();
    assert!(heap.circom_handles.is_free(idx));
    assert!(heap.get_circom_handle(idx).is_none());
}

#[test]
fn recount_live_bytes_includes_circom_handles() {
    let mut heap = Heap::new();
    heap.alloc_circom_handle(sample_handle(0, "Poseidon"))
        .unwrap();
    let total = heap.recount_live_bytes();
    assert!(total > 0);
}
