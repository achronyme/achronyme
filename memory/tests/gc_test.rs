use memory::Heap;
use memory::Value;

#[test]
fn test_gc_alloc_reuse_string() {
    let mut heap = Heap::new();

    let s1 = "Hello".to_string();
    let idx1 = heap.alloc_string(s1);

    // 1. Mark nothing.
    // 2. Sweep.
    // 3. idx1 should be free.

    heap.trace(vec![]); // trace nothing
    heap.sweep();

    // Check internal state: free_indices should have idx1
    assert!(heap.is_string_free(idx1));

    // Alloc new string, should reuse idx1
    let s2 = "World".to_string();
    let idx2 = heap.alloc_string(s2);

    assert_eq!(idx1, idx2, "Heap should reuse freed index");
    assert_eq!(heap.get_string(idx2).unwrap(), "World");
}

#[test]
fn test_gc_cycle_collection() {
    let mut heap = Heap::new();

    // Create two lists
    let a_idx = heap.alloc_list(vec![]);
    let b_idx = heap.alloc_list(vec![]);
    let val_a = Value::list(a_idx);
    let val_b = Value::list(b_idx);

    // Make them cycle: A -> B, B -> A
    if let Some(l) = heap.get_list_mut(a_idx) {
        l.push(val_b);
    }
    if let Some(l) = heap.get_list_mut(b_idx) {
        l.push(val_a);
    }

    // Case 1: Root holds A. Both should be alive.
    heap.trace(vec![val_a]);
    // Verify both marked
    assert!(heap.is_list_marked(a_idx));
    assert!(heap.is_list_marked(b_idx));

    // Reset for next pass (Sweep does this, but we want to test sweep)
    // Actually sweep clears marks.
    heap.sweep();

    // After sweep (with valid roots), they should still be alive (not in free list).
    assert!(!heap.is_list_free(a_idx));
    assert!(!heap.is_list_free(b_idx));

    // Case 2: No roots. Cycle should be collected.
    heap.trace(vec![]); // No roots
    heap.sweep();

    assert!(heap.is_list_free(a_idx));
    assert!(heap.is_list_free(b_idx));
}
