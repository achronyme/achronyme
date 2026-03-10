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

#[test]
fn test_gc_lock_prevents_request() {
    let mut heap = Heap::new();
    heap.next_gc_threshold = 0; // Force threshold to be always exceeded

    // Without lock: alloc should set request_gc
    heap.alloc_string("hello".into());
    assert!(heap.request_gc);
    heap.request_gc = false;

    // With lock: alloc should NOT set request_gc
    heap.lock_gc();
    assert!(heap.is_gc_locked());
    heap.alloc_string("world".into());
    assert!(!heap.request_gc);

    // After unlock: deferred check_gc() fires immediately
    heap.unlock_gc();
    assert!(!heap.is_gc_locked());
    assert!(
        heap.request_gc,
        "unlock_gc should call check_gc for deferred threshold"
    );
}

#[test]
fn test_gc_lock_nesting() {
    let mut heap = Heap::new();
    heap.next_gc_threshold = 0;

    // Nested locks: inner unlock should NOT release the lock
    heap.lock_gc();
    heap.lock_gc();
    assert!(heap.is_gc_locked());

    heap.unlock_gc(); // depth 2 → 1
    assert!(
        heap.is_gc_locked(),
        "inner unlock should not release outer lock"
    );
    heap.alloc_string("test".into());
    assert!(!heap.request_gc, "should still be locked at depth 1");

    heap.unlock_gc(); // depth 1 → 0, triggers check_gc
    assert!(!heap.is_gc_locked());
    assert!(
        heap.request_gc,
        "outermost unlock should catch deferred threshold"
    );
}

#[test]
fn test_gc_lock_default_state() {
    let heap = Heap::new();
    assert!(!heap.is_gc_locked());
}

#[test]
fn test_gc_lock_survives_sweep() {
    let mut heap = Heap::new();

    // Lock, then run a full GC cycle — lock should remain held
    heap.lock_gc();
    heap.alloc_string("survivor".into());
    heap.trace(vec![]);
    heap.sweep();
    assert!(heap.is_gc_locked(), "sweep should not affect gc lock state");
    heap.unlock_gc();
    assert!(!heap.is_gc_locked());
}

#[test]
#[should_panic(expected = "unlock_gc called without matching lock_gc")]
fn test_gc_unlock_without_lock_panics() {
    let mut heap = Heap::new();
    heap.unlock_gc(); // should panic in debug mode
}

#[test]
fn test_heap_limit_flag_set_on_exceed() {
    let mut heap = Heap::new();
    heap.max_heap_bytes = 100;
    for _ in 0..20 {
        heap.alloc_string("hello world".to_string());
    }
    assert!(heap.heap_limit_exceeded);
}

#[test]
fn test_heap_limit_not_set_when_under() {
    let mut heap = Heap::new();
    // default usize::MAX
    heap.alloc_string("hello".into());
    assert!(!heap.heap_limit_exceeded);
}

#[test]
fn test_heap_limit_ignores_gc_lock() {
    let mut heap = Heap::new();
    heap.max_heap_bytes = 10;
    heap.lock_gc();
    heap.alloc_string("this exceeds the limit".to_string());
    assert!(heap.heap_limit_exceeded);
    heap.unlock_gc();
}

#[test]
fn test_heap_limit_default_no_limit() {
    let heap = Heap::new();
    assert_eq!(heap.max_heap_bytes, usize::MAX);
    assert!(!heap.heap_limit_exceeded);
}
