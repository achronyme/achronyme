use egui::Ui;
use std::cell::RefCell;

// We use a thread-local raw pointer to allow Achronyme native functions
// to access the current egui::Ui context without passing generic parameters
// through the entire VM stack.
//
// SAFETY: This implies that the VM and the GUI render loop are running on the
// same thread (which is true for LocalSet architecture).
thread_local! {
    static CURRENT_UI: RefCell<Option<*mut Ui>> = RefCell::new(None);
}

/// Executes a closure with the given UI context active.
/// Used by the `runner` logic.
pub fn with_ui_context<F, R>(ui: &mut Ui, f: F) -> R
where
    F: FnOnce() -> R,
{
    // Save previous context
    let prev = CURRENT_UI.with(|cell| *cell.borrow());

    // Set new context
    CURRENT_UI.with(|cell| {
        *cell.borrow_mut() = Some(ui as *mut Ui);
    });

    let result = f();

    // Restore previous context
    CURRENT_UI.with(|cell| {
        *cell.borrow_mut() = prev;
    });

    result
}

/// Retrieves the current active UI context.
/// Returns None if called outside a render loop.
pub fn get_ui<'a>() -> Option<&'a mut Ui> {
    CURRENT_UI.with(|cell| match *cell.borrow() {
        Some(ptr) => unsafe { Some(&mut *ptr) },
        None => None,
    })
}
