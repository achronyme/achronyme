use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::native::NativeObj;
use memory::{Heap, Value};
use std::collections::HashMap;

use super::frame::CallFrame;
use super::interpreter::InterpreterOps;
use super::native::NativeRegistry;
use super::prove::{ProveHandler, VerifyHandler};
use super::upvalue::UpvalueOps;

/// The Virtual Machine struct
pub struct VM {
    pub heap: Heap,
    // SAFETY: Box<[Value]> guarantees stable address (no reallocation)
    pub stack: Box<[Value]>,
    pub frames: Vec<CallFrame>,
    pub globals: Vec<GlobalEntry>,
    pub interner: HashMap<String, u32>,
    pub natives: Vec<NativeObj>,

    /// Function prototypes (handles) for O(1) CLOSURE lookup
    pub prototypes: Vec<u32>,

    /// Head of the linked list of open upvalues (Index into Heap.upvalues)
    pub open_upvalues: Option<u32>,

    /// If true, GC will run on every possible occasion (for testing)
    pub stress_mode: bool,

    // Passive Debug Symbols (Sidecar)
    pub debug_symbols: Option<HashMap<u16, String>>,

    /// Handler for `prove { }` blocks (injected by CLI or host)
    pub prove_handler: Option<Box<dyn ProveHandler>>,

    /// Handler for `verify_proof()` calls (injected by CLI or host)
    pub verify_handler: Option<Box<dyn VerifyHandler>>,

    /// Location of the last runtime error: (function_name, line_number).
    /// Set by interpret() before returning Err.
    pub last_error_location: Option<(String, u32)>,
}

pub const STACK_MAX: usize = 65_536;
pub const MAX_FRAMES: usize = 4096;

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

impl VM {
    /// Create a new VM instance with bootstrapped native functions
    pub fn new() -> Self {
        // Pre-allocate fixed-size stack and PIN it via Box
        let stack = vec![Value::nil(); STACK_MAX].into_boxed_slice();

        let mut vm = Self {
            heap: Heap::new(),
            stack,
            frames: Vec::with_capacity(64),
            globals: Vec::with_capacity(64),
            interner: HashMap::new(),
            natives: Vec::new(),
            prototypes: Vec::new(),
            open_upvalues: None,
            stress_mode: false,
            debug_symbols: None,
            prove_handler: None,
            verify_handler: None,
            last_error_location: None,
        };

        // Bootstrap native functions
        vm.bootstrap_natives();

        vm
    }

    /// Soft Reset: Clears stack and frames for REPL/Running new script.
    /// CRITICAL: Must close all open upvalues to prevent them from pointing to dead stack slots.
    pub fn reset(&mut self) {
        // 1. Close ALL open upvalues (stack index 0 = everything)
        // Ignore errors here — reset drains the upvalue list regardless.
        let _ = self.close_upvalues(0);

        // 2. Clear Runtime State
        self.frames.clear();
        self.open_upvalues = None;

        // 3. Zero stack in debug builds to prevent stale values leaking
        #[cfg(debug_assertions)]
        self.stack.fill(Value::nil());
    }

    /// Capture the current execution location for error reporting.
    fn capture_error_location(&mut self) {
        if let Some(frame) = self.frames.last() {
            let ip = if frame.ip > 0 { frame.ip - 1 } else { 0 };
            if let Some(closure) = self.heap.get_closure(frame.closure) {
                if let Some(func) = self.heap.get_function(closure.function) {
                    let line = func.line_info.get(ip).copied().unwrap_or(0);
                    if line > 0 {
                        self.last_error_location = Some((func.name.clone(), line));
                    }
                }
            }
        }
    }

    /// Main interpretation loop
    pub fn interpret(&mut self) -> Result<(), RuntimeError> {
        match self.interpret_inner() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.capture_error_location();
                Err(e)
            }
        }
    }

    /// Sidecar Loader: Parses debug symbols from raw bytes
    pub fn load_debug_section(&mut self, bytes: &[u8]) {
        if bytes.len() < 4 {
            return; // Not enough bytes for Header + Count
        }

        let mut cursor = 0;

        // 1. Check Magic (0xDB 0x67)
        if bytes[cursor] != 0xDB || bytes[cursor + 1] != 0x67 {
            return; // Invalid or missing section
        }
        cursor += 2;

        // 2. Read Count
        let count = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        cursor += 2;

        let mut map = HashMap::new();

        for _ in 0..count {
            if cursor + 4 > bytes.len() {
                break; // Truncated
            }

            // Global Index
            let global_idx = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
            cursor += 2;

            // Name Length
            let name_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;

            if cursor + name_len > bytes.len() {
                break; // Truncated name
            }

            // Name Bytes
            let name_bytes = &bytes[cursor..cursor + name_len];
            cursor += name_len;

            if let Ok(name) = std::str::from_utf8(name_bytes) {
                map.insert(global_idx, name.to_string());
            }
        }

        self.debug_symbols = Some(map);
    }
}
