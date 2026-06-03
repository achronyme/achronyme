use super::lc_map::{LcMap, LcMapEntry, LcMapSegment, LcTag, UsedSsaSet};
use super::*;
use ir::types::{Instruction, IrProgram, SsaVar, Visibility as IrVisibility};

mod cache_modes;
mod maps;
mod origins;
mod streaming_intern;
