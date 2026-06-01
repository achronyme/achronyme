use super::{
    state::{ArrayBuf, Cell},
    *,
};

pub(super) fn load_array<F: FieldBackend>(
    buf: &ArrayBuf<F>,
    idx: u64,
) -> Result<Cell<F>, ArtikError> {
    let len = buf.len();
    if idx >= len as u64 {
        return Err(ArtikError::ArrayIndexOutOfBounds { idx, len });
    }
    let i = idx as usize;
    Ok(match buf {
        ArrayBuf::Field(v) => Cell::Field(v[i]),
        ArrayBuf::Int { data, .. } => Cell::Int(data[i]),
    })
}

pub(super) fn store_array<F: FieldBackend>(
    buf: &mut ArrayBuf<F>,
    idx: u64,
    val: Cell<F>,
    val_reg: u32,
) -> Result<(), ArtikError> {
    let len = buf.len();
    if idx >= len as u64 {
        return Err(ArtikError::ArrayIndexOutOfBounds { idx, len });
    }
    let i = idx as usize;
    match (buf, val) {
        (ArrayBuf::Field(v), Cell::Field(fe)) => {
            v[i] = fe;
            Ok(())
        }
        (ArrayBuf::Int { w, data }, Cell::Int(raw)) => {
            data[i] = raw & w.mask();
            Ok(())
        }
        (_, Cell::Undef) => Err(ArtikError::UndefinedRegister { reg: val_reg }),
        _ => Err(ArtikError::WrongCellKind { reg: val_reg }),
    }
}
