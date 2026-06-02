/// Visibility qualifier for circuit/prove parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "Public"),
            Visibility::Witness => write!(f, "Witness"),
        }
    }
}

/// Base type for type annotations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseType {
    Field,
    Bool,
    Int,
    String,
}

impl std::fmt::Display for BaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseType::Field => write!(f, "Field"),
            BaseType::Bool => write!(f, "Bool"),
            BaseType::Int => write!(f, "Int"),
            BaseType::String => write!(f, "String"),
        }
    }
}

impl BaseType {
    /// Returns true if this type is valid in circuit/prove context (R1CS/Plonkish).
    pub fn is_circuit_type(&self) -> bool {
        matches!(self, BaseType::Field | BaseType::Bool)
    }
}

/// A type annotation for circuit variables, prove parameters, and function parameters.
///
/// ```
/// use achronyme_parser::ast::{TypeAnnotation, BaseType, Visibility};
///
/// let t = TypeAnnotation::field();
/// assert_eq!(format!("{t}"), "Field");
///
/// let arr = TypeAnnotation::bool_array(4);
/// assert_eq!(format!("{arr}"), "Bool[4]");
///
/// let pub_field = TypeAnnotation::public();
/// assert_eq!(format!("{pub_field}"), "Public");
///
/// let wit_arr = TypeAnnotation::new(Some(Visibility::Witness), BaseType::Field, Some(3));
/// assert_eq!(format!("{wit_arr}"), "Witness Field[3]");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub visibility: Option<Visibility>,
    pub base: BaseType,
    pub array_size: Option<usize>,
}

impl TypeAnnotation {
    pub fn new(visibility: Option<Visibility>, base: BaseType, array_size: Option<usize>) -> Self {
        Self {
            visibility,
            base,
            array_size,
        }
    }

    pub fn field() -> Self {
        Self {
            visibility: None,
            base: BaseType::Field,
            array_size: None,
        }
    }

    pub fn bool() -> Self {
        Self {
            visibility: None,
            base: BaseType::Bool,
            array_size: None,
        }
    }

    pub fn field_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Field,
            array_size: Some(n),
        }
    }

    pub fn bool_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Bool,
            array_size: Some(n),
        }
    }

    pub fn int() -> Self {
        Self {
            visibility: None,
            base: BaseType::Int,
            array_size: None,
        }
    }

    pub fn string() -> Self {
        Self {
            visibility: None,
            base: BaseType::String,
            array_size: None,
        }
    }

    pub fn int_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Int,
            array_size: Some(n),
        }
    }

    pub fn string_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::String,
            array_size: Some(n),
        }
    }

    pub fn public() -> Self {
        Self {
            visibility: Some(Visibility::Public),
            base: BaseType::Field,
            array_size: None,
        }
    }

    pub fn witness() -> Self {
        Self {
            visibility: Some(Visibility::Witness),
            base: BaseType::Field,
            array_size: None,
        }
    }

    /// Returns the array size if this is an array type.
    pub fn array_len(&self) -> Option<usize> {
        self.array_size
    }

    /// Returns true if this is an array type.
    pub fn is_array(&self) -> bool {
        self.array_size.is_some()
    }
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vis) = &self.visibility {
            write!(f, "{vis}")?;
            // Only show base type if it's Bool or if there's an array size
            // (Public alone = Public Field, so skip "Field" for brevity)
            if self.base == BaseType::Bool || self.array_size.is_some() {
                write!(f, " {}", self.base)?;
            }
        } else {
            write!(f, "{}", self.base)?;
        }
        if let Some(n) = self.array_size {
            write!(f, "[{n}]")?;
        }
        Ok(())
    }
}

/// A function parameter with an optional type annotation.
///
/// ```
/// use achronyme_parser::ast::TypedParam;
///
/// let p = TypedParam { name: "x".into(), type_ann: None };
/// assert_eq!(p.name, "x");
/// assert!(p.type_ann.is_none());
/// ```
#[derive(Clone, Debug)]
pub struct TypedParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,
}
