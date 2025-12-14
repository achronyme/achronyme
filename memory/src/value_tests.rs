#[cfg(test)]
mod tests {
    use crate::Value;

    #[test]
    fn test_nan_boxing_numbers() {
        let v = Value::number(123.456);
        assert!(v.is_number());
        assert!(!v.is_obj());
        assert_eq!(v.as_number(), Some(123.456));

        // Test Negative
        let v_neg = Value::number(-99.9);
        assert!(v_neg.is_number());
        assert_eq!(v_neg.as_number(), Some(-99.9));
    }

    #[test]
    fn test_nan_canon() {
        // Create a NaN manually
        let my_nan = f64::NAN;
        let v = Value::number(my_nan);
        // Should be a number type, but the value is NaN
        assert!(v.is_number());
        assert!(v.as_number().unwrap().is_nan());

        // Ensure it doesn't look like a TAG
        assert!(!v.is_nil());
        assert!(!v.is_bool());
    }

    #[test]
    fn test_nan_boxing_bools() {
        let t = Value::bool(true);
        let f = Value::bool(false);
        assert!(t.is_bool());
        assert!(f.is_bool());
        assert_eq!(t.as_bool(), Some(true));
        assert_eq!(f.as_bool(), Some(false));
        assert!(!t.is_number());
    }

    #[test]
    fn test_nan_boxing_handles() {
        let max_handle = u32::MAX;
        let v = Value::string(max_handle);
        assert!(v.is_obj());
        assert!(v.is_string());
        assert_eq!(v.as_handle(), Some(max_handle));

        let v0 = Value::string(0);
        assert!(v0.is_string());
        assert_eq!(v0.as_handle(), Some(0));
    }
}
