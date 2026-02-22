#[cfg(test)]
mod tests {
    use crate::value::{I60_MAX, I60_MIN};
    use crate::Value;

    #[test]
    fn test_tagged_int_basics() {
        let v = Value::int(123);
        assert!(v.is_int());
        assert!(!v.is_obj());
        assert_eq!(v.as_int(), Some(123));

        let v_neg = Value::int(-99);
        assert!(v_neg.is_int());
        assert_eq!(v_neg.as_int(), Some(-99));
    }

    #[test]
    fn test_tagged_int_zero() {
        let v = Value::int(0);
        assert!(v.is_int());
        assert_eq!(v.as_int(), Some(0));
    }

    #[test]
    fn test_tagged_int_i60_range() {
        // Max i60
        let v_max = Value::int(I60_MAX);
        assert_eq!(v_max.as_int(), Some(I60_MAX));

        // Min i60
        let v_min = Value::int(I60_MIN);
        assert_eq!(v_min.as_int(), Some(I60_MIN));
    }

    #[test]
    fn test_tagged_int_sign_extension() {
        let v = Value::int(-1);
        assert_eq!(v.as_int(), Some(-1));

        let v2 = Value::int(-42);
        assert_eq!(v2.as_int(), Some(-42));

        let v3 = Value::int(-1000000);
        assert_eq!(v3.as_int(), Some(-1000000));
    }

    #[test]
    fn test_tagged_bools() {
        let t = Value::bool(true);
        let f = Value::bool(false);
        assert!(t.is_bool());
        assert!(f.is_bool());
        assert_eq!(t.as_bool(), Some(true));
        assert_eq!(f.as_bool(), Some(false));
        assert!(!t.is_int());
    }

    #[test]
    fn test_tagged_nil() {
        let n = Value::nil();
        assert!(n.is_nil());
        assert!(!n.is_int());
        assert!(!n.is_bool());
        assert!(n.is_falsey());
    }

    #[test]
    fn test_tagged_handles() {
        let max_handle = u32::MAX;
        let v = Value::string(max_handle);
        assert!(v.is_obj());
        assert!(v.is_string());
        assert_eq!(v.as_handle(), Some(max_handle));

        let v0 = Value::string(0);
        assert!(v0.is_string());
        assert_eq!(v0.as_handle(), Some(0));
    }

    #[test]
    fn test_tagged_layout() {
        // TAG_INT = 0, so int(0) is all zeros
        let v = Value::int(0);
        assert_eq!(v.0, 0);

        // TAG_NIL = 1, nil is just 1 << 60
        let n = Value::nil();
        assert_eq!(n.0, 1u64 << 60);

        // TAG_TRUE = 3
        let t = Value::true_val();
        assert_eq!(t.0, 3u64 << 60);
    }

    #[test]
    fn test_int_not_obj() {
        let v = Value::int(42);
        assert!(!v.is_obj());
        assert!(v.as_handle().is_none());
    }

    #[test]
    fn test_field_is_obj() {
        let v = Value::field(7);
        assert!(v.is_obj());
        assert!(v.is_field());
        assert_eq!(v.as_handle(), Some(7));
    }
}
