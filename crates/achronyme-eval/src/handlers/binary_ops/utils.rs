use achronyme_types::value::Value;

/// Convert a Value to its string representation for concatenation
pub fn value_to_string(value: &Value) -> String {
    match value {
        Value::Number(n) => {
            // Format numbers nicely: remove trailing zeros and decimal point if integer
            if n.fract() == 0.0 && n.is_finite() {
                format!("{:.0}", n)
            } else {
                n.to_string()
            }
        }
        Value::Boolean(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Complex(c) => {
            if c.im == 0.0 {
                format!("{}", c.re)
            } else if c.re == 0.0 {
                format!("{}i", c.im)
            } else {
                format!("{}+{}i", c.re, c.im)
            }
        }
        Value::Vector(v) => {
            let elements: Vec<String> = v.iter().map(value_to_string).collect();
            format!("[{}]", elements.join(", "))
        }
        Value::Tensor(t) => format!("{:?}", t),
        Value::ComplexTensor(ct) => format!("{:?}", ct),
        Value::Function(_) => "<function>".to_string(),
        Value::Record(map) => {
            let fields: Vec<String> = map.iter()
                .map(|(k, v)| format!("{}: {}", k, value_to_string(v)))
                .collect();
            format!("{{{}}}", fields.join(", "))
        }
        Value::Edge { from, to, directed, .. } => {
            let arrow = if *directed { " -> " } else { " <> " };
            format!("{}{}{}", from, arrow, to)
        }
        Value::TailCall(_) => "<tail-call>".to_string(),
        Value::EarlyReturn(_) => "<early-return>".to_string(),
        Value::MutableRef(r) => {
            let borrowed = r.borrow();
            value_to_string(&borrowed)
        }
        Value::Null => "null".to_string(),
        Value::Generator(_) => "<generator>".to_string(),
        Value::GeneratorYield(_) => "<generator-yield>".to_string(),
        Value::Error { message, kind, .. } => {
            match kind {
                Some(k) => format!("Error({}: {})", k, message),
                None => format!("Error({})", message),
            }
        }
        Value::LoopBreak(_) => "<loop-break>".to_string(),
        Value::LoopContinue => "<loop-continue>".to_string(),
    }
}
