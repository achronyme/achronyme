use crate::functions::FunctionRegistry;
use crate::unary_math_fn;
use achronyme_types::value::Value;
use achronyme_types::Environment;

pub fn register_functions(registry: &mut FunctionRegistry) {
    registry.register("exp", exp, 1);
    registry.register("ln", ln, 1);
    registry.register("log", ln, 1);
    registry.register("log10", log10, 1);
    registry.register("log2", log2, 1);
    registry.register("sqrt", sqrt, 1);
    registry.register("cbrt", cbrt, 1);
    registry.register("pow", pow, 2);
}

// Implementations

fn exp(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    unary_math_fn!("exp", f64::exp, &args[0])
}

fn ln(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    unary_math_fn!("ln", f64::ln, &args[0])
}

fn log10(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    unary_math_fn!("log10", f64::log10, &args[0])
}

fn log2(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    unary_math_fn!("log2", f64::log2, &args[0])
}

fn sqrt(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    match &args[0] {
        Value::Number(x) => {
            if *x < 0.0 {
                // Return complex number for negative reals: sqrt(-x) = i*sqrt(x)
                let magnitude = (-*x).sqrt();
                Ok(Value::Complex(achronyme_types::complex::Complex::new(
                    0.0, magnitude,
                )))
            } else {
                Ok(Value::Number(x.sqrt()))
            }
        }
        Value::Complex(c) => {
            // Complex square root
            let result = c.sqrt();
            Ok(Value::Complex(result))
        }
        Value::Tensor(t) => {
            // For tensors, apply element-wise, returning complex for negative values
            let data: Vec<Value> = t
                .data()
                .iter()
                .map(|x| {
                    if *x < 0.0 {
                        Value::Complex(achronyme_types::complex::Complex::new(0.0, (-*x).sqrt()))
                    } else {
                        Value::Number(x.sqrt())
                    }
                })
                .collect();
            Ok(Value::Vector(data))
        }
        Value::Vector(v) => {
            let results: Result<Vec<Value>, String> = v
                .iter()
                .map(|val| sqrt(&[val.clone()], _env))
                .collect();
            Ok(Value::Vector(results?))
        }
        _ => Err("sqrt() requires a number, complex, or numeric array".to_string()),
    }
}

fn cbrt(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    unary_math_fn!("cbrt", f64::cbrt, &args[0])
}

fn pow(args: &[Value], _env: &mut Environment) -> Result<Value, String> {
    match (&args[0], &args[1]) {
        (Value::Number(x), Value::Number(y)) => Ok(Value::Number(x.powf(*y))),
        _ => Err("pow() requires two numbers".to_string()),
    }
}
