//! Implementation of `#[ach_native]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, FnArg, ItemFn, Lit, Meta, Pat, ReturnType, Type};

/// Parsed attributes from `#[ach_native(name = "...", arity = N)]`.
struct NativeAttrs {
    name: String,
    arity: i64,
}

fn parse_attrs(attr: TokenStream) -> syn::Result<NativeAttrs> {
    let meta_list: syn::punctuated::Punctuated<Meta, syn::Token![,]> = syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
        attr,
    )?;

    let mut name = None;
    let mut arity = None;

    for meta in &meta_list {
        if let Meta::NameValue(nv) = meta {
            if nv.path.is_ident("name") {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(s), ..
                }) = &nv.value
                {
                    name = Some(s.value());
                }
            } else if nv.path.is_ident("arity") {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: Lit::Int(n), ..
                }) = &nv.value
                {
                    arity = Some(n.base10_parse::<i64>()?);
                } else if let syn::Expr::Unary(syn::ExprUnary {
                    op: syn::UnOp::Neg(_),
                    expr,
                    ..
                }) = &nv.value
                {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: Lit::Int(n), ..
                    }) = expr.as_ref()
                    {
                        arity = Some(-(n.base10_parse::<i64>()?));
                    }
                }
            }
        }
    }

    let name = name.ok_or_else(|| {
        syn::Error::new(proc_macro2::Span::call_site(), "missing `name = \"...\"`")
    })?;
    let arity = arity
        .ok_or_else(|| syn::Error::new(proc_macro2::Span::call_site(), "missing `arity = N`"))?;

    Ok(NativeAttrs { name, arity })
}

/// Detect if a function parameter is `vm: &mut VM` (or `_vm: &mut VM`).
fn is_vm_param(arg: &FnArg) -> bool {
    if let FnArg::Typed(pat_type) = arg {
        if let Type::Reference(r) = pat_type.ty.as_ref() {
            if r.mutability.is_some() {
                if let Type::Path(tp) = r.elem.as_ref() {
                    return tp.path.segments.last().is_some_and(|s| s.ident == "VM");
                }
            }
        }
    }
    false
}

/// Detect if a function parameter is `args: &[Value]`.
fn is_args_slice(arg: &FnArg) -> bool {
    if let FnArg::Typed(pat_type) = arg {
        if let Type::Reference(r) = pat_type.ty.as_ref() {
            if r.mutability.is_none() {
                if let Type::Slice(s) = r.elem.as_ref() {
                    if let Type::Path(tp) = s.elem.as_ref() {
                        return tp.path.segments.last().is_some_and(|s| s.ident == "Value");
                    }
                }
            }
        }
    }
    false
}

/// Detect if a return type is `Result<..., RuntimeError>` (or similar).
fn is_result_return(ret: &ReturnType) -> bool {
    if let ReturnType::Type(_, ty) = ret {
        if let Type::Path(tp) = ty.as_ref() {
            return tp.path.segments.last().is_some_and(|s| s.ident == "Result");
        }
    }
    false
}

/// Check if the function signature matches NativeFn exactly:
/// `fn(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError>`
fn is_passthrough(func: &ItemFn) -> bool {
    let inputs = &func.sig.inputs;
    if inputs.len() != 2 {
        return false;
    }
    is_vm_param(&inputs[0]) && is_args_slice(&inputs[1]) && is_result_return(&func.sig.output)
}

pub fn ach_native_impl(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let attrs = parse_attrs(attr)?;
    let func: ItemFn = parse2(item)?;

    let fn_name = &func.sig.ident;
    let vis = &func.vis;
    let fn_attrs: Vec<_> = func.attrs.iter().collect();
    let native_name = &attrs.name;

    // Passthrough: signature already matches NativeFn
    if is_passthrough(&func) {
        // Emit the function as-is — it's already a valid NativeFn
        return Ok(quote! { #func });
    }

    // Determine which params are args vs vm
    let inputs = &func.sig.inputs;
    let has_vm = inputs.first().is_some_and(is_vm_param);

    // Collect the "real" argument params (everything except vm)
    let arg_params: Vec<_> = if has_vm {
        inputs.iter().skip(1).collect()
    } else {
        inputs.iter().collect()
    };

    let arg_count = arg_params.len();
    let result_return = is_result_return(&func.sig.output);

    // Build the inner function's params and types
    let mut inner_param_names = Vec::new();
    let mut inner_param_types = Vec::new();

    for (i, param) in arg_params.iter().enumerate() {
        if let FnArg::Typed(pat_type) = param {
            let name = if let Pat::Ident(pi) = pat_type.pat.as_ref() {
                pi.ident.clone()
            } else {
                syn::Ident::new(&format!("arg_{i}"), proc_macro2::Span::call_site())
            };
            inner_param_names.push(name);
            inner_param_types.push(pat_type.ty.as_ref().clone());
        }
    }

    // Generate argument extraction from args slice
    let extractions: Vec<_> = inner_param_names
        .iter()
        .zip(inner_param_types.iter())
        .enumerate()
        .map(|(i, (name, ty))| {
            let idx = syn::Index::from(i);
            let arg_pos = i + 1;
            quote! {
                let #name: #ty = <#ty as ::memory::FromValue>::from_value(args[#idx])
                    .map_err(|e| ::vm::error::RuntimeError::TypeMismatch(
                        format!("{}() argument {}: {}", #native_name, #arg_pos, e)
                    ))?;
            }
        })
        .collect();

    // Arity check
    let arity_check = if attrs.arity >= 0 {
        let expected = arg_count;
        let msg = format!(
            "{}() takes exactly {} argument{}",
            native_name,
            expected,
            if expected == 1 { "" } else { "s" }
        );
        quote! {
            if args.len() != #expected {
                return Err(::vm::error::RuntimeError::ArityMismatch(#msg.into()));
            }
        }
    } else {
        quote! {} // variadic — no check
    };

    // Inner function body
    let inner_body = &func.block;
    let inner_ret = &func.sig.output;

    // Build the inner fn params (for the inner call)
    let inner_sig_params: Vec<_> = func.sig.inputs.iter().collect();

    // Call to inner
    let inner_args: Vec<_> = if has_vm {
        let mut v = vec![quote! { vm }];
        v.extend(inner_param_names.iter().map(|n| quote! { #n }));
        v
    } else {
        inner_param_names.iter().map(|n| quote! { #n }).collect()
    };

    let call_and_return = if result_return {
        // Inner returns Result — need to convert Ok value with IntoValue
        // But if return type is Result<Value, _>, no conversion needed
        quote! {
            let result = __inner(#(#inner_args),*)?;
            Ok(::memory::IntoValue::into_value(result))
        }
    } else {
        quote! {
            let result = __inner(#(#inner_args),*);
            Ok(::memory::IntoValue::into_value(result))
        }
    };

    let output = quote! {
        #(#fn_attrs)*
        #vis fn #fn_name(
            vm: &mut ::vm::machine::VM,
            args: &[::memory::Value],
        ) -> Result<::memory::Value, ::vm::error::RuntimeError> {
            #[inline(always)]
            fn __inner(#(#inner_sig_params),*) #inner_ret
                #inner_body

            #arity_check
            #(#extractions)*
            #call_and_return
        }
    };

    Ok(output)
}
