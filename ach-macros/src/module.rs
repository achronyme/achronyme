//! Implementation of `#[ach_module]`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{parse2, Item, ItemMod, Lit, Meta};

/// Parsed attributes from `#[ach_module(name = "...")]`.
struct ModuleAttrs {
    name: String,
}

fn parse_attrs(attr: TokenStream) -> syn::Result<ModuleAttrs> {
    let meta_list: syn::punctuated::Punctuated<Meta, syn::Token![,]> = syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
        attr,
    )?;

    let mut name = None;

    for meta in &meta_list {
        if let Meta::NameValue(nv) = meta {
            if nv.path.is_ident("name") {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(s), ..
                }) = &nv.value
                {
                    name = Some(s.value());
                }
            }
        }
    }

    let name = name.ok_or_else(|| {
        syn::Error::new(proc_macro2::Span::call_site(), "missing `name = \"...\"`")
    })?;

    Ok(ModuleAttrs { name })
}

/// Info extracted from each `#[ach_native(...)]` function in the module.
struct NativeInfo {
    fn_ident: syn::Ident,
    native_name: String,
    arity: i64,
}

/// Extract `#[ach_native(name = "...", arity = N)]` from a function's attributes.
fn extract_native_attr(attrs: &[syn::Attribute]) -> Option<(String, i64)> {
    for attr in attrs {
        if attr.path().is_ident("ach_native") {
            let mut name = None;
            let mut arity = None;

            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        name = Some(s.value());
                    }
                } else if meta.path.is_ident("arity") {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Int(n) = lit {
                        arity = Some(n.base10_parse::<i64>().unwrap_or(0));
                    }
                }
                Ok(())
            });

            if let (Some(n), Some(a)) = (name, arity) {
                return Some((n, a));
            }
        }
    }
    None
}

pub fn ach_module_impl(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let attrs = parse_attrs(attr)?;
    let module: ItemMod = parse2(item)?;

    let mod_ident = &module.ident;
    let mod_vis = &module.vis;

    // Generate struct name: "math" → MathModule
    let struct_name = {
        let mut chars = attrs.name.chars();
        let capitalized: String = match chars.next() {
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        };
        format_ident!("{}Module", capitalized)
    };

    // Collect native function info from the module items
    let mut natives: Vec<NativeInfo> = Vec::new();

    if let Some((_, ref items)) = module.content {
        for item in items {
            if let Item::Fn(func) = item {
                if let Some((name, arity)) = extract_native_attr(&func.attrs) {
                    natives.push(NativeInfo {
                        fn_ident: func.sig.ident.clone(),
                        native_name: name,
                        arity,
                    });
                }
            }
        }
    }

    // Build the NativeDef entries
    let native_defs: Vec<_> = natives
        .iter()
        .map(|n| {
            let name_str = &n.native_name;
            let fn_ident = &n.fn_ident;
            let arity = n.arity;
            quote! {
                ::vm::module::NativeDef {
                    name: #name_str,
                    func: #mod_ident::#fn_ident,
                    arity: #arity as isize,
                }
            }
        })
        .collect();

    let module_name_str = &attrs.name;

    // Emit the module (with #[ach_native] functions processed by their own macro)
    // plus the generated struct + trait impl
    Ok(quote! {
        #module

        #mod_vis struct #struct_name;

        impl ::vm::module::NativeModule for #struct_name {
            fn name(&self) -> &'static str {
                #module_name_str
            }

            fn natives(&self) -> Vec<::vm::module::NativeDef> {
                vec![
                    #(#native_defs),*
                ]
            }
        }
    })
}
