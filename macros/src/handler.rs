use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse2, FnArg, GenericArgument, GenericParam, ItemFn, Lifetime, LifetimeParam, PathArguments,
    ReturnType, Type,
};

/// Rewrite the top-level reference in a parameter type to use `'a`.
fn inject_lifetime(arg: &FnArg) -> FnArg {
    match arg {
        FnArg::Typed(pat_type) => {
            let ty = &*pat_type.ty;
            if let Type::Reference(type_ref) = ty {
                let mut new_ref = type_ref.clone();
                new_ref.lifetime = Some(Lifetime::new("'a", proc_macro2::Span::call_site()));
                let new_ty = Type::Reference(new_ref);
                let mut new_pat_type = pat_type.clone();
                new_pat_type.ty = Box::new(new_ty);
                FnArg::Typed(new_pat_type)
            } else {
                arg.clone()
            }
        }
        other => other.clone(),
    }
}

/// Check that the first parameter is `&mut App<S>` (a mutable reference to App with one generic argument).
fn is_valid_app_param(arg: &FnArg) -> bool {
    if let FnArg::Typed(pat_type) = arg {
        if let Type::Reference(type_ref) = &*pat_type.ty {
            if type_ref.mutability.is_some() {
                if let Type::Path(type_path) = &*type_ref.elem {
                    let segs = &type_path.path.segments;
                    if segs.len() == 1 && segs[0].ident == "App" {
                        return matches!(
                            segs[0].arguments,
                            PathArguments::AngleBracketed(_) | PathArguments::None
                        );
                    }
                }
            }
        }
    }
    false
}

/// Check that the second parameter is `&[u8]` (a shared reference to a byte slice).
fn is_valid_bytes_param(arg: &FnArg) -> bool {
    if let FnArg::Typed(pat_type) = arg {
        if let Type::Reference(type_ref) = &*pat_type.ty {
            if type_ref.mutability.is_none() {
                if let Type::Slice(slice_type) = &*type_ref.elem {
                    if let Type::Path(type_path) = &*slice_type.elem {
                        let segs = &type_path.path.segments;
                        return segs.len() == 1
                            && segs[0].ident == "u8"
                            && segs[0].arguments.is_none();
                    }
                }
            }
        }
    }
    false
}

/// Check that the return type is `Vec<u8>`.
fn is_valid_return_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        let segs = &type_path.path.segments;
        if segs.len() == 1 && segs[0].ident == "Vec" {
            if let PathArguments::AngleBracketed(args) = &segs[0].arguments {
                if args.args.len() == 1 {
                    if let GenericArgument::Type(Type::Path(inner)) = &args.args[0] {
                        let inner_segs = &inner.path.segments;
                        return inner_segs.len() == 1
                            && inner_segs[0].ident == "u8"
                            && inner_segs[0].arguments.is_none();
                    }
                }
            }
        }
    }
    false
}

pub fn handler_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new_spanned(attr, "#[handler] does not take any arguments")
            .to_compile_error();
    }

    let input: ItemFn = match parse2(item) {
        Ok(f) => f,
        Err(e) => return e.to_compile_error(),
    };

    // Validate that the function is async
    if input.sig.asyncness.is_none() {
        return syn::Error::new_spanned(&input.sig.fn_token, "#[handler] requires an async fn")
            .to_compile_error();
    }

    // Validate that it has exactly 2 parameters
    if input.sig.inputs.len() != 2 {
        return syn::Error::new_spanned(
            &input.sig.inputs,
            "#[handler] function must have exactly 2 parameters: (&mut App<S>, &[u8])",
        )
        .to_compile_error();
    }

    let params: Vec<_> = input.sig.inputs.iter().collect();

    // Validate the first parameter is &mut App<S>
    if !is_valid_app_param(params[0]) {
        return syn::Error::new_spanned(
            params[0],
            "#[handler] first parameter must be `&mut App<S>`",
        )
        .to_compile_error();
    }

    // Validate the second parameter is &[u8]
    if !is_valid_bytes_param(params[1]) {
        return syn::Error::new_spanned(params[1], "#[handler] second parameter must be `&[u8]`")
            .to_compile_error();
    }

    // Extract and validate the return type (must be Vec<u8>)
    let ret_ty = match &input.sig.output {
        ReturnType::Default => {
            return syn::Error::new_spanned(
                &input.sig,
                "#[handler] function must return `Vec<u8>`",
            )
            .to_compile_error();
        }
        ReturnType::Type(_, ty) => {
            if !is_valid_return_type(ty) {
                return syn::Error::new_spanned(ty, "#[handler] return type must be `Vec<u8>`")
                    .to_compile_error();
            }
            ty.clone()
        }
    };

    let vis = &input.vis;
    let fn_name = &input.sig.ident;
    let attrs = &input.attrs;
    let body = &input.block;

    // Preserve existing generics/where-clause and prepend the 'a lifetime
    let mut generics = input.sig.generics.clone();
    generics.params.insert(
        0,
        GenericParam::Lifetime(LifetimeParam {
            attrs: vec![],
            lifetime: Lifetime::new("'a", proc_macro2::Span::call_site()),
            colon_token: None,
            bounds: syn::punctuated::Punctuated::new(),
        }),
    );
    let (impl_generics, _, where_clause) = generics.split_for_impl();

    // Rewrite the two parameters with 'a lifetime
    let param0 = inject_lifetime(params[0]);
    let param1 = inject_lifetime(params[1]);

    let output = quote! {
        #(#attrs)*
        #vis fn #fn_name #impl_generics (#param0, #param1) -> ::core::pin::Pin<::alloc::boxed::Box<dyn ::core::future::Future<Output = #ret_ty> + 'a>> #where_clause {
            ::alloc::boxed::Box::pin(async move #body)
        }
    };

    output
}
