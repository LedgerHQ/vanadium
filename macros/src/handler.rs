use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, FnArg, ItemFn, Lifetime, ReturnType, Type};

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

pub fn handler_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
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

    // Extract the return type (should be Vec<u8>)
    let ret_ty = match &input.sig.output {
        ReturnType::Default => {
            return syn::Error::new_spanned(&input.sig, "#[handler] function must return Vec<u8>")
                .to_compile_error();
        }
        ReturnType::Type(_, ty) => ty.clone(),
    };

    let vis = &input.vis;
    let fn_name = &input.sig.ident;
    let attrs = &input.attrs;
    let body = &input.block;

    // Extract and rewrite the two parameters with 'a lifetime
    let params: Vec<_> = input.sig.inputs.iter().collect();
    let param0 = inject_lifetime(&params[0]);
    let param1 = inject_lifetime(&params[1]);

    let output = quote! {
        #(#attrs)*
        #vis fn #fn_name<'a>(#param0, #param1) -> ::core::pin::Pin<::alloc::boxed::Box<dyn ::core::future::Future<Output = #ret_ty> + 'a>> {
            ::alloc::boxed::Box::pin(async move #body)
        }
    };

    output
}
