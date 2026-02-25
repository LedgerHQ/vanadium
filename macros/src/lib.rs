use proc_macro::TokenStream;
use proc_macro_error2::proc_macro_error;
use syn::{DeriveInput, parse_macro_input};

mod derive_serializable;
mod handler;

#[proc_macro_derive(Serializable, attributes(maker, wrapped))]
#[proc_macro_error]
pub fn serializable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_serializable::derive_serializable(input).into()
}

/// Attribute macro that transforms an `async fn` into a handler compatible
/// with the Vanadium SDK's `App` framework.
///
/// # Example
/// ```ignore
/// #[sdk::handler]
/// async fn process_message(app: &mut App, msg: &[u8]) -> Vec<u8> {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn handler(attr: TokenStream, item: TokenStream) -> TokenStream {
    handler::handler_impl(attr.into(), item.into()).into()
}
