use proc_macro::TokenStream;
use syn::parse_macro_input;

mod descriptor_match;

/// Pattern-match on `DescriptorTemplate` values using descriptor-template notation.
///
/// # Syntax
///
/// ```ignore
/// descriptor_match!(expr {
///     pattern => { body },
///     pattern1 | pattern2 => { body },
///     pattern if guard => { body },
///     _ => { default },
/// })
/// ```
///
/// ## Pattern syntax
///
/// Patterns mirror the descriptor template string format:
///
/// - **Keywords**: `pk(x)`, `older(n)`, `and_v(a, b)`, `sortedmulti_a(k, keys)`, etc.
/// - **Wrappers**: `v:pk(x)` for `V(Box(Pk(…)))` — single letter + `:` prefix.
/// - **Bindings**: identifiers in argument positions. Extraction depends on position:
///   - Key-placeholder args (e.g. arg of `pk`) → extracts `.key_index: u32`
///   - Numeric args (e.g. arg of `older`, threshold of `multi`) → extracts `u32`
///   - Key-list args (e.g. 2nd arg of `sortedmulti_a`) → extracts `Vec<u32>` of key indices
/// - **Alternation**: `pk(x) | pkh(x)` — multiple patterns, same bindings.
/// - **Guards**: `if expr` — conditional check after bindings.
/// - **Default**: `_ => { … }` — required.
///
/// The body after `=>` is always a `{ … }` block — the macro does not parse or
/// transform it; it is emitted verbatim with pattern bindings in scope.
#[proc_macro]
pub fn descriptor_match(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as descriptor_match::DescriptorMatchInput);
    descriptor_match::generate(parsed).into()
}
