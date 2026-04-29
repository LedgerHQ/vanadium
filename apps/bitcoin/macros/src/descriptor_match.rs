use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, parenthesized, token, Expr, Token};

// ── Domain tables ────────────────────────────────────────────────────────────

fn keyword_to_variant(kw: &str) -> Option<&'static str> {
    Some(match kw {
        "sh" => "Sh",
        "wsh" => "Wsh",
        "pkh" => "Pkh",
        "wpkh" => "Wpkh",
        "sortedmulti" => "Sortedmulti",
        "sortedmulti_a" => "Sortedmulti_a",
        "tr" => "Tr",
        "pk" => "Pk",
        "pk_k" => "Pk_k",
        "pk_h" => "Pk_h",
        "older" => "Older",
        "after" => "After",
        "andor" => "Andor",
        "and_v" => "And_v",
        "and_b" => "And_b",
        "and_n" => "And_n",
        "or_b" => "Or_b",
        "or_c" => "Or_c",
        "or_d" => "Or_d",
        "or_i" => "Or_i",
        "thresh" => "Thresh",
        "multi" => "Multi",
        "multi_a" => "Multi_a",
        _ => return None,
    })
}

fn wrapper_to_variant(c: char) -> Option<&'static str> {
    Some(match c {
        'a' => "A",
        's' => "S",
        'c' => "C",
        't' => "T",
        'd' => "D",
        'v' => "V",
        'j' => "J",
        'n' => "N",
        'l' => "L",
        'u' => "U",
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ArgKind {
    Key,
    Num,
    KeyList,
    Sub,
}

fn variant_arg_kinds(variant: &str) -> &'static [ArgKind] {
    use ArgKind::*;
    match variant {
        "Pk" | "Pk_k" | "Pk_h" | "Pkh" | "Wpkh" => &[Key],
        "Older" | "After" => &[Num],
        "Multi" | "Multi_a" | "Sortedmulti" | "Sortedmulti_a" => &[Num, KeyList],
        "And_v" | "And_b" | "And_n" | "Or_b" | "Or_c" | "Or_d" | "Or_i" => &[Sub, Sub],
        "Andor" => &[Sub, Sub, Sub],
        "Sh" | "Wsh" | "A" | "S" | "C" | "T" | "D" | "V" | "J" | "N" | "L" | "U" => &[Sub],
        _ => &[],
    }
}

// ── AST types ────────────────────────────────────────────────────────────────

pub struct DescriptorMatchInput {
    expr: Expr,
    arms: Vec<MatchArm>,
}

struct MatchArm {
    patterns: Vec<DescPattern>,
    guard: Option<Expr>,
    body: TokenStream,
}

enum DescPattern {
    Call {
        variant: String,
        args: Vec<PatternArg>,
    },
    Wildcard,
}

enum PatternArg {
    Binding(Ident),
    SubPattern {
        wrappers: Vec<String>,
        inner: Box<DescPattern>,
    },
}

// ── Parsing ──────────────────────────────────────────────────────────────────

impl Parse for DescriptorMatchInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let expr: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let content;
        braced!(content in input);
        let mut arms = Vec::new();
        while !content.is_empty() {
            arms.push(content.call(parse_match_arm)?);
        }
        Ok(DescriptorMatchInput { expr, arms })
    }
}

fn parse_match_arm(input: ParseStream) -> syn::Result<MatchArm> {
    let mut patterns = vec![parse_desc_pattern(input)?];
    while input.peek(Token![|]) {
        input.parse::<Token![|]>()?;
        patterns.push(parse_desc_pattern(input)?);
    }

    let guard = if input.peek(Token![if]) {
        input.parse::<Token![if]>()?;
        let mut guard_tokens = TokenStream::new();
        while !input.peek(Token![=>]) {
            let tt: proc_macro2::TokenTree = input.parse()?;
            guard_tokens.extend(std::iter::once(tt));
        }
        Some(syn::parse2::<Expr>(guard_tokens)?)
    } else {
        None
    };

    input.parse::<Token![=>]>()?;

    let body_content;
    braced!(body_content in input);
    let body: TokenStream = body_content.parse()?;

    if input.peek(Token![,]) {
        input.parse::<Token![,]>()?;
    }

    Ok(MatchArm {
        patterns,
        guard,
        body,
    })
}

fn parse_desc_pattern(input: ParseStream) -> syn::Result<DescPattern> {
    if input.peek(Token![_]) {
        input.parse::<Token![_]>()?;
        return Ok(DescPattern::Wildcard);
    }
    parse_possibly_wrapped_pattern(input)
}

fn parse_possibly_wrapped_pattern(input: ParseStream) -> syn::Result<DescPattern> {
    let mut wrappers = Vec::new();

    while input.peek(syn::Ident) && input.peek2(Token![:]) {
        let ident: Ident = input.parse()?;
        let s = ident.to_string();
        if s.len() == 1 {
            let c = s.chars().next().unwrap();
            match wrapper_to_variant(c) {
                Some(v) => {
                    input.parse::<Token![:]>()?;
                    wrappers.push(v.to_string());
                }
                None => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown wrapper '{}'", c),
                    ));
                }
            }
        } else {
            // Treat multi-letter idents before ':' as groups of wrapper characters,
            // e.g. `sln:older(x)` -> wrappers 's', 'l', 'n' applied to `older`.
            for c in s.chars() {
                match wrapper_to_variant(c) {
                    Some(v) => {
                        wrappers.push(v.to_string());
                    }
                    None => {
                        return Err(syn::Error::new(
                            ident.span(),
                            format!("unknown wrapper character '{}' in group '{}'", c, s),
                        ));
                    }
                }
            }
            input.parse::<Token![:]>()?;
        }
    }

    let ident: Ident = input.parse()?;
    parse_keyword_call_from_ident(ident, &wrappers, input)
}

fn parse_keyword_call_from_ident(
    ident: Ident,
    wrappers: &[String],
    input: ParseStream,
) -> syn::Result<DescPattern> {
    let kw_str = ident.to_string();
    let variant = keyword_to_variant(&kw_str).ok_or_else(|| {
        syn::Error::new(
            ident.span(),
            format!("unknown descriptor keyword '{}'", kw_str),
        )
    })?;

    let content;
    parenthesized!(content in input);
    let arg_kinds = variant_arg_kinds(variant);
    let mut args = Vec::new();
    let mut i = 0;
    while !content.is_empty() {
        if i > 0 {
            content.parse::<Token![,]>()?;
        }
        let kind = arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub);
        let arg = match kind {
            ArgKind::Key | ArgKind::Num | ArgKind::KeyList => {
                let binding: Ident = content.parse()?;
                PatternArg::Binding(binding)
            }
            ArgKind::Sub => parse_possibly_wrapped_sub(&content)?,
        };
        args.push(arg);
        i += 1;
    }

    let inner = DescPattern::Call {
        variant: variant.to_string(),
        args,
    };

    if wrappers.is_empty() {
        Ok(inner)
    } else {
        Ok(wrap_pattern(inner, wrappers))
    }
}

fn wrap_pattern(inner: DescPattern, wrappers: &[String]) -> DescPattern {
    let mut current = inner;
    for w in wrappers.iter().rev() {
        current = DescPattern::Call {
            variant: w.clone(),
            args: vec![PatternArg::SubPattern {
                wrappers: vec![],
                inner: Box::new(current),
            }],
        };
    }
    current
}

fn parse_possibly_wrapped_sub(input: ParseStream) -> syn::Result<PatternArg> {
    let mut wrappers = Vec::new();
    while input.peek(syn::Ident) && input.peek2(Token![:]) {
        let ident: Ident = input.parse()?;
        let s = ident.to_string();
        if s.len() == 1 {
            let c = s.chars().next().unwrap();
            match wrapper_to_variant(c) {
                Some(v) => {
                    input.parse::<Token![:]>()?;
                    wrappers.push(v.to_string());
                }
                None => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!("unknown wrapper '{}'", c),
                    ));
                }
            }
        } else {
            // Treat multi-letter identifiers before ':' as grouped wrappers,
            // consistent with `parse_possibly_wrapped_pattern`.
            for c in s.chars() {
                match wrapper_to_variant(c) {
                    Some(v) => wrappers.push(v.to_string()),
                    None => {
                        return Err(syn::Error::new(
                            ident.span(),
                            format!("unknown wrapper '{}'", c),
                        ));
                    }
                }
            }
            // Consume the ':' that follows the wrapper group.
            input.parse::<Token![:]>()?;
        }
    }

    if input.peek(syn::Ident) && input.peek2(token::Paren) {
        let ident: Ident = input.parse()?;
        let inner = parse_keyword_call_from_ident(ident, &[], input)?;
        Ok(PatternArg::SubPattern {
            wrappers,
            inner: Box::new(inner),
        })
    } else if input.peek(syn::Ident) {
        if !wrappers.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "wrappers cannot be applied to a binding identifier",
            ));
        }
        let binding: Ident = input.parse()?;
        Ok(PatternArg::Binding(binding))
    } else {
        Err(syn::Error::new(
            input.span(),
            "expected a descriptor pattern or binding identifier",
        ))
    }
}

// ── Code generation ──────────────────────────────────────────────────────────
//
// Strategy: flatten each pattern into a list of "match steps", where each step
// says "match expression X against variant V, binding temporaries t1, t2, …".
// Then fold the list into nested `if let` blocks from outside in, with the
// innermost block containing the let-bindings and the body.

/// A single destructuring step in a flattened pattern.
struct MatchStep {
    /// The expression to match (as tokens).
    matchee: TokenStream,
    /// The variant to match against.
    variant: String,
    /// Temporary variable names for each positional argument.
    temp_vars: Vec<Ident>,
}

/// A user-visible binding extracted from the pattern.
struct UserBinding {
    name: Ident,
    extraction: TokenStream,
}

struct VarCounter(usize);

impl VarCounter {
    fn new() -> Self {
        VarCounter(0)
    }
    fn next(&mut self, prefix: &str) -> Ident {
        let n = format!("__{}{}", prefix, self.0);
        self.0 += 1;
        Ident::new(&n, Span::call_site())
    }
}

/// Flatten a pattern into a sequence of match steps and user bindings.
fn flatten_pattern(
    pat: &DescPattern,
    expr: TokenStream,
    is_boxed: bool,
    counter: &mut VarCounter,
    steps: &mut Vec<MatchStep>,
    user_bindings: &mut Vec<UserBinding>,
) {
    match pat {
        DescPattern::Wildcard => {}
        DescPattern::Call { variant, args } => {
            let arg_kinds = variant_arg_kinds(variant);

            let matchee = if is_boxed {
                quote!(#expr.as_ref())
            } else {
                expr
            };

            let temp_vars: Vec<Ident> = args
                .iter()
                .enumerate()
                .map(|(i, _)| counter.next(&format!("p{}_", i)))
                .collect();

            steps.push(MatchStep {
                matchee,
                variant: variant.clone(),
                temp_vars: temp_vars.clone(),
            });

            for (i, (arg, tv)) in args.iter().zip(temp_vars.iter()).enumerate() {
                let kind = arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub);
                match arg {
                    PatternArg::Binding(ident) => {
                        let extraction = match kind {
                            ArgKind::Key => quote!(#tv),
                            ArgKind::Num => quote!(*#tv),
                            ArgKind::KeyList => {
                                quote!(#tv)
                            }
                            ArgKind::Sub => quote!(#tv),
                        };
                        user_bindings.push(UserBinding {
                            name: ident.clone(),
                            extraction,
                        });
                    }
                    PatternArg::SubPattern { wrappers, inner } => {
                        // Process wrappers: each wrapper is a single-arg variant wrapping Box
                        let mut current_expr = quote!(#tv);
                        let mut current_is_boxed = kind == ArgKind::Sub;

                        for w in wrappers {
                            let wtv = counter.next("w");
                            let wmatchee = if current_is_boxed {
                                quote!(#current_expr.as_ref())
                            } else {
                                current_expr.clone()
                            };
                            steps.push(MatchStep {
                                matchee: wmatchee,
                                variant: w.clone(),
                                temp_vars: vec![wtv.clone()],
                            });
                            current_expr = quote!(#wtv);
                            current_is_boxed = true;
                        }

                        flatten_pattern(
                            inner,
                            current_expr,
                            current_is_boxed,
                            counter,
                            steps,
                            user_bindings,
                        );
                    }
                }
            }
        }
    }
}

/// Fold a list of match steps into nested `if let` blocks.
/// The innermost block contains the `inner_code`.
fn fold_steps(steps: &[MatchStep], inner_code: TokenStream) -> TokenStream {
    let mut code = inner_code;
    for step in steps.iter().rev() {
        let variant_ident = Ident::new(&step.variant, Span::call_site());
        let matchee = &step.matchee;
        let tvs: Vec<&Ident> = step.temp_vars.iter().collect();

        let destructure = if tvs.is_empty() {
            quote!(DescriptorTemplate::#variant_ident)
        } else {
            quote!(DescriptorTemplate::#variant_ident(#(#tvs),*))
        };

        code = quote! {
            if let #destructure = #matchee {
                #code
            }
        };
    }
    code
}

pub fn generate(input: DescriptorMatchInput) -> TokenStream {
    let expr = &input.expr;

    let mut pattern_arms = Vec::new();
    let mut default_body = None;

    for arm in &input.arms {
        if arm.patterns.len() == 1 {
            if let DescPattern::Wildcard = &arm.patterns[0] {
                default_body = Some(&arm.body);
                continue;
            }
        }
        pattern_arms.push(arm);
    }

    let default_body = default_body.expect("descriptor_match! requires a `_ => { … }` default arm");

    let match_var = Ident::new("__desc_match_expr", Span::call_site());
    let mut arm_stmts = Vec::new();

    for arm in &pattern_arms {
        let body = &arm.body;
        let guard = &arm.guard;

        for pat in &arm.patterns {
            let mut counter = VarCounter::new();
            let mut steps = Vec::new();
            let mut user_bindings = Vec::new();

            flatten_pattern(
                pat,
                quote!(#match_var),
                false,
                &mut counter,
                &mut steps,
                &mut user_bindings,
            );

            let binding_lets: Vec<TokenStream> = user_bindings
                .iter()
                .map(|b| {
                    let name = &b.name;
                    let extraction = &b.extraction;
                    quote! { let #name = #extraction; }
                })
                .collect();

            let innermost = if let Some(guard_expr) = guard {
                quote! {
                    #(#binding_lets)*
                    if #guard_expr {
                        break 'descriptor_match { #body };
                    }
                }
            } else {
                quote! {
                    #(#binding_lets)*
                    break 'descriptor_match { #body };
                }
            };

            let code = fold_steps(&steps, innermost);
            arm_stmts.push(code);
        }
    }

    quote! {
        'descriptor_match: {
            let #match_var = #expr;
            #(#arm_stmts)*
            { #default_body }
        }
    }
}
