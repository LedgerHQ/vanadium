use proc_macro2::TokenStream;
use proc_macro_error2::abort;
use quote::{format_ident, quote, ToTokens};
use syn::{parse::Parse, DataEnum, DataStruct, DeriveInput, Field, Fields, Ident, Member, Meta, Token, Visibility};

enum Wrapped {
    // the inner ident is useless in itself, just stored to keep the span.
    MaybeConst(Ident), 
    Ident(Ident)
}

impl Parse for Wrapped {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ident = input.parse::<Ident>()?;
        if input.is_empty() {
            if ident == "maybe_const" {
                return Ok(Wrapped::MaybeConst(ident));
            } else {
                return Err(syn::Error::new_spanned(ident, "only `maybe_const` and `name = $ident` or allowed."));
            }
        }
        input.parse::<Token![=]>()?;
        let name = input.parse::<Ident>()?;
        if ident != "name" {
            return Err(syn::Error::new_spanned(ident, "only `maybe_const` and `name = $ident` or allowed."))
        }
        Ok(Wrapped::Ident(name))
    }
}

pub fn derive_serializable(input: DeriveInput) -> TokenStream {
    let mut iter = input.attrs.iter().filter_map(|att| match &att.meta {
        Meta::List(meta_list) if meta_list.path.segments.first().unwrap().ident == "wrapped" => {
            match meta_list.parse_args::<Wrapped>() {
                Ok(wrapped) => Some(wrapped),
                Err(err) => abort!(meta_list, "invalid wrapped args: {}", err),
            }
        }
        _ => None,
    });

    let wrapped_ident = iter.next();
    if let Some(Wrapped::Ident(dup) | Wrapped::MaybeConst(dup)) = iter.next() {
        abort!(dup, "duplicate wrapped attribute");
        
    }

    let mut iter = input.attrs.iter().filter_map(|att| match &att.meta {
        Meta::List(meta_list) if meta_list.path.segments.first().unwrap().ident == "maker" => {
            match meta_list.parse_args::<Ident>() {
                Ok(fn_name) => Some(fn_name),
                Err(err) => abort!(meta_list, "invalid maker args: {}", err),
            }
        }
        _ => None,
    });

    let make_fn_ident = iter.next();
    if let Some(dup) = iter.next() {
        abort!(dup, "duplicate maker");
    }

    let vis = &input.vis;

    match &input.data {
        syn::Data::Struct(data) => derive_struct(vis, &input.ident, data, wrapped_ident.as_ref(), make_fn_ident.as_ref()),
        syn::Data::Enum(data) => derive_enum(vis, &input.ident, data, wrapped_ident.as_ref()),
        syn::Data::Union(data) => abort!(data.union_token, "unions are not supported"),
    }
}

fn derive_enum(
    vis: &Visibility,
    ident: &Ident,
    data: &DataEnum,
    wrapped_ident: Option<&Wrapped>,
) -> TokenStream {

    let wrapped = wrapped_ident.map(|wrapped_ident| wrappable_enum(vis, ident, data, wrapped_ident));

    let serialized_length_match_arms = data.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Named(fields) => {
                let spread_fields = fields.named.iter().map(|field| field.ident.as_ref());
                let get_field_length = spread_fields.clone();
                quote! {
                    Self::#variant_ident { #(#spread_fields,)* } => 1 #(
                        + Serializable::get_serialized_length(#get_field_length)
                    )*
                }
            }
            Fields::Unnamed(fields_unnamed) => {
                let field_names = fields_unnamed
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format_ident!("__field_{}__", i))
                    .collect::<Vec<_>>();
                quote! {
                    Self::#variant_ident(#(#field_names),*) => 1 #(
                        + Serializable::get_serialized_length(#field_names)
                    )*
                }
            }
            Fields::Unit => quote!(Self::#variant_ident => 1),
        }
    });
    let deserialize_match_arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(discriminant, variant)| {
            let variant_ident = &variant.ident;
            let discriminant = discriminant as u8;
            match &variant.fields {
                Fields::Named(fields_named) => {
                    let deserialize_fields = fields_named.named.iter().map(|field| {
                        let field_name = field.ident.as_ref();
                        let ty = &field.ty;
                        // we could use the `?` operator, but it incrase compile times, and since nobody looks at macro code output... 
                        quote! {
                            let (#field_name, __rest) = match <#ty as Deserializable>::deserialize(__rest) {
                                Ok(v) => v,
                                Err(err) => return Err(err)
                            };
                        }
                    });
                    let spread_fields = fields_named.named.iter().map(|field| field.ident.as_ref());
                    quote! {
                        [#discriminant, __rest @ ..] => {
                            #(
                                #deserialize_fields
                            )*
                            Ok((Self::#variant_ident { #(#spread_fields,)* }, __rest))
                        }
                    }
                }
                Fields::Unnamed(fields_unnamed) => {
                    let fields = fields_unnamed
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, field)| (format_ident!("__field_{}__", i), &field.ty))
                        .collect::<Vec<_>>();

                        let deserialize_fields = fields.iter().map(|(field_name, ty)| {
                            // we could use the `?` operator, but it incrase compile times, and since nobody looks at macro code output... 
                            quote! {
                                let (#field_name, __rest) = match <#ty as Deserializable>::deserialize(__rest) {
                                    Ok(v) => v,
                                    Err(err) => return Err(err),
                                };
                            }
                        });

                    let spread_fields = fields.iter().map(|(ident, _)| ident);

                    quote! {
                        [#discriminant, __rest @ ..] => {
                            #(
                                #deserialize_fields
                            )*
                            Ok((Self::#variant_ident(#(#spread_fields),*), __rest))
                        }
                    }
                }
                Fields::Unit => quote! {
                    [#discriminant, __rest @ ..] => Ok((Self::#variant_ident, __rest))
                },
            }
        });
    let slice_too_short = format!("{} slice to short for tag", ident);

    let serialize_match_arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(discriminant, variant)| {
            let discriminant = discriminant as u8;
            let variant_ident = &variant.ident;
            match &variant.fields {
                Fields::Named(fields_named) => {
                    let fields_names = fields_named.named.iter().map(|field| field.ident.as_ref());
                    let fields = fields_names.clone();
                    quote! {
                        Self::#variant_ident { #(#fields_names,)* } => {
                            __buff[*__pos] = #discriminant;
                            *__pos += 1;
                            #(
                                Serializable::serialize(#fields, __buff, __pos);
                            )*
                        }
                    }
                }
                Fields::Unnamed(fields_unnamed) => {
                    let field_names = fields_unnamed
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, _)| format_ident!("__field_{}__", i))
                        .collect::<Vec<_>>();

                    quote! {
                        Self::#variant_ident(#(#field_names),*) => {
                            __buff[*__pos] = #discriminant;
                            *__pos += 1;
                            #(
                                Serializable::serialize(#field_names, __buff, __pos);
                            )*
                        }
                    }
                }
                Fields::Unit => quote! {
                    Self::#variant_ident => {
                        __buff[*__pos] = #discriminant;
                        *__pos += 1;
                    }
                },
            }
        });

    let maker_functions = data
        .variants
        .iter()
        .enumerate()
        .filter_map(|(discriminant, variant)| {
            let mut iter = variant.attrs.iter().filter_map(|att| match &att.meta {
                Meta::List(list) if list.path.segments.first().unwrap().ident == "maker" => {
                    match list.parse_args::<Ident>() {
                        Ok(ident) => Some(ident),
                        Err(err) => abort!(list, "invalid maker args: {}", err)
                    }
                }
                _ => None,
            });
            match (iter.next(), iter.next()) {
                (Some(ident), None) => Some((variant, ident, discriminant)),
                (Some(_), Some(dup)) => abort!(dup, "duplicates maker attribute"),
                _ => None,
            }
        })
        .map(|(variant, fn_make_ident, discriminant)| {
            let discriminant = discriminant as u8;
            let (args, get_len, serialize) = match &variant.fields {
                Fields::Named(fields_named) => {
                    let args = fields_named.named.iter().map(|field| {
                        let name = &field.ident;
                        let ty = &field.ty;
                        quote!(#name: <#ty as Makeable>::ArgType)
                    });
                    let get_fields_len = fields_named.named.iter().map(|field| {
                        let name = &field.ident;
                        quote!(Serializable::get_serialized_length(&#name))
                    });
                    let serialize_field = fields_named.named.iter().map(|field| {
                        let name = &field.ident;
                        quote!(Serializable::serialize(&#name, &mut __buff, &mut __pos))
                    });
                    (
                        quote!(#(#args),*),
                        quote!({
                            1 #( + #get_fields_len)*
                        }),
                        quote!({
                            __buff[__pos] = #discriminant;
                            __pos += 1;
                            #(
                                #serialize_field;
                            )*
                        }),
                    )
                }
                Fields::Unnamed(fields_unnamed) => {
                    let fields = fields_unnamed
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, field)| (format_ident!("__field_{}__", i), &field.ty))
                        .collect::<Vec<_>>();
                    let args = fields
                        .iter()
                        .map(|(name, ty)| quote!(#name: <#ty as Makeable>::ArgType));
                    let serialize_field = fields
                        .iter()
                        .map(|(name, _)| quote!(Serializable::serialize(&#name, &mut __buff, &mut __pos)));
                    let get_fields_len = fields
                        .iter()
                        .map(|(name, _)| quote!(Serializable::get_serialized_length(&#name)));
                    (
                        quote!(#(#args),*),
                        quote!({
                            1 #( + #get_fields_len)*
                        }),
                        quote!({
                            __buff[__pos] = #discriminant;
                            __pos += 1;
                            #(
                                #serialize_field;
                            )*
                        })
                    )
                }
                Fields::Unit => (
                    quote!(),
                    quote!(1usize),
                    quote! {
                        __buff[__pos] = #discriminant;
                        __pos += 1;
                    },
                ),
            };

            quote! {
                pub fn #fn_make_ident(#args) -> Vec<u8> {
                    let __len = #get_len;
                    let mut __buff = Vec::with_capacity(__len);
                    let mut __pos = 0;
                    #serialize
                    unsafe {
                        __buff.set_len(__len);
                    }
                    __buff
                }
            }
        });

    quote! {

        impl Serializable for #ident {
            fn get_serialized_length(&self) -> usize {
                match self {
                    #(
                        #serialized_length_match_arms,
                    )*
                }
            }

            fn serialize(&self, __buff: &mut [u8], __pos: &mut usize) {
                match self {
                    #(
                        #serialize_match_arms,
                    )*
                }
            }
        }

        impl Deserializable for #ident {
            fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                match slice {
                    [] => Err(#slice_too_short),
                    #(
                        #deserialize_match_arms,
                    )*
                    _ => Err("unknown tag"),
                }
            }
        }

        impl #ident {
            #(
                #maker_functions
            )*
        }

        #wrapped

        impl Makeable<'_> for #ident {
            type ArgType = #ident;
        }
    }
}

fn wrappable_enum(
    vis: &Visibility,
    ident: &Ident,
    data: &DataEnum,
    wrapped_ident: &Wrapped,
) -> TokenStream {
    let wrapped_ident = match wrapped_ident {
        Wrapped::Ident(ident) => ident,
        Wrapped::MaybeConst(_) => {
            return quote! {
                impl Wrappable for #ident {
                    type Wrapped = MaybeConst<#ident>;
                }
            };
        }
    };

    let variants = data.variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        match &variant.fields {
            Fields::Named(fields_named) => {
                let fields = fields_named.named.iter().map(|field| {
                    let ident = field.ident.as_ref();
                    let ty = &field.ty;
                    quote!(#ident: <#ty as Wrappable>::Wrapped)
                });
                quote! {
                    #variant_ident{
                        #(
                            #fields,
                        )*
                    }
                }
            }
            Fields::Unnamed(fields_unnamed) => {
                let fields = fields_unnamed.unnamed.iter().map(|field| {
                    let ty = &field.ty;
                    quote!(<#ty as Wrappable>::Wrapped)
                });
                quote!(#variant_ident(#(#fields),*))
            }
            Fields::Unit => quote!(#variant_ident),
        }
    });
    let serialize_wrapped_match_arms = data.variants.iter().enumerate().map(|(discriminant,variant)| {
        let discriminant = discriminant as u8;
        let variant_ident = &variant.ident;

        match &variant.fields {
            Fields::Named(fields_named) => {
                let fields = fields_named.named.iter().map(|field| field.ident.as_ref());
                let serialize_fields = fields.clone();
                quote! {
                    Self::#variant_ident { #(#fields,)* } => {
                        __parts.push(SerializedPart::Static(alloc::vec![#discriminant]));
                        #(
                            __parts.extend(WrappedSerializable::serialize_wrapped(#serialize_fields));
                        )*
                    }
                }
            },
            Fields::Unnamed(fields_unnamed) => {
                let fields = fields_unnamed
                        .unnamed
                        .iter()
                        .enumerate()
                        .map(|(i, _)| format_ident!("__field_{}__", i))
                        .collect::<Vec<_>>();
                
                quote! {
                    Self::#variant_ident(#(#fields),*) => {
                        __parts.push(SerializedPart::Static(alloc::vec![#discriminant]));
                        #(
                            __parts.extend(WrappedSerializable::serialize_wrapped(#fields));
                        )*
                    }
                }
            },
            Fields::Unit => {
                quote! {
                    Self::#variant_ident => {
                        __parts.push(SerializedPart::Static(alloc::vec![#discriminant]));
                    }
                }
            },
        }
    });

    quote! {
        #[derive(Debug, PartialEq, Eq, Clone)]
        #vis enum #wrapped_ident {
            #(
                #variants,
            )*
        }

        impl WrappedSerializable for #wrapped_ident {
            fn serialize_wrapped(&self) -> Vec<SerializedPart> {
                let mut __parts = Vec::new();
                match self {
                    #(
                        #serialize_wrapped_match_arms,
                    )*
                }
                __parts
            }
        }

        impl Wrappable for #ident {
            type Wrapped = #wrapped_ident;
        }
    }
}

struct CustomFields<'a> {
    member: Member,
    field: &'a Field,
}

impl ToTokens for CustomFields<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.member.to_tokens(tokens);
    }
}

fn derive_struct(vis: &Visibility, ident: &Ident, data: &DataStruct, wrapped_ident: Option<&Wrapped>, make_fn_ident: Option<&Ident>) -> TokenStream {
    let fields = data.fields.members().zip(&data.fields).map(|(member, field)| {
        CustomFields {
            member,
            field
        }
    }).collect::<Vec<_>>();

    let maker_fn = make_fn_ident.map(|make_fn_ident| {
        let (args, get_len, serialize) = match &data.fields {
            Fields::Named(fields_named) => {
                let args = fields_named.named.iter().map(|field| {
                    let name = &field.ident;
                    let ty = &field.ty;
                    quote!(#name: <#ty as Makeable>::ArgType)
                });
                let get_fields_len = fields_named.named.iter().map(|field| {
                    let name = &field.ident;
                    quote!(Serializable::get_serialized_length(&#name))
                });
                let serialize_field = fields_named.named.iter().map(|field| {
                    let name = &field.ident;
                    quote!(Serializable::serialize(&#name, &mut __buff, &mut __pos))
                });
                (
                    quote!(#(#args),*),
                    quote!({
                        0 #( + #get_fields_len)*
                    }),
                    quote!({
                        #(
                            #serialize_field;
                        )*
                    }),
                )
            },
            Fields::Unnamed(fields_unnamed) => {
                let fields = fields_unnamed.unnamed.iter().enumerate().map(|(i, field)| {
                    let ty = &field.ty;
                    (format_ident!("field_{}", i), ty)
                }).collect::<Vec<_>>();
                let args = fields
                        .iter()
                        .map(|(name, ty)| quote!(#name: <#ty as Makeable>::ArgType));
                    let serialize_field = fields
                        .iter()
                        .map(|(name, _)| quote!(Serializable::serialize(&#name, &mut __buff, &mut __pos)));
                    let get_fields_len = fields
                        .iter()
                        .map(|(name, _)| quote!(Serializable::get_serialized_length(&#name)));
                    (quote!(#(#args),*),
                    quote!({
                        0 #( + #get_fields_len)*
                    }),
                    quote!({
                        #(
                            #serialize_field;
                        )*
                    }))
            },
            Fields::Unit => (quote! {}, quote! {1usize}, quote! {}),
        };
        quote! {
            impl #ident {
                pub fn #make_fn_ident(#args) -> Vec<u8> {
                    let __len = #get_len;
                    let mut __buff = Vec::with_capacity(__len);
                    let mut __pos = 0;
                    #serialize
                    unsafe {
                        __buff.set_len(__len);
                    }
                    __buff
                }
            }
        }
    });

    let wrapped = wrapped_ident.map(|wrapped_ident| wrappable_struct(vis, ident, &fields, wrapped_ident));




    let serialized_fields = fields.iter().map(|field| {
        let ty = &field.field.ty;
        quote! {
            <#ty as Serializable>::serialize(&self.#field, __buff, __pos)
        }
    });

    let deserialized_fields = fields.iter().map(|field| {
        let ty = &field.field.ty;
        quote! {
            #field: match <#ty as Deserializable>::deserialize(__rest) {
                Ok((v, rest)) => {
                    __rest = rest;
                    v
                },
                Err(err) => return Err(err)
            }
        }
    });


    quote! {
        impl Serializable for #ident {
            fn get_serialized_length(&self) -> usize {
                0 #(+ Serializable::get_serialized_length(&self.#fields))*
            }

            fn serialize(&self, __buff: &mut [u8], __pos: &mut usize) {
                #(
                    #serialized_fields;
                )*
            }
        }

        impl Deserializable for #ident {
            fn deserialize(mut __rest: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                let this = Self {
                    #(
                        #deserialized_fields,
                    )*
                };
                Ok((this, __rest))
            }
        }

        #maker_fn

        #wrapped

        impl Makeable<'_> for #ident {
            type ArgType = #ident;
        }
    }
}

fn wrappable_struct(
    vis: &Visibility,
    ident: &Ident,
    fields: &[CustomFields],
    wrapped_ident: &Wrapped,
) -> TokenStream {
    
    let wrapped_ident = match wrapped_ident {
        Wrapped::Ident(ident) => ident,
        Wrapped::MaybeConst(_) => {
            return quote! {
                impl Wrappable for #ident {
                    type Wrapped = MaybeConst<#ident>;
                }
            };
        }
    };

    let struct_fields = fields.iter().map(|field| {
        let ty = &field.field.ty;

        quote!(pub #field: <#ty as Wrappable>::Wrapped)
    });

    quote! {
        #[derive(Debug, PartialEq, Eq, Clone)]
        #vis struct #wrapped_ident {
            #(
                #struct_fields,
            )*
        }

        impl WrappedSerializable for #wrapped_ident {
            fn serialize_wrapped(&self) -> Vec<SerializedPart> {
                let mut __parts = Vec::new();
                #(
                    __parts.extend(WrappedSerializable::serialize_wrapped(&self.#fields));
                )*
                __parts
            }
        }

        impl Wrappable for #ident {
            type Wrapped = #wrapped_ident;
        }
    }
}
