//! This crate provides the [`shadowquic::SEncode`] and [`shadowquic::SDecode`] derive macros.
//! These two macros automatically implement the SEncode and SDecode traits for structs and enums as long as
//! the member or variants are themselves SEncode or SDecode.
//!
//! Below is the example of how to use, below example defines the protocol header for socks5 address.
//!
//! ```rust, ignore
//! use shadowquic_macros::{SDecode, SEncode};
//! use shadowquic::msgs::{SDecode, SEncode};
//! use shadowquic::error::SError;
//! /// derive SDecode and SEncode automatically.
//! #[derive(SDecode, SEncode)]
//! pub struct SocksAddr {
//!     pub addr: AddrOrDomain,
//!     pub port: u16,
//! }
//! /// SDecode/SEncode will define SDecode/SEncode automatically.
//! /// `#[repr(u8)]` is required to specify the type of discriminant for enum.
//! #[derive(SDecode, SEncode)]
//! #[repr(u8)]
//! pub enum AddrOrDomain {
//!     V4([u8; 4]) = 0x1,
//!     V6([u8; 16]) = 0x4,
//!     Domain(VarVec) = 0x3,
//! }
//!
//! /// You need to define SEncode/SDecode traits yourself
//! /// since they are not defined for Vec.
//! pub struct VarVec {
//!     pub len: u8,
//!     pub contents: Vec<u8>,
//! }
//! ```
//! You can send the socks5 address by
//! ```rust, ignore
//! let addr: SocksAddr = ...;
//! let mut tcp_stream: TcpStream = ...;
//! addr.encode(&mut tcp_stream).await?;
//! ```
//! or you can receive the socks5 address by
//! ```rust, ignore
//! let mut tcp_stream: TcpStream = ...;
//! let addr = SocksAddr::decode(&mut tcp_stream).await?;
//! ```
//!
//! Based on these two macros,
//! you can easily define your own protocol header and implement them fast and clean.
//!
//! Structs may use `#[size_tag]` with both derives to prefix the encoded struct
//! payload with a `u32` byte length. During decode, the tagged payload is read
//! before the fields are decoded. If the payload is longer than the current
//! struct definition needs, trailing bytes are ignored. If the payload is
//! shorter, missing trailing bytes are read as zeroes up to a bounded
//! compatibility limit. This allows fields to be appended to size-tagged structs
//! while still decoding older messages.
//!
//! Check [`shadowquic::msgs::socks5`] to see how socks5 protocol header is defined.
//! A full protocol implementation can be seen in [`shadowquic::socks`] module
//!
//!

use proc_macro::TokenStream;
use proc_macro2::TokenTree;
use quote::quote;

/// Derive [`shadowquic::SEncode`] automatically for the struct or enum.
/// For struct, it encodes each field in order. For enum, it first encodes the discriminant as a u8/u16... defined by `#[repr(*)]`
/// and then encodes the content based on the value of disriminant.
/// For enum variants, at most one field is supported. Named field/or tuple field is not supported for enum.
///  `#[repr(*)]` is required for enum to specify the type of discriminant.
/// For structs, `#[size_tag]` prefixes the encoded field payload with a `u32` byte length.
#[proc_macro_derive(SEncode, attributes(size_tag))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);

    let ret = match ast.data {
        syn::Data::Struct(_) => impl_struct_encode(&ast),
        syn::Data::Enum(_) => impl_enum_encode(&ast),
        syn::Data::Union(..) => Err(syn::Error::new_spanned(
            ast,
            "Union is not supported by SEncode macro".to_string(),
        )),
    };
    match ret {
        Ok(token_stream) => token_stream.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// A simple check for common primitive repr types.
fn is_valid_repr_type(s: &str) -> bool {
    matches!(
        s,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}
/// Helper function to extract the Type from the #[repr(...)] attribute
fn get_repr_type(attrs: &[syn::Attribute]) -> Option<syn::Type> {
    for attr in attrs {
        if attr.path().is_ident("repr") {
            // Parse the meta items inside the attribute (e.g., repr(u8))
            if let syn::Meta::List(meta_list) = &attr.meta {
                //eprintln!("{:#?}", meta_list);
                {
                    if let Some(TokenTree::Ident(repr_type)) =
                        meta_list.tokens.clone().into_iter().next()
                    {
                        // Check if the path is a valid primitive (u8, u16, etc.)
                        // and convert the path to a Type
                        // Note: A real implementation should validate this further.

                        let ident_str = repr_type.to_string();
                        if is_valid_repr_type(&ident_str) {
                            return Some(syn::parse_quote! { #repr_type });
                        }
                    }
                }
            }
        }
    }
    None
}

fn impl_enum_encode(st: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_ident = &st.ident;
    let fields = get_variants_from_derive_input(st)?;
    let repr_type = get_repr_type(&st.attrs)
        .ok_or_else(|| syn::Error::new_spanned(st, "Missing repr attribute"))?;
    let builder_struct_fields_def = generate_enum_encode_varints(fields, &repr_type)?;

    //eprintln!("{:#?}",fields);
    //eprintln!("{:#?}",st);
    let ret = quote! {
        #[async_trait::async_trait]
        impl SEncode for #struct_ident {
            async fn encode<T: tokio::io::AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
                let x = unsafe { *<*const Self>::from(self).cast::<#repr_type>() }.clone();
                x.encode(s).await?;
                match self {
                    #builder_struct_fields_def
                }
                Ok(())
            }
        }
    };

    Ok(ret)
}
fn impl_enum_decode(st: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_ident = &st.ident;
    let fields = get_variants_from_derive_input(st)?;
    let repr_type = get_repr_type(&st.attrs).ok_or_else(|| {
        syn::Error::new_spanned(
            st,
            "Missing repr attribute, adding attribute like `#[repr(u8)]`",
        )
    })?;

    let discrims = generate_enum_discriminants(fields, &repr_type)?;
    let builder_struct_fields_def = generate_enum_decode_varints(fields, &repr_type)?;

    //eprintln!("{:#?}",fields);
    //eprintln!("{:#?}",st);
    let ret = quote! {
        #[async_trait::async_trait]
        impl SDecode for #struct_ident {
            async fn decode<T: tokio::io::AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
                let disval = #repr_type::decode(s).await?;
                #discrims
                let ret = match disval {
                    #builder_struct_fields_def
                    _ => return Err(SError::ProtocolViolation),
                };
                Ok(ret)
            }
        }
    };

    Ok(ret)
}

fn impl_struct_encode(st: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_ident = &st.ident;
    let fields = get_fields_from_derive_input(st)?;
    let builder_struct_fields_def = generate_struct_encode_fields(fields)?;

    let has_size_tag = st.attrs.iter().any(|attr| attr.path().is_ident("size_tag"));

    let body = if has_size_tag {
        quote! {
            use tokio::io::AsyncWriteExt;
            let mut buf = Vec::new();
            {
                let s = &mut buf;
                #builder_struct_fields_def
            }
            let len = buf.len() as u32;
            len.encode(s).await?;
            s.write_all(&buf).await?;
        }
    } else {
        quote! {
            #builder_struct_fields_def
        }
    };

    //eprintln!("{:#?}",st);
    let ret = quote! {
        #[async_trait::async_trait]
        impl SEncode for #struct_ident {
            async fn encode<T: tokio::io::AsyncWrite + Unpin + Send>(&self, s: &mut T) -> Result<(), SError> {
                #body
                Ok(())
            }
        }
    };

    Ok(ret)
}

type StructFields = syn::punctuated::Punctuated<syn::Field, syn::Token!(,)>;

fn get_fields_from_derive_input(d: &syn::DeriveInput) -> syn::Result<&StructFields> {
    if let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(syn::FieldsNamed { ref named, .. }),
        ..
    }) = d.data
    {
        return Ok(named);
    }
    Err(syn::Error::new_spanned(
        d,
        "Must define on a Struct, not Enum".to_string(),
    ))
}
type EnumVariants = syn::punctuated::Punctuated<syn::Variant, syn::Token!(,)>;

fn get_variants_from_derive_input(d: &syn::DeriveInput) -> syn::Result<&EnumVariants> {
    if let syn::Data::Enum(syn::DataEnum {
        variants: ref vars, ..
    }) = d.data
    {
        return Ok(vars);
    }
    Err(syn::Error::new_spanned(
        d,
        "Must define on a Struct, not Enum".to_string(),
    ))
}
fn generate_enum_encode_varints(
    fields: &EnumVariants,
    _repr_type: &syn::Type,
) -> syn::Result<proc_macro2::TokenStream> {
    // eprintln!("{:#?}", idents);

    // eprintln!("{:#?}", fields);
    let mut token_stream = quote! {};
    let unit_idents: Vec<_> = fields
        .iter()
        .filter(|x| x.fields == syn::Fields::Unit)
        .map(|f| &f.ident)
        .collect();
    for ident in unit_idents {
        let tokenstream_piece = quote! {
            Self::#ident => { },

        };
        token_stream.extend(tokenstream_piece);
    }
    for idents in fields
        .iter()
        .filter(|x| x.fields != syn::Fields::Unit)
        .map(|f| &f.ident)
    {
        let tokenstream_piece = quote! {
            Self::#idents(val) => {
                val.encode(s).await?;
            },

        };
        token_stream.extend(tokenstream_piece);
    }
    Ok(token_stream)
}

fn generate_enum_decode_varints(
    fields: &EnumVariants,
    _repr_type: &syn::Type,
) -> syn::Result<proc_macro2::TokenStream> {
    // eprintln!("{:#?}", idents);

    // eprintln!("{:#?}", fields);
    let fields = fields.iter();
    let mut token_stream = quote! {};
    for ident in fields {
        if ident.fields == syn::Fields::Unit {
            //eprintln!("{:#?}", ident);
            let ident = &ident.ident;
            let ident_name = quote::format_ident!("{}_TAG", ident)
                .to_string()
                .to_uppercase();
            let ident_name = quote::format_ident!("{}", ident_name);
            let tokenstream_piece = quote! {
                #ident_name => Self::#ident,
            };
            token_stream.extend(tokenstream_piece);
        } else {
            //eprintln!("{:#?}", ident);
            let ident_name = ident.ident.clone();
            let ident_tag = quote::format_ident!("{}_TAG", ident.ident.to_string().to_uppercase());
            let field_type = ident.fields.iter().next().unwrap().ty.clone();
            if ident.fields.iter().count() > 1 {
                return Err(syn::Error::new_spanned(
                    ident,
                    "Only one field is supported for non-unit variants".to_string(),
                ));
            }
            let tokenstream_piece = quote! {
                #ident_tag => {
                    let val = <#field_type as SDecode>::decode(s).await?;
                    Self::#ident_name(val)
                },

            };
            token_stream.extend(tokenstream_piece);
        }
    }

    Ok(token_stream)
}

fn generate_enum_discriminants(
    fields: &EnumVariants,
    repr: &syn::Type,
) -> syn::Result<proc_macro2::TokenStream> {
    // eprintln!("{:#?}", idents);

    //eprintln!("{:#?}", fields);
    let mut ret = quote! {};
    let mut counter = 0;
    let mut lit = syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(syn::LitInt::new("0", proc_macro2::Span::call_site())),
        attrs: vec![],
    });
    for idents in fields {
        if let Some((
            _,
            lit_int, // syn::Expr::Lit(syn::ExprLit {
                     //     lit: syn::Lit::Int(lit_int),
                     //     ..
                     // }),
        )) = &idents.discriminant
        {
            let ident = &idents.ident;
            let tag_ident = quote::format_ident!("{}_TAG", ident.to_string().to_uppercase());
            ret.extend(quote! {
                const #tag_ident : #repr = #lit_int;
            });
            counter = 1;
            lit = lit_int.clone();

            //eprintln!("{:#?}", lit_int);
        } else {
            let ident = &idents.ident;
            let tag_ident = quote::format_ident!("{}_TAG", ident.to_string().to_uppercase());
            ret.extend(quote! {
                      const #tag_ident : #repr = #lit + (#counter as #repr);
            });
            counter += 1;
        }
    }
    //eprint!("{:#?}", ret);
    Ok(ret)
}

fn generate_struct_encode_fields(fields: &StructFields) -> syn::Result<proc_macro2::TokenStream> {
    let idents: Vec<_> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    let mut token_stream = quote! {};
    for (ident, _type) in idents.iter().zip(types.iter()) {
        let tokenstream_piece = quote! {
            self.#ident.encode(s).await?;

        };
        token_stream.extend(tokenstream_piece);
    }
    Ok(token_stream)
}

/// Derive [`shadowquic::SDecode`] automatically for the struct or enum.
/// For struct, it decodes each field in order. For enum, it first decodes a u8/u16... defined by `#[repr(*)]` as discriminant and then decodes the content based on the value of disriminant.
/// For enum variants, at most one field is supported. Named field/or tuple field is not supported for enum.
/// `#[repr(*)]` is required for enum to specify the type of discriminant.
/// For structs, `#[size_tag]` reads a `u32` byte length before the field payload, ignores trailing payload bytes,
/// and zero-pads missing trailing bytes up to a bounded compatibility limit.
#[proc_macro_derive(SDecode, attributes(size_tag))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);

    let ret = match ast.data {
        syn::Data::Struct(_) => impl_struct_decode(&ast),
        syn::Data::Enum(_) => impl_enum_decode(&ast),
        syn::Data::Union(..) => Err(syn::Error::new_spanned(
            ast,
            "Union is not supported by SEncode macro".to_string(),
        )),
    };
    match ret {
        Ok(token_stream) => token_stream.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn impl_struct_decode(st: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_ident = &st.ident;
    let fields = get_fields_from_derive_input(st)?;
    let builder_struct_fields_def = generate_decode_fields(fields)?;

    let has_size_tag = st.attrs.iter().any(|attr| attr.path().is_ident("size_tag"));

    let body = if has_size_tag {
        quote! {
            use tokio::io::AsyncReadExt;
            let len = u32::decode(s).await? as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).await?;
            const COMPAT_PADDING_LIMIT: usize = 1024;
            let mut reader = (&buf[..]).chain(tokio::io::repeat(0).take(COMPAT_PADDING_LIMIT as u64));
            let s = &mut reader;
            Ok(Self {
                #builder_struct_fields_def
            })
        }
    } else {
        quote! {
            Ok(Self {
                #builder_struct_fields_def
            })
        }
    };

    //eprintln!("{:#?}",st);
    let ret = quote! {
        #[async_trait::async_trait]
        impl SDecode for #struct_ident {
            async fn decode<T: tokio::io::AsyncRead + Unpin + Send>(s: &mut T) -> Result<Self, SError> {
               #body
            }
        }
    };

    Ok(ret)
}

fn generate_decode_fields(fields: &StructFields) -> syn::Result<proc_macro2::TokenStream> {
    let idents: Vec<_> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<_> = fields.iter().map(|f| &f.ty).collect();

    let mut token_stream = quote! {};
    for (ident, type_) in idents.iter().zip(types.iter()) {
        let tokenstream_piece = quote! {
            #ident: #type_::decode(s).await?,
        };

        token_stream.extend(tokenstream_piece);
    }
    Ok(token_stream)
}
