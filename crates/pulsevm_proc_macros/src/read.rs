use alloc::{borrow::ToOwned, string::ToString};
use proc_macro2::TokenStream;
use quote::{ToTokens, quote, quote_spanned};
use syn::{
    Data, DeriveInput, Fields, GenericParam, Generics, Ident,
    parse::{Parse, ParseStream, Result as ParseResult},
    parse_quote,
    spanned::Spanned,
};

pub struct DeriveRead {
    ident: Ident,
    generics: Generics,
    data: Data,
}

impl Parse for DeriveRead {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        let DeriveInput {
            ident,
            mut generics,
            data,
            ..
        } = input.parse()?;
        for param in &mut generics.params {
            if let GenericParam::Type(ref mut type_param) = *param {
                type_param
                    .bounds
                    .push(parse_quote!(pulsevm_serialization::Read));
            }
        }
        Ok(Self {
            ident,
            generics,
            data,
        })
    }
}

impl ToTokens for DeriveRead {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let name = &self.ident;
        let (impl_generics, ty_generics, where_clause) = &self.generics.split_for_impl();
        let call_site = ::proc_macro2::Span::call_site();
        let reads = match &self.data {
            Data::Struct(data) => match data.fields {
                Fields::Named(ref fields) => {
                    let field_reads = fields.named.iter().map(|f| {
                        let ident = &f.ident;
                        let ty = &f.ty;
                        quote_spanned! {f.span() =>
                            let #ident = <#ty as pulsevm_serialization::Read>::read(bytes, pos)?;
                        }
                    });
                    let field_names = fields.named.iter().map(|f| {
                        let ident = &f.ident;
                        quote! {
                            #ident,
                        }
                    });
                    quote! {
                        #(#field_reads)*
                        let item = #name {
                            #(#field_names)*
                        };
                        Ok(item)
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let field_reads = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let ty = &f.ty;
                        let ident_name = "field_".to_owned() + &i.to_string();
                        let ident = Ident::new(&ident_name, call_site);
                        quote_spanned! {f.span() =>
                            let #ident = <#ty as pulsevm_serialization::Read>::read(bytes, pos)?;
                        }
                    });
                    let fields_list = fields.unnamed.iter().enumerate().map(|(i, _f)| {
                        let ident_name = "field_".to_owned() + &i.to_string();
                        let ident = Ident::new(&ident_name, call_site);
                        quote! {
                            #ident,
                        }
                    });
                    quote! {
                        #(#field_reads)*
                        let item = #name(
                            #(#fields_list)*
                        );
                        Ok(item)
                    }
                }
                Fields::Unit => {
                    unimplemented!();
                }
            },
            Data::Enum(_) | Data::Union(_) => unimplemented!(),
        };

        let expanded = quote! {
            #[automatically_derived]
            #[allow(unused_qualifications)]
            impl #impl_generics pulsevm_serialization::Read for #name #ty_generics #where_clause {
                #[inline]
                fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
                    #reads
                }
            }
        };
        expanded.to_tokens(tokens);
    }
}
