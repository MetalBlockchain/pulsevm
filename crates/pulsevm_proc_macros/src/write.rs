use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote, quote_spanned};
use syn::{
    Data, DeriveInput, Fields, GenericParam, Generics, Ident, Index,
    parse::{Parse, ParseStream, Result as ParseResult},
    parse_quote,
    spanned::Spanned,
};

pub struct DeriveWrite {
    ident: Ident,
    generics: Generics,
    data: Data,
}

impl Parse for DeriveWrite {
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
                    .push(parse_quote!(pulsevm_serialization::Write));
            }
        }
        Ok(Self {
            ident,
            generics,
            data,
        })
    }
}

impl ToTokens for DeriveWrite {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let name = &self.ident;
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();
        let call_site = ::proc_macro2::Span::call_site();
        let var = quote!(self);
        let writes = match &self.data {
            Data::Struct(data) => match data.fields {
                Fields::Named(ref fields) => {
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        let access = quote_spanned!(call_site => #var.#name);
                        quote_spanned! { f.span() =>
                            pulsevm_serialization::Write::write(&#access, bytes, pos)?;
                        }
                    });
                    quote! {
                        #(#recurse)*
                        Ok(())
                    }
                }
                Fields::Unnamed(ref fields) => {
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index {
                            index: i as u32,
                            span: call_site,
                        };
                        let access = quote_spanned!(call_site => #var.#index);
                        quote_spanned! { f.span() =>
                            pulsevm_serialization::Write::write(&#access, bytes, pos)?;
                        }
                    });
                    quote! {
                        #(#recurse)*
                        Ok(())
                    }
                }
                Fields::Unit => {
                    quote! {
                        Ok(())
                    }
                }
            },
            Data::Enum(_) | Data::Union(_) => unimplemented!(),
        };

        let expanded = quote! {
            #[automatically_derived]
            #[allow(unused_qualifications)]
            impl #impl_generics pulsevm_serialization::Write for #name #ty_generics #where_clause {
                #[inline]
                fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
                    #writes
                }
            }
        };

        expanded.to_tokens(tokens);
    }
}
