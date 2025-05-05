use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

mod name;

#[inline]
#[proc_macro]
pub fn name(input: TokenStream) -> TokenStream {
    use crate::name::PulseName;
    let item = parse_macro_input!(input as PulseName);
    quote!(#item).into()
}