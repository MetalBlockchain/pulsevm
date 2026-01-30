use proc_macro::TokenStream;
use pulsevm_name::Name;
use quote::quote;
use syn::parse_macro_input;

#[inline]
#[proc_macro]
pub fn name(input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as Name);
    quote!(#item).into()
}
