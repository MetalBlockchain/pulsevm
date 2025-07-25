#![no_std]
extern crate alloc;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

mod internal;
mod name;
mod num_bytes;
mod read;
mod write;

#[inline]
#[proc_macro]
pub fn name(input: TokenStream) -> TokenStream {
    use crate::name::PulseName;
    let item = parse_macro_input!(input as PulseName);
    quote!(#item).into()
}

#[inline]
#[proc_macro_derive(NumBytes)]
pub fn derive_num_bytes(input: TokenStream) -> TokenStream {
    use crate::num_bytes::DeriveNumBytes;
    let item = parse_macro_input!(input as DeriveNumBytes);
    quote!(#item).into()
}

#[inline]
#[proc_macro_derive(Read)]
pub fn read(input: TokenStream) -> TokenStream {
    use crate::read::DeriveRead;
    let item = parse_macro_input!(input as DeriveRead);
    quote!(#item).into()
}

#[inline]
#[proc_macro_derive(Write)]
pub fn write(input: TokenStream) -> TokenStream {
    use crate::write::DeriveWrite;
    let item = parse_macro_input!(input as DeriveWrite);
    quote!(#item).into()
}
