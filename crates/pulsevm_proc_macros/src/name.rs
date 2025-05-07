use proc_macro2::{Literal, TokenStream};
use pulsevm_name::name_from_bytes;
use quote::{ToTokens, TokenStreamExt};
use syn::{
    LitStr,
    parse::{Parse, ParseStream, Result as ParseResult},
};

pub struct PulseName(u64);

impl Parse for PulseName {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        let name = input.parse::<LitStr>()?.value();
        name_from_bytes(name.bytes())
            .map(Self)
            .map_err(|_e| input.error("failed to parse name"))
    }
}

impl ToTokens for PulseName {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append(Literal::u64_suffixed(self.0))
    }
}
