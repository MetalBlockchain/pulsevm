//! `#[derive(ArenaObject)]` — generates the [`ArenaObject`] impl (and the
//! secondary-index declarations) so a table type is a declaration, not
//! boilerplate.
//!
//! ```ignore
//! #[repr(C)]
//! #[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout, ArenaObject)]
//! #[arena(type_id = 3)]
//! struct Account {
//!     id: ObjectId<Account>,       // the `id` field is the primary key
//!     #[arena(index)]              // an ordered-unique secondary index
//!     name: u64,
//!     creation_date: u32,
//!     _pad: u32,
//! }
//! ```
//!
//! For each `#[arena(index)]` field the macro emits a tag type named
//! `<Struct>By<Field>` (e.g. `AccountByName`) so it can be used in
//! `find_by::<Account, AccountByName>(..)`.

use proc_macro::TokenStream;
use quote::{
    format_ident,
    quote,
};
use syn::{
    Data,
    DeriveInput,
    Fields,
    LitInt,
    parse_macro_input,
};

#[proc_macro_derive(ArenaObject, attributes(arena))]
pub fn derive_arena_object(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    // `#[arena(type_id = N)]` on the struct.
    let mut type_id: Option<LitInt> = None;
    for attr in &input.attrs {
        if attr.path().is_ident("arena") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("type_id") {
                    type_id = Some(meta.value()?.parse()?);
                    Ok(())
                } else {
                    Err(meta.error("unknown arena attribute on struct; expected `type_id`"))
                }
            })?;
        }
    }
    let type_id = type_id.ok_or_else(|| {
        syn::Error::new_spanned(name, "missing `#[arena(type_id = N)]` on the struct")
    })?;

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "ArenaObject requires a struct with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "ArenaObject can only be derived for structs",
            ));
        }
    };

    let mut has_id = false;
    let mut ordered_tags = Vec::new();
    let mut hashed_tags = Vec::new();
    let mut index_defs = Vec::new();
    for field in fields {
        let ident = field.ident.as_ref().unwrap();
        if ident == "id" {
            has_id = true;
        }
        let is_index = field
            .attrs
            .iter()
            .any(|a| a.path().is_ident("arena") && attr_has_flag(a, "index"));
        // `#[arena(hash_index)]` picks the O(1) hash backend for a point-only
        // index (no range/iteration); plain `#[arena(index)]` stays ordered.
        let is_hash = field
            .attrs
            .iter()
            .any(|a| a.path().is_ident("arena") && attr_has_flag(a, "hash_index"));
        if is_index || is_hash {
            let field_ty = &field.ty;
            let tag = format_ident!("{}By{}", name, pascal(&ident.to_string()));
            index_defs.push(quote! {
                #[allow(non_camel_case_types)]
                pub struct #tag;
                impl ::pulsevm_arena::IndexedBy<#name> for #tag {
                    type Key = #field_ty;
                    fn key(o: &#name) -> #field_ty {
                        o.#ident
                    }
                }
            });
            if is_hash {
                hashed_tags.push(tag);
            } else {
                ordered_tags.push(tag);
            }
        }
    }

    if !has_id {
        return Err(syn::Error::new_spanned(
            name,
            "ArenaObject requires an `id: ObjectId<Self>` field",
        ));
    }

    let secondary = quote! {
        vec![
            #( ::pulsevm_arena::key_index::<Self, #ordered_tags>(), )*
            #( ::pulsevm_arena::hash_index::<Self, #hashed_tags>(), )*
        ]
    };

    Ok(quote! {
        #( #index_defs )*

        impl ::pulsevm_arena::ArenaObject for #name {
            const TYPE_ID: u16 = #type_id;
            fn id(&self) -> ::pulsevm_arena::ObjectId<Self> {
                self.id
            }
            fn set_id(&mut self, id: ::pulsevm_arena::ObjectId<Self>) {
                self.id = id;
            }
            fn secondary_indices() -> Vec<Box<dyn ::pulsevm_arena::SecondaryIndex<Self>>> {
                #secondary
            }
        }
    })
}

/// True if the `#[arena(..)]` attribute lists a bare `flag` (e.g. `index`).
fn attr_has_flag(attr: &syn::Attribute, flag: &str) -> bool {
    let mut found = false;
    let _ = attr.parse_nested_meta(|meta| {
        if meta.path.is_ident(flag) {
            found = true;
        }
        Ok(())
    });
    found
}

/// snake_case (or a bare word) to PascalCase for the generated tag name.
fn pascal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for c in s.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}
