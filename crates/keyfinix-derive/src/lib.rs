use proc_macro::TokenStream;
use quote::ToTokens;
use rich_error::RichErrorEnum;
use syn::{DeriveInput, ExprLit, GenericParam, parse_macro_input};

mod rich_error;

#[proc_macro_derive(RichError, attributes(http, kind, inherit))]
pub fn derive_rich_error(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    derive_rich_error_impl(ast).into()
}

fn derive_rich_error_impl(ast: DeriveInput) -> proc_macro2::TokenStream {
    let rich_error = RichErrorEnum::try_from(ast).expect("Failed to parse rich error");
    rich_error
        .impl_rich_error()
        .map(|ts| ts.into_token_stream())
        .unwrap_or_else(syn::Error::into_compile_error)
}
