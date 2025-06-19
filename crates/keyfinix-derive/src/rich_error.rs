use http::{StatusCode, status::InvalidStatusCode};
use proc_macro2::Span;
use quote::{ToTokens, quote};
use sha2::{Digest, Sha256};
use syn::{Data, Fields, GenericParam, Ident, Lit};
use uuid::Uuid;

pub struct RichErrorEnum {
    pub crate_name: String,
    pub name: Ident,
    pub fallback_http: StatusCode,
    pub kind_ty: syn::Type,
    pub variants: Vec<RichErrorVariant>,
    pub generics: syn::Generics,
}

fn sha256_uuid(s: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(s);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    Uuid::new_v8(bytes)
}

impl RichErrorEnum {
    pub fn impl_rich_error(&self) -> Result<impl ToTokens, syn::Error> {
        let (name, kind_ty) = (self.name.clone(), self.kind_ty.clone());
        let kind_assoc = quote! {
            type Kind = #kind_ty;
        };

        let selector = |v: &RichErrorVariant| {
            let v_name = &v.name;
            match &v.fields {
                Fields::Named(_) => {
                    quote! {
                       _private_this@#name::#v_name { .. }
                    }
                }
                Fields::Unnamed(fields) => {
                    let unnamed = fields.unnamed.len();
                    let selectors = (0..unnamed)
                        .map(|i| Ident::new(&format!("_{}", i), Span::call_site()))
                        .collect::<Vec<_>>();
                    quote! {
                        _private_this@#name::#v_name(#(#selectors),*)
                    }
                }
                Fields::Unit => {
                    quote! {
                        _private_this@#name::#v_name
                    }
                }
            }
        };

        let kind_fn = self
            .variants
            .iter()
            .map(|v| {
                let selector = selector(v);
                if v.kind_ctor_or_inherit.is_none() {
                    quote! {
                        #selector => RichError::kind(_0).into(),
                    }
                } else {
                    let ctor = v.kind_ctor_or_inherit.clone().unwrap();
                    quote! {
                        #selector => #ctor,
                    }
                }
            })
            .collect::<Vec<_>>();

        let kind_fn = quote! {
            fn kind(&self) -> Self::Kind {
                match self {
                    #(#kind_fn)*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }
            }
        };

        let http_fn = self
            .variants
            .iter()
            .map(|v| {
                let selector = selector(v);
                if v.kind_ctor_or_inherit.is_none() && v.http.is_none() {
                    quote! {
                        #selector => RichError::http_status(_0),
                    }
                } else {
                    let http = v.http.unwrap_or(self.fallback_http).as_u16();
                    quote! {
                        #selector => #http.try_into().unwrap(),
                    }
                }
            })
            .collect::<Vec<_>>();

        let http_fn = quote! {
            fn http_status(&self) -> ::http::StatusCode {
                match self {
                    #(#http_fn)*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }
            }
        };

        let uuid_fn = self
            .variants
            .iter()
            .map(|v| {
                let name = v.name.clone();
                let key = format!("{}::{}::{}", self.crate_name, self.name, name);
                let uuid = sha256_uuid(&key);

                let uuid = uuid.to_string();
                let selector = selector(v);
                quote! {
                    #selector => ::uuid::uuid!(#uuid),
                }
            })
            .collect::<Vec<_>>();

        let uuid_fn = quote! {
            fn uuid(&self) -> ::uuid::Uuid {
                match self {
                    #(#uuid_fn)*
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                }
            }
        };

        let generics = self.generics.clone();
        let mut generics_without_constraints = generics.clone();
        generics_without_constraints
            .params
            .iter_mut()
            .for_each(|param| {
                if let GenericParam::Type(t) = param {
                    t.bounds.clear();
                    t.colon_token = None;
                    t.default = None;
                    t.eq_token = None;
                }
            });

        Ok(quote! {
            impl #generics RichError for #name #generics_without_constraints {
                #kind_assoc
                #kind_fn
                #http_fn
                #uuid_fn
            }
        })
    }
}

pub struct RichErrorVariant {
    pub name: Ident,
    pub fields: Fields,
    pub http: Option<StatusCode>,
    pub kind_ctor_or_inherit: Option<syn::Expr>,
}

fn http_lit_to_u16(lit: Lit) -> Result<StatusCode, syn::Error> {
    match lit {
        Lit::Int(lit) => StatusCode::from_u16(lit.base10_parse::<u16>()?)
            .map_err(|e| syn::Error::new(lit.span(), e.to_string())),
        Lit::Str(lit) => lit
            .value()
            .parse()
            .map_err(|e: InvalidStatusCode| syn::Error::new(lit.span(), e.to_string())),
        _ => Err(syn::Error::new(
            lit.span(),
            "Expected a string or integer literal",
        )),
    }
}

impl TryFrom<syn::DeriveInput> for RichErrorEnum {
    type Error = syn::Error;

    fn try_from(data: syn::DeriveInput) -> Result<Self, Self::Error> {
        let crate_name = std::env::var("CARGO_PKG_NAME").unwrap();

        let name = data.ident;
        match data.data {
            Data::Enum(r#enum) => {
                let fallback_http = data
                    .attrs
                    .iter()
                    .find_map(|attr| {
                        if attr.path().is_ident("http") {
                            Some(attr.parse_args::<Lit>().unwrap())
                        } else {
                            None
                        }
                    })
                    .map(http_lit_to_u16)
                    .transpose()?
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

                let kind_ty = data
                    .attrs
                    .iter()
                    .find_map(|attr| {
                        if attr.path().is_ident("kind") {
                            Some(attr.parse_args::<syn::Type>())
                        } else {
                            None
                        }
                    })
                    .transpose()?
                    .ok_or_else(|| {
                        syn::Error::new(
                            name.span(),
                            "Expected a kind attribute on the enum to indicate ErrorKind",
                        )
                    })?;

                let variants = r#enum
                    .variants
                    .into_iter()
                    .map(|v| {
                        let ident_span = v.ident.span();

                        let inherit = v
                            .attrs
                            .iter()
                            .find(|attr| attr.path().is_ident("inherit"))
                            .is_some();

                        let name = v.ident;
                        let http = v
                            .attrs
                            .iter()
                            .find_map(|attr| {
                                if attr.path().is_ident("http") {
                                    Some(attr.parse_args::<Lit>())
                                } else {
                                    None
                                }
                            })
                            .transpose()?
                            .map(http_lit_to_u16)
                            .transpose()?;

                        let kind_ctor_or_inherit = if !inherit {
                                 Some(v
                            .attrs
                            .iter()
                            .find_map(|attr| {
                                if attr.path().is_ident("kind") {
                                    Some(attr.parse_args::<syn::Expr>())
                                } else {
                                    None
                                }
                            })
                            .transpose()?
                            .ok_or_else(|| {
                                syn::Error::new(
                                    ident_span,
                                    format!(
                                        "Expected a kind attribute on the variant {} to indicate ErrorKind",
                                        name
                                    ),
                                )
                            })?)
                        } else {
                            None
                        };

                        Ok::<_, syn::Error>(RichErrorVariant {
                            name,
                            fields: v.fields,
                            http,
                            kind_ctor_or_inherit,
                        })
                    })
                    .try_fold(Vec::new(), |mut acc, v| {
                        v.map(|v| {
                            acc.push(v);
                            acc
                        })
                    })?;

                Ok(RichErrorEnum {
                    crate_name,
                    name,
                    fallback_http,
                    kind_ty,
                    variants,
                    generics: data.generics,
                })
            }
            _ => Err(syn::Error::new(name.span(), "Expected an enum")),
        }
    }
}
