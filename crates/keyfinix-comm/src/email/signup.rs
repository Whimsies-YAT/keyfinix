use askama::Template;

#[allow(missing_docs)]
pub struct SignupTemplateData {
    pub service_name: String,
    pub display_name: String,
    pub verification_url: String,
}

impl<'a> From<&'a SignupTemplateData> for (SignupTemplateText<'a>, SignupTemplateHtml<'a>) {
    fn from(val: &'a SignupTemplateData) -> Self {
        (
            SignupTemplateText { data: val },
            SignupTemplateHtml { data: val },
        )
    }
}

#[derive(Template)]
#[template(path = "signup.txt")]
#[allow(missing_docs)]
pub struct SignupTemplateText<'a> {
    data: &'a SignupTemplateData,
}

#[derive(Template)]
#[template(path = "signup.html")]
#[allow(missing_docs)]
pub struct SignupTemplateHtml<'a> {
    data: &'a SignupTemplateData,
}
