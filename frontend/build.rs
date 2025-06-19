fn main() {
    ui_box::pack();
}

mod ui_box {
    use std::{
        io::{Cursor, Read},
        path::PathBuf,
        str::FromStr,
    };

    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use proc_macro2::TokenStream;
    use quote::quote;
    use sha2::Digest;

    const UI_DIST_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/ui/dist");

    struct File {
        name: String,
        size: u64,
        original_size: u64,
        buffer: Vec<u8>,
    }

    fn discover_files(base_dir: PathBuf, prefix: String) -> Vec<File> {
        let mut files: Vec<File> = Vec::new();
        for entry in std::fs::read_dir(&base_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let mut data = std::fs::read(&path).unwrap();
                let size = data.len();

                if size > 2 << 10 {
                    let mut gzip = flate2::bufread::GzEncoder::new(
                        Cursor::new(&data),
                        flate2::Compression::best(),
                    );
                    let mut gzip_buffer = Vec::new();
                    gzip.read_to_end(&mut gzip_buffer).unwrap();
                    if gzip_buffer.len() < size * 4 / 5 {
                        data = gzip_buffer;
                    }
                }

                files.push(File {
                    name: format!("{}/{}", prefix, path.file_name().unwrap().to_str().unwrap()),
                    size: data.len() as u64,
                    original_size: size as u64,
                    buffer: data,
                });
            } else if path.is_dir() {
                files.extend(discover_files(
                    base_dir.join(&path),
                    format!("{}/{}", prefix, path.file_name().unwrap().to_str().unwrap()),
                ));
            } else {
                panic!("Unknown file type: {:?}", path);
            }
        }
        files
    }

    pub fn pack() {
        let files = discover_files(UI_DIST_DIR.into(), String::new());
        println!("cargo:rerun-if-changed={}", UI_DIST_DIR);

        let buffer_codegen = |buffer: &[u8]| {
            let mut buffer_code = buffer.iter().fold(String::from("b\""), |mut acc, b| {
                acc.push_str(&format!("\\x{:02x}", b));
                acc
            });
            buffer_code.push_str("\"");
            buffer_code
        };

        let map_code =
            files.iter().fold(String::new(), |mut acc, f| {
                acc.push_str(&format!(
                "File {{ name: \"{}\", size: {}, original_size: {}, buffer: {}, mime: \"{}\", etag: \"{}\" }},",
                f.name,
                f.size,
                f.original_size,
                buffer_codegen(&f.buffer),
                mime_guess::from_path(&f.name).first_or_text_plain().essence_str(),
                format!("\\\"{}\\\"", BASE64_URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&f.buffer)))
            ));
                acc
            });
        let map_code = TokenStream::from_str(&map_code).unwrap();

        let code = quote! {
            struct File {
                pub name: &'static str,
                pub size: u64,
                pub original_size: u64,
                pub buffer: &'static [u8],
                pub mime: &'static str,
                pub etag: &'static str,
            }

            impl File {
                const fn is_gzipped(&self) -> bool {
                    self.size != self.original_size
                }
            }

            static UI_DIST_FILES: &[File] = &[
                #map_code
            ];
        };

        let out_dir = std::env::var("OUT_DIR").unwrap();
        let out_path = PathBuf::from(out_dir).join("ui_box.rs");
        std::fs::write(out_path, code.to_string()).unwrap();
    }
}
