use anyhow::Context;
use anyhow::Result;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::X509;
use std::convert::AsRef;
use std::iter::IntoIterator;
use std::path::PathBuf;

fn load_cert(to: &str, cert_dir: &PathBuf) -> Result<X509> {
    let filename = format!("{}.p7s", to);
    let path = cert_dir.join(filename);

    let cert_content =
        std::fs::read(path).with_context(|| format!("Failed to read certificate for {}", to))?;

    // Decode the DER into an RSA public key.
    Ok(X509::from_der(&cert_content)
        .with_context(|| format!("Failed to parse DER certificate for {}", to))?)
}

pub fn encrypt_data<S, I>(content: &[u8], to: I, cert_dir: &PathBuf) -> Result<Vec<u8>>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut recipients =
        Stack::new().with_context(|| format!("Failed to create Stack for Recipient Certs"))?;
    for mail in to.into_iter() {
        let mail = mail.as_ref();
        let pubkey = load_cert(mail, &cert_dir)
            .with_context(|| format!("Failed to load certificate for {}", mail))?;
        recipients
            .push(pubkey)
            .with_context(|| format!("Failed to add X509 Cert for {} to Stack", mail))?;
    }

    let cipher: Cipher = Cipher::aes_256_cbc();
    let cms = CmsContentInfo::encrypt(&recipients, content, cipher, CMSOptions::BINARY)
        .with_context(|| format!("Failed to encrypt content"))?;

    cms.to_der()
        .with_context(|| format!("Failed to convert CMS result to DER"))
}
