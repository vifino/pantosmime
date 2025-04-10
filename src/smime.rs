use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::X509;
use std::convert::AsRef;
use std::iter::IntoIterator;
use std::path::Path;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Extracts signer certificates from PKCS#7 DER file content (.p7s)
fn extract_signers_from_p7s(der_data: &[u8]) -> Result<Stack<X509>> {
    let pkcs7 =
        Pkcs7::from_der(der_data).with_context(|| format!("Failed to parse PKCS#7 data"))?;

    // Use empty cert stack (second param is for additional certs, optional)
    let dummy_stack = Stack::new().context("Failed to create empty X509 stack")?;

    let certs: Stack<X509> = pkcs7
        .signers(&dummy_stack, Pkcs7Flags::empty())
        .with_context(|| "No certificates found in PKCS#7 data")?;

    Ok(certs)
}

/// Finds the first certificate in the list that matches the given email address.
/// It checks Subject Alternative Name (SAN) first, then falls back to Subject DN.
fn find_cert_for_email<'a>(certs: &'a [X509], email: &str) -> Result<&'a X509> {
    certs
        .iter()
        .find(|cert| {
            // Check Subject Alternative Names
            cert.subject_alt_names()
            .map(|san| {
                san.iter()
                    .filter_map(|name| name.email())
                    .any(|san_email| san_email.eq_ignore_ascii_case(email))
            })
            .unwrap_or(false)
        ||
        // Fallback: Check Subject DN for Email or Common Name
        cert.subject_name()
            .entries()
            .filter_map(|entry| {
                let nid = entry.object().nid();
                if nid == Nid::PKCS9_EMAILADDRESS || nid == Nid::COMMONNAME {
                    entry.data().as_utf8().ok().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .any(|name| name.eq_ignore_ascii_case(email))
        })
        .ok_or_else(|| anyhow!("Failed to find cert for {} in cert stack", email))
}

// Loads a certificate stack from a file with multiple PEM certificates
async fn load_pem_stack(cert: impl AsRef<Path>) -> Result<Vec<X509>> {
    let cert_content = fs::read(&cert)
        .await
        .with_context(|| format!("Failed to read certificate {:?}", cert.as_ref()))?;

    Ok(X509::stack_from_pem(&cert_content)
        .with_context(|| format!("Failed to parse PEM certificate {:?}", cert.as_ref()))?)
}

// Write a certificate stack to a file with multiple PEM certificates
async fn write_pem_stack<C, I>(stack: I, to: &Path) -> Result<()>
where
    C: AsRef<X509>,
    I: IntoIterator<Item = C>,
{
    // Open or create the file, truncate it if it already exists.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)
        .await
        .with_context(|| format!("Failed to create PEM file at {:?}", to))?;

    for cert in stack.into_iter() {
        let pem = cert
            .as_ref()
            .to_pem()
            .with_context(|| "Failed to encode certificate to PEM")?;
        file.write_all(&pem)
            .await
            .with_context(|| "Failed to write certificate PEM to file")?;
    }

    Ok(())
}

pub async fn encrypt_data<S, I>(content: &[u8], to: I, cert_dir: &PathBuf) -> Result<Vec<u8>>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut recipients =
        Stack::new().with_context(|| format!("Failed to create Stack for Recipient Certs"))?;
    for mail in to.into_iter() {
        let mail = mail.as_ref();
        let pubkey_chain = load_pem_stack(&cert_dir.join(format!("{}.pem", mail)))
            .await
            .with_context(|| format!("Failed to load certificates for {}", mail))?;
        let pubkey = find_cert_for_email(&pubkey_chain, &mail)?;
        recipients
            .push(pubkey.clone())
            .with_context(|| format!("Failed to add X509 Cert for {} to Stack", mail))?;
    }

    let cipher: Cipher = Cipher::aes_256_cbc();
    let cms = CmsContentInfo::encrypt(&recipients, content, cipher, CMSOptions::BINARY)
        .with_context(|| format!("Failed to encrypt content"))?;

    cms.to_der()
        .with_context(|| format!("Failed to convert CMS result to DER"))
}
