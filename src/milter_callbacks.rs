use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use bytes::{Bytes, BytesMut};
use indymilter::{
    Actions, Callbacks, Context, ContextActions, EomActions, EomContext, IntoCString, MacroStage,
    Macros, NegotiateContext, Status,
};
use lazy_static::lazy_static;
use regex::Regex;
use std::borrow::Cow;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::mime_parser::MimeContainer;
use crate::smime;

#[derive(Debug)]
pub enum MilterAction {
    Encrypt,
    ExtractKeys,
}

/// Context to carry across the steps.
#[derive(std::default::Default)]
pub struct MilterContext<'a> {
    action: Option<MilterAction>,
    sender: String,
    recipients: Vec<String>,
    queue_id: Option<String>,

    headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    body: BytesMut,
}

/// Extracts the email address from a sender/recipient field.
pub fn extract_email(input: &str) -> Option<&str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"(?i)<([^>]+)>|^([^<>\s]+@[^<>\s]+)$"#).unwrap();
    }

    let input = input.trim();

    RE.captures(input)
        .and_then(|caps| caps.get(1).or_else(|| caps.get(2)))
        .map(|m| m.as_str())
}

/// Try to get Queue ID from the macros of the current context.
fn get_queue_id_macro<'a>(macros: &Macros) -> Option<String> {
    macros
        .get(c"i")
        .and_then(|cstr| Some(cstr.to_string_lossy().into_owned()))
}

fn try_get_queue_id<'a>(macros: &Macros, context: &mut Option<MilterContext<'a>>) -> String {
    let ctx = match context {
        Some(ctx) => ctx,
        None => {
            return String::from("<none>");
        }
    };

    if ctx.queue_id.is_none() {
        ctx.queue_id = get_queue_id_macro(macros);
    }
    ctx.queue_id.clone().unwrap_or(String::from("<none>"))
}

/// Negotiate the required actions for the signing/encrypting dance.
#[tracing::instrument(skip(context))]
async fn on_negotiate<'a>(context: &mut NegotiateContext<MilterContext<'a>>) -> Status {
    // We need a few special actions.
    context.requested_actions |=
        Actions::ADD_HEADER | Actions::CHANGE_HEADER | Actions::REPLACE_BODY;
    info!("Negotiating actions: added ADD_HEADER, CHANGE_HEADER, and REPLACE_BODY");

    let macros = &mut context.requested_macros;
    macros.insert(MacroStage::Mail, c"i".into());
    macros.insert(MacroStage::Rcpt, c"i".into());
    macros.insert(MacroStage::Eoh, c"i".into());
    macros.insert(MacroStage::Data, c"i".into());
    macros.insert(MacroStage::Eom, c"i".into());

    Status::Continue
}

/// Check if sender is in whitelist.
#[tracing::instrument(skip(context, args), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_mail<'a>(context: &mut Context<MilterContext<'a>>, args: Vec<CString>) -> Status {
    if let Some(sender) = args.into_iter().next() {
        let sender_email = match extract_email(&sender.to_string_lossy()) {
            Some(mail) => mail.to_string(),
            None => {
                error!(?sender, "Could not extract sender email");
                return Status::Reject;
            }
        };
        debug!(%sender_email, "Sender accepted and context initialized");
        context.data = Some(MilterContext {
            sender: sender_email,
            recipients: Vec::new(),
            ..Default::default()
        });
        Status::Continue
    } else {
        warn!("No sender provided in on_mail; rejecting message");
        Status::Reject
    }
}

/// Check if keys are available for recipient.
/// If yes, add to recipients, otherwise reject
#[tracing::instrument(skip(context, args), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_rcpt<'a>(context: &mut Context<MilterContext<'a>>, args: Vec<CString>) -> Status {
    if let Some(recipient) = args.into_iter().next() {
        if let Some(ctx) = &mut context.data {
            let recipient_email = match extract_email(&recipient.to_string_lossy()) {
                Some(mail) => mail.to_string(),
                None => {
                    error!(?recipient, "Could not extract recipient email");
                    return Status::Reject;
                }
            };
            debug!(%recipient_email, "Added recipient to context");
            ctx.recipients.push(recipient_email);
            Status::Continue
        } else {
            error!("Context data is missing in on_rcpt; rejecting message");
            Status::Reject
        }
    } else {
        warn!("No recipient provided in on_rcpt; rejecting message");
        Status::Reject
    }
}

/// Process headers
#[tracing::instrument(skip(context, name, value, responsible), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_header<'a>(
    context: &mut Context<MilterContext<'a>>,
    name: CString,
    value: CString,
    responsible: Arc<Vec<String>>,
) -> Status {
    let ctx = match context.data.as_mut() {
        Some(ctx) => ctx,
        None => {
            error!("Missing context data in on_header; rejecting message");
            return Status::Reject;
        }
    };

    // Decide on action if not already set.
    if ctx.action.is_none() {
        match responsible.as_ref().iter().find_map(|e| {
            let e = e.as_str();
            if e.eq_ignore_ascii_case(&ctx.sender) {
                Some(MilterAction::Encrypt)
            } else if ctx.recipients.iter().any(|r| r.eq_ignore_ascii_case(e)) {
                Some(MilterAction::ExtractKeys)
            } else {
                None
            }
        }) {
            Some(action) => {
                info!("Need to perform {:?} on message", action);
                ctx.action = Some(action);
            }
            None => {
                debug!("Not responsible for neither sender nor recipients; no further processing");
                return Status::Accept;
            }
        };
    };

    let name_str = name.to_string_lossy();
    let value_str = value.to_string_lossy();
    let interesting_headers = vec![
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "Content-Disposition",
    ];
    if interesting_headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&name_str))
    {
        ctx.headers.push((
            Cow::Owned(name_str.to_string()),
            Cow::Owned(value_str.to_string()),
        ));
        debug!(header = %name_str, value = %value_str, "Added custom header");
    }
    Status::Continue
}

/// Check if Headers are complete enough to encrypt content.
#[tracing::instrument(skip(context), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_eoh<'a>(context: &mut Context<MilterContext<'a>>) -> Status {
    if let Some(ctx) = &mut context.data {
        if ctx.headers.is_empty() {
            warn!("Headers are empty in on_eoh; rejecting message");
            return Status::Reject;
        }
        info!("Headers are complete");
        Status::Continue
    } else {
        error!("Missing context data in on_eoh; rejecting message");
        Status::Reject
    }
}

/// Parse body
#[tracing::instrument(skip(context, data), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_body<'a>(context: &mut Context<MilterContext<'a>>, data: Bytes) -> Status {
    if let Some(ctx) = &mut context.data {
        ctx.body.extend_from_slice(&data);
        debug!(body_len = %ctx.body.len(), "Accumulated body data");
        Status::Continue
    } else {
        error!("Missing context data in on_body; rejecting message");
        Status::Reject
    }
}

#[tracing::instrument(skip(ctx, actions, new_headers))]
async fn update_headers<'a>(
    ctx: &mut MilterContext<'a>,
    actions: &EomActions,
    new_headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
) -> Result<()> {
    for (updated_key, updated_value) in new_headers.iter() {
        if let Some((current_key, current_value)) = ctx
            .headers
            .iter()
            .find(|t| t.0.as_ref().eq_ignore_ascii_case(updated_key.as_ref()))
        {
            if current_value != updated_value {
                debug!(
                    key = %current_key,
                    old_value = %current_value,
                    new_value = %updated_value,
                    "Changing header"
                );
                actions
                    .change_header(
                        current_key.into_c_string(),
                        1,
                        Some(updated_value.into_c_string()),
                    )
                    .await?;
            }
        } else {
            debug!(
                key = %updated_key,
                value = %updated_value,
                "Adding new header"
            );
            actions
                .add_header(updated_key.into_c_string(), updated_value.into_c_string())
                .await?;
        }
    }
    // TODO: If a key exists in current headers, but not the new ones, it should be deleted. But is
    // this necessary?
    Ok(())
}

fn wrap_bytes_crlf(buf: &mut BytesMut, wrap_at: usize) {
    let line_ending = line_wrap::crlf();
    let len = buf.len();
    let mut additional_len = (len / wrap_at) * 2;
    if len % wrap_at == 0 {
        additional_len -= 2;
    }
    buf.resize(len + additional_len, 0);
    line_wrap::line_wrap(buf, len, wrap_at, &line_ending);
}

/// Actually rewrite the content!
#[tracing::instrument(skip(context, cert_dir), fields(queue = try_get_queue_id(&context.macros, &mut context.data)))]
async fn on_eom<'a>(context: &mut EomContext<MilterContext<'a>>, cert_dir: PathBuf) -> Status {
    let ctx = match context.data.as_mut() {
        Some(ctx) => ctx,
        None => {
            error!("Missing context data in on_eom; rejecting message");
            return Status::Reject;
        }
    };

    let action = match &ctx.action {
        Some(a) => a,
        None => {
            error!("No action determined in on_eom; rejecting message");
            return Status::Reject;
        }
    };

    match action {
        MilterAction::Encrypt => {
            // Encrypt and encode actual body.
            let encrypted = match smime::encrypt_data(&ctx.body, &ctx.recipients, &cert_dir).await {
                Ok(data) => data,
                Err(e) => {
                    error!(error = ?e, "Failed to encrypt message body");
                    return Status::Reject;
                }
            };
            let encoded = BASE64_STANDARD.encode(&encrypted);
            let mut wrapped = BytesMut::from(encoded.as_bytes());
            wrap_bytes_crlf(&mut wrapped, 76);

            // Reserialize and replace changed headers and body.
            let new_headers = vec![
                (Cow::Borrowed("MIME-Version"), Cow::Borrowed("1.0")),
                (
                    Cow::Borrowed("Content-Type"),
                    Cow::Borrowed(
                        "application/pkcs7-mime; name=smime.p7m; smime-type=enveloped-data",
                    ),
                ),
                (
                    Cow::Borrowed("Content-Transfer-Encoding"),
                    Cow::Borrowed("base64"),
                ),
                (
                    Cow::Borrowed("Content-Disposition"),
                    Cow::Borrowed("attachment; filename=smime.p7m"),
                ),
            ];

            if let Err(e) = update_headers(ctx, &context.actions, new_headers).await {
                error!(error = ?e, "Failed to update headers in on_eom for encryption");
                return Status::Reject;
            }

            if context.actions.replace_body(&wrapped).await.is_err() {
                error!("Failed to replace body after encryption");
                return Status::Reject;
            }
            if context
                .actions
                .add_header(
                    "X-PANTOSMIME",
                    "Successfully encrypted plain-text message. Yay!",
                )
                .await
                .is_err()
            {
                error!("Failed adding X-PANOSMIME header")
            };
            info!("Encryption successful, accepting mail");
            Status::Accept
        }

        MilterAction::ExtractKeys => {
            // Parse using MIME Parser.
            let body_str = String::from_utf8_lossy(&ctx.body);
            let container = match MimeContainer::parse_mime_container_data(
                &body_str,
                ctx.headers.clone(), // TODO: eliminate clone if possible
            ) {
                Ok((_, container)) => container,
                Err(e) => {
                    error!(error = ?e, "Failed to parse MIME container in on_eom for key extraction");
                    return Status::Reject;
                }
            };

            // Check if smime signed message
            if !container
                .find_header_value("Content-Type")
                .is_some_and(|e| e.to_lowercase().contains("multipart/signed"))
            {
                info!("Message does not contain multipart/signed content, moving on");
                return Status::Accept;
            }

            // Iterate through message parts to find one with content type "application/pkcs7-signature".
            let signature_part = match container.parts.iter().find(|p| {
                p.find_header_value("Content-Type").is_some_and(|e| {
                    let e = e.to_lowercase();
                    e.contains("application/pkcs7-signature")
                        || e.contains("application/x-pkcs7-signature")
                })
            }) {
                Some(sp) => sp,
                None => {
                    error!(
                        "Message is multipart/signed, but didn't find any PKCS#7 signature part"
                    );
                    return Status::Reject;
                }
            };

            // De-B64 and validate if cert is valid for sender?
            let mut signature_data = signature_part.body.to_string();
            signature_data.retain(|c| !c.is_whitespace());
            let decoded = match BASE64_STANDARD.decode(signature_data.as_bytes()) {
                Ok(data) => data,
                Err(error) => {
                    error!(?error, "Failed to decrypt signature");
                    return Status::Reject;
                }
            };

            // Extract the cert and verify it's got a cert matching the sender.
            let cert_chain = match smime::extract_certificates_from_p7s(&decoded) {
                Ok(chain) => chain,
                Err(error) => {
                    error!(?error, "Failed to extract signers from signature");
                    return Status::Reject;
                }
            };
            if let Err(error) = smime::find_cert_for_email(&cert_chain, &ctx.sender) {
                error!(
                    ?error,
                    "Failed to find signature certificate matching sender"
                );
                return Status::Reject;
            }
            info!(sender = ?ctx.sender, cert_count = ?cert_chain.len(), "Found signature for sender");

            // Save PEM into <sender>.pem file.
            let path = cert_dir.join(format!("{}.pem", ctx.sender));
            if let Err(error) = smime::write_pem_stack(cert_chain, &path).await {
                error!(
                    ?error,
                    "Failed to write signature certificate chain to File"
                );
                return Status::Reject;
            }
            if context
                .actions
                .add_header(
                    "X-PANTOSMIME",
                    "Successfully extracted signature and certificate chain. Yay!",
                )
                .await
                .is_err()
            {
                error!("Failed adding X-PANOSMIME header")
            };
            info!("Successfully extracted certificate chain from Email");
            Status::Accept
        }
    }
}

async fn skip_this() -> Status {
    Status::Continue
}

pub fn assemble_callbacks<'a>(
    cert_dir: PathBuf,
    responsible: Arc<Vec<String>>,
) -> Callbacks<MilterContext<'a>> {
    Callbacks::new()
        .on_negotiate(|context, _, _| Box::pin(on_negotiate(context)))
        .on_connect(|_, _, _| Box::pin(skip_this()))
        .on_helo(|_, _| Box::pin(skip_this()))
        .on_mail(|context, args| Box::pin(on_mail(context, args)))
        .on_rcpt(|context, args| Box::pin(on_rcpt(context, args)))
        .on_data(|_| Box::pin(skip_this()))
        .on_header(move |context, name, value| {
            Box::pin(on_header(context, name, value, Arc::clone(&responsible)))
        })
        .on_eoh(|context| Box::pin(on_eoh(context)))
        .on_body(|context, data| Box::pin(on_body(context, data)))
        .on_eom(move |context| Box::pin(on_eom(context, cert_dir.clone())))
        .on_unknown(|_, _| Box::pin(skip_this()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email_variants() {
        let cases = [
            ("John Doe <john@example.com>", Some("john@example.com")),
            ("<jane@example.com>", Some("jane@example.com")),
            ("foo@bar.com", Some("foo@bar.com")),
            ("  <baz@example.org> ", Some("baz@example.org")),
            ("John Doe", None),
            ("John Doe john@example.com", None),
            ("", None),
            ("   ", None),
        ];

        for (input, expected) in cases {
            assert_eq!(
                extract_email(input),
                expected,
                "Failed on input: {:?}",
                input
            );
        }
    }

    #[test]
    fn test_line_wrap() {
        let mut data = BytesMut::from("testtest".as_bytes());
        wrap_bytes_crlf(&mut data, 4);
        assert_eq!(data, BytesMut::from("test\r\ntest"));

        data = BytesMut::from("testtest".as_bytes());
        wrap_bytes_crlf(&mut data, 6);
        assert_eq!(data, BytesMut::from("testte\r\nst"));
    }
}
