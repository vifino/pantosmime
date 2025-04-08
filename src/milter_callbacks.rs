use anyhow::Result;
use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::{Bytes, BytesMut};
use indymilter::{
    Actions, Callbacks, Context, ContextActions, EomActions, EomContext, IntoCString,
    NegotiateContext, Status,
};
use std::borrow::Cow;
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::mime_parser::MimeContainer;
use crate::smime;

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

    headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    body: BytesMut,
}

/// Negotiate the required actions for the signing/encrypting dance.
async fn on_negotiate<'a>(context: &mut NegotiateContext<MilterContext<'a>>) -> Status {
    // We need a few special actions.
    context.requested_actions |=
        Actions::ADD_HEADER | Actions::CHANGE_HEADER | Actions::REPLACE_BODY;

    Status::Continue
}

/// Check if sender is in whitelist.
async fn on_mail<'a>(context: &mut Context<MilterContext<'a>>, args: Vec<CString>) -> Status {
    // TODO: Check if this sender is in our whitelist, if not, we should send
    // Status::Accept to stop processing.
    if let Some(sender) = args.into_iter().next() {
        let sender = sender.to_string_lossy().to_string();
        context.data = Some(MilterContext {
            sender,
            recipients: Vec::new(),
            ..Default::default()
        });
        Status::Continue
    } else {
        // TODO: log
        Status::Reject
    }
}

/// Check if keys are available for recipient.
/// If yes, add to recipients, otherwise reject
async fn on_rcpt<'a>(context: &mut Context<MilterContext<'a>>, args: Vec<CString>) -> Status {
    // TODO: Normalize?
    if let Some(sender) = args.into_iter().next() {
        if let Some(ctx) = &mut context.data {
            ctx.recipients.push(sender.to_string_lossy().to_string());
            Status::Continue
        } else {
            // TODO: log
            Status::Reject
        }
    } else {
        // TODO: log
        Status::Reject
    }
}

/// Process headers
async fn on_header<'a>(
    context: &mut Context<MilterContext<'a>>,
    name: CString,
    value: CString,
    responsible: Arc<Vec<String>>,
) -> Status {
    let ctx = match context.data.as_mut() {
        Some(ctx) => ctx,
        None => return Status::Reject,
    };

    if ctx.action.is_none() {
        // Fate hasn't been decided yet.
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
            Some(action) => ctx.action = Some(action),
            None => return Status::Accept, // TODO: no further processing, log
        };
    };

    let name = name.to_string_lossy();
    let value = value.to_string_lossy();
    let interesting_headers = vec![
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "Content-Disposition",
    ];
    if !interesting_headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&name))
    {
        ctx.headers
            .push((Cow::Owned(name.to_string()), Cow::Owned(value.to_string())));
    }
    Status::Continue
}

/// Check if Headers are complete enough to encrypt content.
async fn on_eoh<'a>(context: &mut Context<MilterContext<'a>>) -> Status {
    // TODO: Check if headers are complete, then Continue, otherwise Reject
    if let Some(ctx) = &mut context.data {
        if ctx.headers.is_empty() {
            // TODO: log, no headers
            return Status::Reject;
        }
        Status::Continue
    } else {
        // TODO: log
        Status::Reject
    }
}

/// Parse body
async fn on_body<'a>(context: &mut Context<MilterContext<'a>>, data: Bytes) -> Status {
    if let Some(ctx) = &mut context.data {
        ctx.body.extend_from_slice(&data);
        Status::Continue
    } else {
        Status::Reject
    }
}

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
                actions
                    .change_header(
                        current_key.into_c_string(),
                        1,
                        Some(updated_value.into_c_string()),
                    )
                    .await?;
            }
        } else {
            actions
                .add_header(updated_key.into_c_string(), updated_value.into_c_string())
                .await?;
        }
    }
    // TODO: If a key exists in current headers, but not the new ones, it should be deleted. But is
    // this necessary?
    Ok(())
}

/// Actually rewrite the content!
async fn on_eom<'a>(context: &mut EomContext<MilterContext<'a>>, cert_dir: PathBuf) -> Status {
    let ctx = match context.data.as_mut() {
        Some(ctx) => ctx,
        None => return Status::Reject,
    };

    let action = match &ctx.action {
        Some(a) => a,
        None => return Status::Reject, // TODO: log error
    };

    match action {
        MilterAction::Encrypt => {
            // Encrypt and encode actual body.
            let encrypted = match smime::encrypt_data(&ctx.body, &ctx.recipients, &cert_dir) {
                Ok(data) => data,
                Err(_) => return Status::Reject, // TODO: log
            };
            let encoded = BASE64_STANDARD.encode(&encrypted);
            let wrapped_len = encoded.len() + (encoded.len() / 76) * 2 + 2;
            let mut wrapped = BytesMut::with_capacity(wrapped_len);
            line_wrap::line_wrap(&mut wrapped, encoded.len(), 76, &line_wrap::crlf());

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

            if let Err(_) = update_headers(ctx, &context.actions, new_headers).await {
                // TODO: log error
                return Status::Reject;
            }

            if context.actions.replace_body(&wrapped).await.is_err() {
                return Status::Reject;
            }
            Status::Accept
        }

        MilterAction::ExtractKeys => {
            // Parse using MIME Parser.
            let body_str = String::from_utf8_lossy(&ctx.body);
            let container = match MimeContainer::parse_mime_container_data(
                &body_str,
                ctx.headers.clone(), // TODO: eliminate clone
            ) {
                Ok((_, container)) => container,
                Err(_) => return Status::Reject, // TODO: log error
            };

            // TODO: Check if smime signed message
            // TODO: Iterate through message parts to find one with content type "application/pkcs7-signature".
            // TODO: De-B64 and validate if cert is valid for sender?
            // TODO: Save DER into <sender>.p7s file.
            todo!()
        }
    }
}

pub fn assemble_callbacks<'a>(
    cert_dir: PathBuf,
    responsible: Arc<Vec<String>>,
) -> Callbacks<MilterContext<'a>> {
    Callbacks::new()
        .on_negotiate(|context, _, _| Box::pin(on_negotiate(context)))
        .on_mail(|context, args| Box::pin(on_mail(context, args)))
        .on_rcpt(|context, args| Box::pin(on_rcpt(context, args)))
        .on_header(move |context, name, value| {
            Box::pin(on_header(context, name, value, Arc::clone(&responsible)))
        })
        .on_eoh(|context| Box::pin(on_eoh(context)))
        .on_body(|context, data| Box::pin(on_body(context, data)))
        .on_eom(move |context| Box::pin(on_eom(context, cert_dir.clone())))
}
