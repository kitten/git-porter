//! Human push output from native porcelain and validated receiver results.
//! @ref LLP 0002#push-status
use crate::runtime::push_result::{Forwarded, Outcome, Report, Row};
fn branch(reference: &str) -> &str {
    reference.strip_prefix("refs/heads/").unwrap_or(reference)
}
fn row(
    output: &mut String,
    row: &Row,
    reference: &str,
    reason: Option<&str>,
    style: super::terminal::Style,
) {
    let name = branch(reference);
    if let Some(reason) = reason {
        output.push_str(&format!(
            " ! {} {name} -> {name} ({reason})\n",
            style.status('!', "[remote rejected]")
        ));
    } else {
        let (summary, suffix) = row
            .summary
            .split_once(" (")
            .map(|(s, reason)| (s, format!(" ({reason}")))
            .unwrap_or((&row.summary, String::new()));
        output.push_str(&format!(
            " {} {} {name} -> {name}{suffix}\n",
            row.flag,
            style.status(row.flag, summary)
        ));
    }
}
fn forwarded(
    output: &mut String,
    result: &Forwarded,
    reference: &str,
    quiet: bool,
    style: super::terminal::Style,
) {
    if quiet
        && matches!(result.outcome, Outcome::Complete)
        && result.rows.iter().all(|r| r.flag != '!')
    {
        return;
    }
    output.push_str(&format!(
        "{} {}\n",
        style.heading("Forwarded to"),
        result.url.as_deref().unwrap_or("origin (unresolved)")
    ));
    for native in &result.rows {
        row(output, native, reference, None, style);
    }
    let name = branch(reference);
    let summary = match &result.outcome {
        Outcome::Complete => return,
        Outcome::Published => {
            format!(
                "= {label} {name} -> {name} (intended commit confirmed at origin)",
                label = style.status('=', "[published]")
            )
        }
        Outcome::NotPublished => {
            format!(
                "! {label} {name} -> {name} (origin still at expected old tip)",
                label = style.status('!', "[not published]")
            )
        }
        Outcome::Moved { actual } => format!(
            "! {label} {name} -> {name} (origin now at {}; inspect before retrying)",
            actual.as_ref().map(|s| &s[..7]).unwrap_or("absent"),
            label = style.status('!', "[moved]")
        ),
        Outcome::Unknown => {
            format!(
                "! {label} {name} -> {name} (origin recheck failed; may have published)",
                label = style.status('!', "[unknown]")
            )
        }
        Outcome::NotAttempted { reason } => {
            format!(
                "! {label} {name} -> {name} ({})",
                reason.text(),
                label = style.status('!', "[not attempted]")
            )
        }
    };
    output.push_str(&format!(" {summary}\n"));
}
pub fn render(
    receiver: &str,
    reference: &str,
    native: &[Row],
    result: Option<&Report>,
    quiet: bool,
) -> String {
    render_styled(
        receiver,
        reference,
        native,
        result,
        quiet,
        super::terminal::Style::default(),
    )
}
pub(crate) fn render_terminal(
    receiver: &str,
    reference: &str,
    native: &[Row],
    result: Option<&Report>,
    quiet: bool,
) -> String {
    render_styled(
        receiver,
        reference,
        native,
        result,
        quiet,
        super::terminal::current(),
    )
}
fn render_styled(
    receiver: &str,
    reference: &str,
    native: &[Row],
    result: Option<&Report>,
    quiet: bool,
    style: super::terminal::Style,
) -> String {
    let mut output = String::new();
    let failed = result.is_some_and(|r| !r.receiver_ok) || native.iter().any(|r| r.flag == '!');
    if !quiet || failed {
        output.push_str(&format!("{} {receiver}\n", style.heading("To")));
        if native.is_empty() && failed {
            let reason = result
                .map(|r| {
                    r.receiver_reason
                        .as_deref()
                        .unwrap_or_else(|| r.reason.text())
                })
                .unwrap_or("receiver push failed");
            row(
                &mut output,
                &Row {
                    flag: '!',
                    summary: "[rejected]".into(),
                },
                reference,
                Some(reason),
                style,
            );
        }
        for native in native {
            let reason = result
                .filter(|r| !r.receiver_ok)
                .and_then(|r| r.receiver_reason.as_deref());
            row(&mut output, native, reference, reason, style);
        }
    }
    if let Some(f) = result.and_then(|r| r.forwarded.as_ref()) {
        forwarded(&mut output, f, reference, quiet, style);
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::{
        cli::status,
        runtime::push_result::{Forwarded, Outcome, Reason, Report, Row},
    };
    const REF: &str = "refs/heads/contributors/topic";
    fn report(outcome: Outcome) -> Report {
        Report {
            version: 1,
            repository: Some("/srv/repo".into()),
            reference: Some(REF.into()),
            intended: Some("a".repeat(40)),
            receiver_ok: false,
            receiver_reason: Some("onward push failed".into()),
            reason: Reason::ReceiverRejected,
            forwarded: Some(Forwarded {
                url: Some("git@forge.example:org/repo.git".into()),
                rows: vec![],
                outcome,
            }),
        }
    }
    #[test]
    fn native_status_flags_and_friendly_refs_are_preserved() {
        for flag in [' ', '+', '*', '-', '=', '!'] {
            let mut record = report(Outcome::Complete);
            record.receiver_ok = true;
            record.receiver_reason = None;
            record.forwarded.as_mut().unwrap().rows = vec![Row {
                flag,
                summary: "[native status]".into(),
            }];
            let text = status::render(
                "receiver:repo",
                REF,
                &[Row {
                    flag: '*',
                    summary: "[new branch]".into(),
                }],
                Some(&record),
                false,
            );
            assert!(
                text.contains(&format!(
                    " {flag} [native status] contributors/topic -> contributors/topic"
                )),
                "{text}"
            );
            assert!(text.find("To receiver:").unwrap() < text.find("Forwarded to ").unwrap());
            assert!(
                !text.contains("Done")
                    && !text.contains('\t')
                    && !text.contains(&format!("{} ->", "a".repeat(40)))
            );
        }
    }
    #[test]
    fn every_outcome_has_honest_summary_and_order() {
        for (outcome, expected) in [
            (
                Outcome::Published,
                "= [published] contributors/topic -> contributors/topic (intended commit confirmed at origin)",
            ),
            (
                Outcome::NotPublished,
                "! [not published] contributors/topic -> contributors/topic (origin still at expected old tip)",
            ),
            (
                Outcome::Moved {
                    actual: Some("b".repeat(40)),
                },
                "! [moved] contributors/topic -> contributors/topic (origin now at bbbbbbb; inspect before retrying)",
            ),
            (
                Outcome::Unknown,
                "! [unknown] contributors/topic -> contributors/topic (origin recheck failed; may have published)",
            ),
            (
                Outcome::NotAttempted {
                    reason: Reason::DefaultBranchProtected,
                },
                "! [not attempted] contributors/topic -> contributors/topic (default branch protected)",
            ),
        ] {
            let record = report(outcome);
            let native = [Row {
                flag: '!',
                summary: "[remote rejected] (pre-receive hook declined)".into(),
            }];
            let text = status::render("receiver:repo", REF, &native, Some(&record), false);
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("(onward push failed)"));
            assert!(!text.contains("hook declined") && !text.contains("origin accepted"));
            assert!(text.find("To receiver:").unwrap() < text.find("Forwarded to ").unwrap());
        }
    }
    #[test]
    fn quiet_hides_success_but_keeps_failure_uncertainty_and_no_origin_has_no_forward_block() {
        let native = [Row {
            flag: ' ',
            summary: "1111111..2222222".into(),
        }];
        let mut record = report(Outcome::Complete);
        record.receiver_ok = true;
        record.receiver_reason = None;
        record.forwarded.as_mut().unwrap().rows = native.to_vec();
        assert!(status::render("receiver", REF, &native, Some(&record), true).is_empty());
        record.receiver_ok = false;
        record.receiver_reason = Some("onward result uncertain".into());
        record.forwarded.as_mut().unwrap().outcome = Outcome::Unknown;
        let text = status::render("receiver", REF, &native, Some(&record), true);
        assert!(text.contains("Forwarded to") && text.contains("[unknown]"));
        record.forwarded = None;
        assert!(
            !status::render("receiver", REF, &native, Some(&record), false)
                .contains("Forwarded to")
        );
    }
}
