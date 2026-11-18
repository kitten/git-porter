use super::*;
#[test]
fn destination_and_final_argument_checks_share_component_policy() {
    let policy = Policy {
        destinations: vec!["forge.example".into()],
        allow_default_branch: false,
        skip_wrapped_key: false,
        wrapped: PathBuf::new(),
        source: PathBuf::new(),
        public: PathBuf::new(),
        known_hosts: PathBuf::new(),
    };
    assert!(
        policy
            .allows("ssh://git@forge.example:2222/group/sub/repo.git")
            .is_ok()
    );
    for url in [
        "ssh://git@evil.example:2222/group/sub/repo",
        "https://forge.example/group/sub/repo",
    ] {
        assert!(policy.allows(url).is_err(), "{url}");
    }
    let good: Vec<_> = [
        "-p",
        "2222",
        "git@forge.example",
        "git-receive-pack 'group/sub/repo.git'",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    assert!(policy.validate_transport(&good).is_ok());
    let bad: Vec<_> = [
        "-o",
        "ProxyCommand=evil",
        "git@forge.example",
        "git-receive-pack 'group/sub/repo'",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    assert!(policy.validate_transport(&bad).is_err());
}

#[test]
fn optional_host_allowlist_and_default_branch_policy() {
    use crate::server::publication::protect_default_branch;
    use std::collections::BTreeMap;
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    let unrestricted = Policy::read(&root, &root.join("known_hosts"), &BTreeMap::new()).unwrap();
    assert!(unrestricted.allows("git@github.com:org/repo.git").is_ok());
    assert!(!unrestricted.allow_default_branch);
    let mut values = BTreeMap::from([
        (
            "porter.publishto".into(),
            vec!["github.com".into(), "gitlab.com".into()],
        ),
        ("porter.allowdefaultbranch".into(), vec!["true".into()]),
    ]);
    for skip_wrapped_key in ["false", "true"] {
        values.insert(
            "porter.skipwrappedkey".into(),
            vec![skip_wrapped_key.into()],
        );
        let restricted = Policy::read(&root, &root.join("known_hosts"), &values).unwrap();
        assert!(restricted.allow_default_branch);
        assert!(restricted.allows("git@gitlab.com:fork/any.git").is_ok());
        assert!(restricted.allows("git@other.example:org/repo").is_err());
    }
    let head = b"ref: refs/heads/main\tHEAD\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tHEAD\n";
    assert_eq!(
        protect_default_branch(true, head, "refs/heads/main"),
        Err(Reason::DefaultBranchProtected)
    );
    assert!(protect_default_branch(true, head, "refs/heads/feature").is_ok());
    assert!(protect_default_branch(true, b"", "refs/heads/feature").is_err());
    let unicode = format!("ref: refs/heads/主分支\tHEAD\n{}\tHEAD\n", "a".repeat(40));
    assert!(protect_default_branch(true, unicode.as_bytes(), "refs/heads/feature").is_ok());
    assert!(protect_default_branch(true, unicode.as_bytes(), "refs/heads/主分支").is_err());
    for (success, advertisement) in [
        (false, head.as_slice()),
        (
            true,
            b"ref: refs/heads/main\tHEAD\nref: refs/heads/other\tHEAD\n".as_slice(),
        ),
        (true, b"ref: refs/tags/main\tHEAD\n".as_slice()),
        (true, b"\xff".as_slice()),
    ] {
        assert_eq!(
            protect_default_branch(success, advertisement, "refs/heads/main"),
            Err(Reason::DefaultBranchUnknown)
        );
    }
}

#[test]
fn origin_outcomes_use_only_valid_pinned_observations() {
    let reference = "refs/heads/topic";
    let intended = "a".repeat(40);
    let expected = "b".repeat(40);
    let moved = "c".repeat(40);
    for (actual, outcome) in [
        (Some(intended.clone()), Outcome::Published),
        (Some(expected.clone()), Outcome::NotPublished),
        (
            Some(moved.clone()),
            Outcome::Moved {
                actual: Some(moved),
            },
        ),
        (None, Outcome::Moved { actual: None }),
    ] {
        let bytes = actual
            .map(|sha| format!("{sha}\t{reference}\n"))
            .unwrap_or_default();
        assert_eq!(
            origin_outcome(bytes.as_bytes(), reference, &intended, &expected).unwrap(),
            outcome
        );
    }
    assert_eq!(
        origin_outcome(b"", reference, &intended, "").unwrap(),
        Outcome::NotPublished
    );
    for invalid in [
        format!("{expected}\trefs/heads/other\n"),
        format!("{expected}\t{reference}\n{expected}\t{reference}\n"),
        format!("not-an-oid\t{reference}\n"),
        format!("{}\t{reference}\n", "A".repeat(40)),
    ] {
        assert!(push_result::ref_tip(invalid.as_bytes(), reference).is_err());
        assert!(origin_outcome(invalid.as_bytes(), reference, &intended, &expected).is_err());
    }
}

#[test]
fn publication_decisions_cover_each_outcome_without_spawning_git_or_ssh() {
    use crate::runtime::push_result::Row;
    let hook = |attempted, accepted| HookReport {
        version: 1,
        reference: "refs/heads/topic".into(),
        intended: "a".repeat(40),
        attempted,
        accepted,
        rows: if attempted {
            vec![Row {
                flag: if accepted { ' ' } else { '!' },
                summary: if accepted { "old..new" } else { "[rejected]" }.into(),
            }]
        } else {
            vec![]
        },
        reason: Reason::DefaultBranchProtected,
    };
    let never = || panic!("origin must not be queried");
    assert!(matches!(
        publication_result(None, false, never).1,
        Outcome::NotAttempted {
            reason: Reason::ReceiverRejected
        }
    ));
    assert_eq!(publication_result(None, true, never).1, Outcome::Unknown);
    assert!(matches!(
        publication_result(Some(hook(false, false)), false, never).1,
        Outcome::NotAttempted {
            reason: Reason::DefaultBranchProtected
        }
    ));
    assert_eq!(
        publication_result(Some(hook(true, true)), true, never).1,
        Outcome::Complete
    );
    for receiver_ok in [false, true] {
        for outcome in [
            Outcome::Published,
            Outcome::NotPublished,
            Outcome::Moved {
                actual: Some("c".repeat(40)),
            },
            Outcome::Unknown,
        ] {
            let calls = std::cell::Cell::new(0);
            let (rows, actual, reason) =
                publication_result(Some(hook(true, false)), receiver_ok, || {
                    calls.set(calls.get() + 1);
                    Ok(outcome.clone())
                });
            assert_eq!(actual, outcome);
            assert_eq!(calls.get(), 1);
            assert_eq!(rows[0].summary, "[rejected]");
            assert_eq!(
                reason.as_deref(),
                Some(
                    if matches!(outcome, Outcome::Moved { .. } | Outcome::Unknown) {
                        "onward result uncertain"
                    } else {
                        "onward push failed"
                    }
                )
            );
        }
    }
    let (_, outcome, reason) = publication_result(Some(hook(true, false)), false, || {
        Err("origin connection lost".into())
    });
    assert_eq!(outcome, Outcome::Unknown);
    assert_eq!(reason.as_deref(), Some("onward result uncertain"));
    let (_, outcome, reason) =
        publication_result(Some(hook(true, true)), false, || Ok(Outcome::Published));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(reason.as_deref(), Some("receiver update failed"));
}

#[test]
fn malformed_head_advertisements_fail_closed() {
    for name in [
        "refs/heads/",
        "refs/heads/../main",
        "refs/heads/a..b",
        "refs/heads/a.lock",
        "refs/heads/a b",
        "refs/heads/@{x}",
    ] {
        let text = format!("ref: {name}\tHEAD\n{}\tHEAD\n", "a".repeat(40));
        assert_eq!(
            protect_default_branch(true, text.as_bytes(), "refs/heads/feature"),
            Err(Reason::DefaultBranchUnknown)
        );
    }
    for rows in [
        "ref: refs/heads/main\tHEAD\n".to_owned(),
        format!("ref: refs/heads/main\tHEAD\n{}\tHEAD\n", "A".repeat(40)),
        format!("ref: refs/heads/main\tHEAD\n{}\tHEAD\n", "0".repeat(40)),
        format!(
            "ref: refs/heads/main\tHEAD\n{}\tHEAD\nextra\n",
            "a".repeat(40)
        ),
        format!(
            "ref: refs/heads/main\tHEAD\n{}\tHEAD\n{}\tHEAD\n",
            "a".repeat(40),
            "a".repeat(40)
        ),
        "ref: refs/heads/main\tHEAD\nnot-an-oid\tHEAD\n".to_owned(),
    ] {
        assert_eq!(
            protect_default_branch(true, rows.as_bytes(), "refs/heads/feature"),
            Err(Reason::DefaultBranchUnknown)
        );
    }
}

#[test]
fn a_second_hook_cannot_replace_a_claimed_transactions_result() {
    use crate::server::config::ServerConfig;
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let path = home.join(".gitconfig");
    fs::write(&path, "[porter]\n").unwrap();
    let config = ServerConfig::read_environment(&path, &home, &home, &home.join("cache")).unwrap();
    let context = HookContext {
        gitdir: home.clone(),
        objects: home.join("objects"),
        socket: home.join("agent"),
        public: None,
        url: "git@github.com:org/repo".into(),
        mode: "ff".into(),
        observed: String::new(),
        reference: "refs/heads/contributors/test".into(),
        sha: "a".repeat(40),
    };
    let path = home.join("publication.json");
    fs::write(&path, serde_json::to_vec(&context).unwrap()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    // Even a first hook that refuses its updates owns the one-shot transaction.
    assert!(
        pre_receive(&config, &[], Some(&path))
            .unwrap_err()
            .to_string()
            .contains("exactly one")
    );
    let record_path = home.join("hook-result.json");
    let mut record: HookReport = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
    record.attempted = true;
    record.accepted = true;
    crate::server::authorized::atomic(&record_path, &serde_json::to_vec(&record).unwrap()).unwrap();
    let before = fs::read(&record_path).unwrap();
    let update = [(
        "0".repeat(40),
        context.sha.clone(),
        context.reference.clone(),
    )];
    assert!(
        pre_receive(&config, &update, Some(&path))
            .unwrap_err()
            .to_string()
            .contains("already claimed")
    );
    assert_eq!(fs::read(&record_path).unwrap(), before);
}
