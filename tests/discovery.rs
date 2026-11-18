use git_porter::{
    server::config::ServerConfig,
    server::discovery::{self, Identity},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn git(path: &Path, args: &[&str]) {
    let output = Command::new(git_porter::server::config::executable("git").unwrap())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn repository(home: &Path, path: &str, identity: &str) -> PathBuf {
    let path = home.join(path);
    fs::create_dir_all(&path).unwrap();
    git(&path, &["init", "-q"]);
    git(&path, &["remote", "add", "origin", identity]);
    path.canonicalize().unwrap()
}
fn policy(home: &Path, root: &Path, extra: &str) -> ServerConfig {
    let path = home.join(".gitconfig");
    fs::write(
        &path,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\n{extra}",
            root.display()
        ),
    )
    .unwrap();
    ServerConfig::read_environment(
        &path.canonicalize().unwrap(),
        home,
        home,
        &home.join(".cache/git-porter"),
    )
    .unwrap()
}
fn identity(name: &str) -> Identity {
    Identity::parse(&format!("git@example.com:{name}.git")).unwrap()
}
fn cache_file(config: &ServerConfig) -> PathBuf {
    fs::read_dir(&config.discovery.cache)
        .unwrap()
        .map(|v| v.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap()
}

#[test]
fn warm_hits_new_namespaces_moves_and_duplicates_never_bypass_identity() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let one = repository(
        &home,
        "projects/kitten/linn",
        "git@example.com:kitten/linn.git",
    );
    repository(
        &home,
        "projects/another-org/widget",
        "https://example.com/another-org/widget",
    );
    // A large dependency tree is pruned before visiting it or invoking Git.
    fs::create_dir_all(home.join("projects/node_modules")).unwrap();
    for i in 0..200 {
        fs::create_dir(home.join(format!("projects/node_modules/dep{i}"))).unwrap();
    }
    let config = policy(&home, &home.join("projects"), "");
    let id = identity("kitten/linn");
    let cold = discovery::scan(&config, &id).unwrap();
    assert!(cold.complete);
    assert_eq!(cold.candidates, std::slice::from_ref(&one));
    assert_eq!(cold.identity_reads, 2);
    assert!(cold.visited < 40);
    // Creating the cache namespace can change home once; the next scan establishes
    // coverage after that creation. Steady-state hits never walk the home tree.
    discovery::scan(&config, &id).unwrap();
    let warm = discovery::scan(&config, &id).unwrap();
    assert!(warm.cached);
    assert_eq!(warm.visited, 0);
    assert_eq!(warm.identity_reads, 1);
    assert!(warm.coverage_checks > 0);
    assert_eq!(warm.configuration_checks, 2);
    eprintln!(
        "cold: {} entries / {} Git / {:?}; warm: {} listings / {} coverage checks / {} config hashes / {} Git / {:?}",
        cold.visited,
        cold.identity_reads,
        cold.elapsed,
        warm.visited,
        warm.coverage_checks,
        warm.configuration_checks,
        warm.identity_reads,
        warm.elapsed
    );
    // Repository activity is not a change to the directory census or remote.
    fs::write(one.join("untracked"), "fixture").unwrap();
    git(&one, &["symbolic-ref", "HEAD", "refs/heads/other"]);
    let other = home.join("projects/another-org/widget");
    git(&other, &["symbolic-ref", "HEAD", "refs/heads/other"]);
    let active = discovery::scan(&config, &id).unwrap();
    assert!(active.cached);
    assert_eq!(active.visited, 0);
    assert_eq!(active.identity_reads, 1);
    // Expiry refreshes coverage, not every unchanged remote identity.
    let file = cache_file(&config);
    let mut stored: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    stored["created"] = 0.into();
    fs::write(&file, serde_json::to_vec(&stored).unwrap()).unwrap();
    let expired = discovery::scan(&config, &id).unwrap();
    assert!(!expired.cached);
    assert!(expired.visited > 0);
    assert_eq!(expired.identity_reads, 1);
    assert_eq!(expired.candidates, std::slice::from_ref(&one));
    let new = repository(
        &home,
        "projects/third-org/tool",
        "git@example.com:third-org/tool.git",
    );
    let found = discovery::scan(&config, &identity("third-org/tool")).unwrap();
    assert!(!found.cached);
    assert_eq!(
        found.identity_reads, 1,
        "only the new remote needs inspection"
    );
    assert_eq!(found.candidates, [new]);
    // A bounded/incomplete pass retains work already completed for other entries.
    let file = cache_file(&config);
    let mut partial: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    partial["complete"] = false.into();
    let unknown = partial["repositories"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["path"].as_str() == other.to_str())
        .unwrap();
    unknown["identity"] = serde_json::Value::Null;
    unknown["digest"] = "".into();
    fs::write(&file, serde_json::to_vec(&partial).unwrap()).unwrap();
    let progress = discovery::scan(&config, &id).unwrap();
    assert!(progress.complete && !progress.cached);
    assert_eq!(
        progress.identity_reads, 2,
        "one match plus the unfinished entry; other completed entries survive"
    );

    let moved = home.join("projects/moved/linn");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&one, &moved).unwrap();
    assert_eq!(
        discovery::scan(&config, &id).unwrap().candidates,
        std::slice::from_ref(&moved)
    );
    let duplicate = repository(
        &home,
        "projects/duplicate/linn",
        "https://example.com/kitten/linn",
    );
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates.len(), 2);
    git(
        &duplicate,
        &[
            "remote",
            "set-url",
            "origin",
            "git@example.com:fork/linn.git",
        ],
    );
    assert_eq!(
        discovery::scan(&config, &id).unwrap().candidates,
        std::slice::from_ref(&moved)
    );
    let settled = discovery::scan(&config, &id).unwrap();
    assert_eq!(
        settled.identity_reads, 1,
        "changed nonmatch should be retained"
    );
    fs::remove_dir_all(&moved).unwrap();
    let missing = discovery::scan(&config, &id).unwrap();
    assert!(missing.complete && missing.candidates.is_empty());
    assert_eq!(
        missing.identity_reads, 0,
        "missing entry must not discard unrelated identities"
    );
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(cache_file(&config)).unwrap()).unwrap();
    assert!(
        !stored["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"].as_str() == moved.to_str())
    );
    // Losing a repo marker exposes children hidden by the former repo boundary.
    fs::remove_dir_all(duplicate.join(".git")).unwrap();
    let nested = repository(
        &home,
        "projects/duplicate/linn/nested",
        "git@example.com:kitten/linn.git",
    );
    let exposed = discovery::scan(&config, &id).unwrap();
    assert!(exposed.complete);
    assert_eq!(exposed.candidates, std::slice::from_ref(&nested));
    fs::remove_dir_all(&nested).unwrap();
    fs::write(&nested, "not a directory").unwrap();
    let not_directory = discovery::scan(&config, &id).unwrap();
    assert!(not_directory.complete && not_directory.candidates.is_empty());
    assert_eq!(not_directory.identity_reads, 0);
}

#[test]
fn content_hashes_and_external_includes_invalidate_cached_nonmatches() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let one = repository(&home, "one", "git@example.com:org/one.git");
    let two = repository(&home, "two", "git@example.com:org/two.git");
    let config = policy(&home, &home, "");
    let id = identity("org/one");
    discovery::scan(&config, &id).unwrap();
    discovery::scan(&config, &id).unwrap();
    // Restore the exact timestamp after a same-length edit. Only content-based
    // invalidation notices that a formerly unrelated repo became a duplicate.
    let path = two.join(".git/config");
    let time = fs::metadata(&path).unwrap().modified().unwrap();
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("org/two", "org/one");
    fs::write(&path, text).unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(time))
        .unwrap();
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates.len(), 2);
    git(&two, &["remote", "remove", "origin"]);
    let include = home.join("external.gitconfig");
    fs::write(
        &include,
        "[remote \"origin\"]\nurl = git@example.com:org/two.git\n",
    )
    .unwrap();
    git(&two, &["config", "include.path", include.to_str().unwrap()]);
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates, [one]);
    fs::write(
        &include,
        "[remote \"origin\"]\nurl = git@example.com:org/one.git\n",
    )
    .unwrap();
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates.len(), 2);
    fs::remove_file(&include).unwrap();
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates.len(), 1);
    fs::write(
        &include,
        "[remote \"origin\"]\nurl = git@example.com:org/one.git\n",
    )
    .unwrap();
    assert_eq!(discovery::scan(&config, &id).unwrap().candidates.len(), 2);
    let conditional = repository(&home, "conditional", "git@example.com:org/unused.git");
    git(&conditional, &["remote", "remove", "origin"]);
    git(
        &conditional,
        &["symbolic-ref", "HEAD", "refs/heads/inactive"],
    );
    git(
        &conditional,
        &[
            "config",
            "includeIf.onbranch:activate.path",
            include.to_str().unwrap(),
        ],
    );
    discovery::scan(&config, &id).unwrap();
    let before = discovery::scan(&config, &id).unwrap();
    assert_eq!(before.candidates.len(), 2);
    git(
        &conditional,
        &["symbolic-ref", "HEAD", "refs/heads/activate"],
    );
    let after = discovery::scan(&config, &id).unwrap();
    assert!(after.cached);
    assert_eq!(
        after.candidates.len(),
        2,
        "conditional includes remain nonmatches on every branch"
    );
}

#[test]
fn cache_corruption_expiry_concurrency_permissions_and_search_scope() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let allowed = repository(&home, "allowed/repo", "git@example.com:org/repo.git");
    repository(&home, "private/repo", "git@example.com:org/repo.git");
    let config = policy(&home, &home.join("allowed"), "");
    let id = identity("org/repo");
    assert_eq!(
        discovery::scan(&config, &id).unwrap().candidates,
        std::slice::from_ref(&allowed)
    );
    discovery::scan(&config, &id).unwrap();
    let mut equivalent = config.clone();
    equivalent.discovery.roots = vec![
        home.join("allowed"),
        home.join("allowed"),
        home.join("allowed/nested"),
    ];
    assert!(
        discovery::scan(&equivalent, &id).unwrap().cached,
        "equivalent normalized roots should share coverage"
    );
    let file = cache_file(&config);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&config.discovery.cache)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    fs::write(&file, b"{bad json").unwrap();
    let rebuilt = discovery::scan(&config, &id).unwrap();
    assert!(!rebuilt.cached);
    assert_eq!(rebuilt.candidates, std::slice::from_ref(&allowed));
    let mut data: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    data["created"] = 0.into();
    for entry in data["repositories"].as_array_mut().unwrap() {
        entry["identity"] = serde_json::Value::Null;
    }
    fs::write(&file, serde_json::to_vec(&data).unwrap()).unwrap();
    let retry = discovery::scan(&config, &id).unwrap();
    assert!(!retry.cached);
    assert_eq!(
        retry.identity_reads, 1,
        "expired negatives must not persist transient failures inside strict roots"
    );
    assert_eq!(retry.candidates, std::slice::from_ref(&allowed));
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                assert_eq!(
                    discovery::scan(&config, &id).unwrap().candidates,
                    std::slice::from_ref(&allowed)
                );
            });
        }
    });
    let mut changed = policy(&home, &home.join("allowed"), "");
    changed.discovery.depth = 1;
    assert!(!discovery::scan(&changed, &id).unwrap().cached);
    changed.discovery.roots = vec![home.join("allowed")];
    let scoped = discovery::scan(&changed, &id).unwrap();
    assert!(scoped.complete);
    assert_eq!(scoped.candidates, [allowed]);
    fs::set_permissions(&changed.discovery.cache, fs::Permissions::from_mode(0o755)).unwrap();
    let uncached = discovery::scan(&changed, &id).unwrap();
    assert!(!uncached.cached);
    assert_eq!(uncached.candidates.len(), 1);
}

#[test]
fn linked_worktrees_bare_repos_depth_exclusions_and_negative_additions() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let main = repository(&home, "main", "git@example.com:org/main.git");
    git(
        &main,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "initial",
        ],
    );
    git(&main, &["worktree", "add", "-qb", "other", "../linked"]);
    let bare = home.join("bare.git");
    fs::create_dir(&bare).unwrap();
    git(&bare, &["init", "--bare", "-q"]);
    git(
        &bare,
        &["remote", "add", "origin", "git@example.com:org/bare.git"],
    );
    let config = policy(&home, &home, "");
    assert_eq!(
        discovery::scan(&config, &identity("org/main"))
            .unwrap()
            .candidates
            .len(),
        2
    );
    assert_eq!(
        discovery::scan(&config, &identity("org/bare"))
            .unwrap()
            .candidates,
        [bare]
    );
    let missing = identity("new/repo");
    assert!(
        discovery::scan(&config, &missing)
            .unwrap()
            .candidates
            .is_empty()
    );
    let created = repository(&home, "new/repo", "git@example.com:new/repo.git");
    assert_eq!(
        discovery::scan(&config, &missing).unwrap().candidates,
        [created]
    );
    repository(
        &home,
        "node_modules/hidden",
        "git@example.com:org/hidden.git",
    );
    assert!(
        discovery::scan(&config, &identity("org/hidden"))
            .unwrap()
            .candidates
            .is_empty()
    );
    repository(
        &home,
        "deep/a/b/c/d/e/f/repo",
        "git@example.com:org/deep.git",
    );
    let incomplete = discovery::scan(&config, &identity("org/deep")).unwrap();
    assert!(!incomplete.complete);
    assert!(
        !discovery::scan(&config, &identity("org/deep"))
            .unwrap()
            .cached
    );
}

#[test]
fn origin_preference_never_merges_forks_through_a_shared_upstream() {
    let home = tempfile::tempdir().unwrap();
    let home = home.path().canonicalize().unwrap();
    let fork = repository(&home, "fork", "git@example.com:fork/repo.git");
    git(
        &fork,
        &[
            "remote",
            "add",
            "upstream",
            "git@example.com:canonical/repo.git",
        ],
    );
    let config = policy(&home, &home, "");
    let canonical = identity("canonical/repo");
    assert!(
        discovery::scan(&config, &canonical)
            .unwrap()
            .candidates
            .is_empty()
    );
    assert_eq!(
        discovery::scan(&config, &identity("fork/repo"))
            .unwrap()
            .candidates,
        std::slice::from_ref(&fork)
    );
    git(&fork, &["remote", "remove", "origin"]);
    let secondary = discovery::scan(&config, &canonical).unwrap();
    assert_eq!(secondary.candidates, std::slice::from_ref(&fork));
    assert_eq!(secondary.identity_reads, 1);
    git(
        &fork,
        &["remote", "add", "other", "git@example.com:other/repo.git"],
    );
    assert!(
        discovery::scan(&config, &canonical)
            .unwrap()
            .candidates
            .is_empty()
    );
    git(
        &fork,
        &["remote", "add", "origin", "/unsupported/local/path"],
    );
    assert!(
        discovery::scan(&config, &canonical)
            .unwrap()
            .candidates
            .is_empty()
    );
    git(
        &fork,
        &[
            "remote",
            "set-url",
            "origin",
            "git@example.com:canonical/repo.git",
        ],
    );
    git(
        &fork,
        &[
            "remote",
            "set-url",
            "--add",
            "origin",
            "git@example.com:fork/repo.git",
        ],
    );
    assert!(
        discovery::scan(&config, &canonical)
            .unwrap()
            .candidates
            .is_empty()
    );
}

#[test]
fn gitdir_files_and_local_url_rewrites_are_read_without_git_processes() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let repo = repository(&home, "checkout", "short:org/repo");
    let metadata = home.join(".metadata");
    fs::rename(repo.join(".git"), &metadata).unwrap();
    fs::write(repo.join(".git"), "gitdir: ../.metadata\n").unwrap();
    git(
        &repo,
        &["config", "url.git@example.com:.insteadOf", "short:"],
    );
    assert_eq!(discovery::origin(&repo).unwrap(), identity("org/repo"));
    let config = policy(&home, &home, "");
    assert_eq!(
        discovery::scan(&config, &identity("org/repo"))
            .unwrap()
            .candidates,
        vec![repo]
    );
}

#[test]
fn repository_config_ignores_broken_ambient_files_and_global_rewrites() {
    if let Some(repository) = std::env::var_os("PORTER_TEST_OWN_CONFIG") {
        let expected = std::env::var("PORTER_TEST_EXPECTED_HOST").unwrap();
        assert_eq!(
            discovery::origin(Path::new(&repository)).unwrap().host,
            expected
        );
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let policy_path = home.join("receiver-policy");
        fs::write(&policy_path, "[porter]\n").unwrap();
        let policy = ServerConfig::read_environment(
            &policy_path,
            &home,
            &home,
            &home.join(".cache/git-porter"),
        )
        .unwrap();
        assert!(
            discovery::scan(
                &policy,
                &Identity::parse("git@global.example:org/repo").unwrap()
            )
            .unwrap()
            .candidates
            .is_empty()
        );
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let repo = repository(&home, "repo", "git@example.com:org/repo");
    let config_home = home.join("custom-config");
    fs::create_dir_all(config_home.join("git")).unwrap();
    let system = home.join("system-config");
    for path in [
        home.join(".gitconfig"),
        config_home.join("git/config"),
        system.clone(),
    ] {
        fs::write(path, "[broken\n").unwrap();
    }
    let run = |host: &str| {
        let output = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_RUNTIME_DIR", home.join("run"))
            .env("TMPDIR", std::env::temp_dir())
            .env("GIT_CONFIG_SYSTEM", &system)
            .env("PORTER_TEST_OWN_CONFIG", &repo)
            .env("PORTER_TEST_EXPECTED_HOST", host)
            .args([
                "--exact",
                "repository_config_ignores_broken_ambient_files_and_global_rewrites",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            format!(
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        );
    };
    run("example.com");
    fs::write(
        home.join(".gitconfig"),
        "[url \"git@global.example:\"]\ninsteadOf = alias:\n",
    )
    .unwrap();
    fs::write(config_home.join("git/config"), "").unwrap();
    fs::write(&system, "").unwrap();
    git(&repo, &["config", "remote.origin.url", "alias:org/repo"]);
    run("alias"); // No match for global.example: its global rewrite is ignored.
}

#[test]
fn strict_repo_config_rejects_ambiguity_and_conditionals_and_resets_urls() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let repo = repository(&home, "repo", "git@example.com:org/repo");
    let path = repo.join(".git/config");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        format!("{original}\n[remote \"origin\"]\nurl =\nurl = git@example.com:org/reset\n"),
    )
    .unwrap();
    assert_eq!(discovery::origin(&repo).unwrap(), identity("org/reset"));
    for extra in [
        "[remote \"origin\"]\nurl = git@example.com:org/other\n",
        "[includeIf \"hasconfig:remote.*.url:**\"]\npath = missing\n",
        "[includeIf \"onbranch:main\"]\npath = missing\n",
        "[url \"git@other.example:\"]\ninsteadOf = git@example.com:\n[url \"git@third.example:\"]\ninsteadOf = git@example.com:\n",
    ] {
        fs::write(&path, format!("{original}\n{extra}")).unwrap();
        assert!(discovery::origin(&repo).is_err(), "{extra}");
        let config = policy(&home, &home, "");
        assert!(
            discovery::scan(&config, &identity("org/repo"))
                .unwrap()
                .candidates
                .is_empty()
        );
    }
}

#[test]
fn space_ending_metadata_paths_share_identity_and_cache_invalidation() {
    for common_pointer in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let repo = repository(&home, "checkout", "git@example.com:org/old");
        let common = home.join(".metadata ");
        fs::rename(repo.join(".git"), &common).unwrap();
        if common_pointer {
            let admin = home.join(".worktree");
            fs::create_dir(&admin).unwrap();
            fs::copy(common.join("HEAD"), admin.join("HEAD")).unwrap();
            fs::write(admin.join("commondir"), "../.metadata \n").unwrap();
            fs::write(repo.join(".git"), "gitdir: ../.worktree\n").unwrap();
        } else {
            fs::write(repo.join(".git"), "gitdir: ../.metadata \n").unwrap();
        }
        let config = policy(&home, &home, "");
        let wanted = identity("org/new");
        assert_eq!(discovery::origin(&repo).unwrap(), identity("org/old"));
        assert!(
            discovery::scan(&config, &wanted)
                .unwrap()
                .candidates
                .is_empty()
        );
        assert!(
            discovery::scan(&config, &wanted)
                .unwrap()
                .candidates
                .is_empty()
        );
        let path = common.join("config");
        fs::write(
            &path,
            fs::read_to_string(&path)
                .unwrap()
                .replace("org/old", "org/new"),
        )
        .unwrap();
        assert_eq!(discovery::origin(&repo).unwrap(), wanted);
        assert_eq!(
            discovery::scan(&config, &wanted).unwrap().candidates,
            vec![repo]
        );
    }
}

#[test]
fn fifo_metadata_pointers_are_rejected_without_blocking_lookup_or_cache() {
    if let Some(repo) = std::env::var_os("PORTER_TEST_FIFO_POINTER") {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let config = policy(&home, &home, "");
        assert!(discovery::origin(Path::new(&repo)).is_err());
        assert!(
            discovery::scan(&config, &identity("org/repo"))
                .unwrap()
                .candidates
                .is_empty()
        );
        return;
    }
    for common_pointer in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let repo = repository(&home, "repo", "git@example.com:org/repo");
        let fifo = if common_pointer {
            repo.join(".git/commondir")
        } else {
            fs::remove_dir_all(repo.join(".git")).unwrap();
            repo.join(".git")
        };
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_RUNTIME_DIR", home.join("run"))
            .env("TMPDIR", std::env::temp_dir())
            .env("PORTER_TEST_FIFO_POINTER", &repo)
            .args([
                "--exact",
                "fifo_metadata_pointers_are_rejected_without_blocking_lookup_or_cache",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO blocked pointer resolution");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
