use std::{fs, path::Path, process::Command};
#[test]
fn installed_surface_and_setup_use_only_the_copied_package() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let bin = root.join("bin");
    let home = root.join("home");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&home).unwrap();
    for (name, built) in [
        ("git-porter", env!("CARGO_BIN_EXE_git-porter")),
        ("git-send", env!("CARGO_BIN_EXE_git-send")),
        ("git-receive", env!("CARGO_BIN_EXE_git-receive")),
    ] {
        let source = std::env::var_os("GIT_PORTER_TEST_BIN")
            .map(|p| Path::new(&p).join(name))
            .unwrap_or_else(|| Path::new(built).to_path_buf());
        fs::copy(source, bin.join(name)).unwrap();
        let help = Command::new(bin.join(name))
            .arg("--help")
            .env("HOME", &home)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .output()
            .unwrap();
        assert!(help.status.success());
        if name == "git-porter" {
            let text = String::from_utf8(help.stdout).unwrap();
            assert!(text.contains("setup|key:create|key:public"));
            assert!(!text.contains("internal:"));
        }
    }
    assert!(fs::read_dir(&home).unwrap().next().is_none());
}
