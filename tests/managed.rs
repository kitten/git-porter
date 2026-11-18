mod support;
#[test]
#[ignore = "requires Nix and isolated loopback sshd; executes only the generated fixture fragment"]
fn generated_home_manager_remote_provisioning() {
    support::acceptance(true);
}
