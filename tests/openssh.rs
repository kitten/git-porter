mod support;
#[test]
#[ignore = "isolated loopback sshd acceptance; run cargo test --test openssh -- --ignored"]
fn real_openssh_publication_and_receive() {
    support::acceptance(false);
}
