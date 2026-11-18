# LLP 0003: Using LLP in git-porter

**Type:** Guide\
**Status:** Active\
**Systems:** LLP, ContributorWorkflow\
**Related:** LLP 0000, LLP 0001, LLP 0002, LLP 0004

## Workflow

Read governing LLPs before implementation; update durable intent in the same
change. The map is [src/README.md](../src/README.md). Keep numbered explainers
and guides with Type, Status, Systems and Related metadata. Use sparse @ref
citations; anchors are stable interfaces. Cite repository artifacts/LLPs only;
ordinary operator documentation owns external research/provenance. No task
journals here.

[The Python checker](../scripts/check_llp_refs.py) and its
[fixtures](../tests/tools/test_check_llp_refs.py) follow linn's LLP conventions.
Keep that tooling in Python. Rust owns acceptance tooling.

## Source and test architecture

Group CLI, server policy, credentials and runtime code by responsibility. Keep
publication signers separate from policy/orchestration and avoid flat re-export
layers for this internal library. Run cargo fmt, locked workspace tests and
clippy through the flake devShell. The toolchain is pinned there, not by
rust-version.

Put pure porter rules next to their modules under cfg(test): framing and
mutation bounds, exact-key derivation, wrapping/storage, branch and publication
policy, origin-outcome classification and status rendering. Use in-memory
requests and responses; do not launch Git, SSH, ssh-agent or ssh-keygen to test
those decisions.

Keep integration coverage for porter-owned boundaries: installed command
dispatch, framed handoff, configuration/discovery, credential files and
subprocess teardown. Command spies verify the arguments/environment porter
chooses, not Git/SSH behavior. Git and OpenSSH are trusted dependencies; do not
duplicate their own behavior tests.

[OpenSSH acceptance](../tests/openssh.rs) verifies one complete porter workflow,
including its restricted agent/session binding, pre-receive/quarantine handoff
and credential modes. [Home Manager acceptance](../tests/managed.rs) verifies
generated policy/activation, remote key creation and one receiver/forwarder
push, without repeating the full workflow. Both share synthetic isolated
fixtures, run explicitly with --ignored, and never touch real account
configuration. Outcome/recheck decisions are tested directly with controlled
observations; no custom forge scripts or per-outcome SSH scenarios are needed.
The Nix fixture lives at tests/e2e/managed.nix; test only its own activation
fragment, never an enclosing profile switch. The flake module-policy check
evaluates sender-only settings and expected receiver-policy assertion failures
using tests/e2e/module-policy.nix. [Install checks](../tests/install.rs) test
copied or extracted binaries via GIT_PORTER_TEST_BIN. GIT_PORTER_TEST_FLAKE
selects an optional immutable snapshot.

[Release packaging](../scripts/package_release.py) uses Python’s standard library
for deterministic archives and release manifests, following the same tooling
approach as the LLP checker. Keep focused tests in tests/tools. No separate Rust
tooling crate or Cargo alias is needed. Retain regression gates; one-off extraction
copies, VM images and private checkout workarounds are not product files.
