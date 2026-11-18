# git-porter contributor rules

The LLP corpus is the specification. Read the governing LLP before implementing
or changing a subsystem; update durable intent in the same change. The map is
src/README.md. Use sparse @ref citations; anchors are stable interfaces.
LLPs cite only repository artifacts and other LLPs. External research and
source provenance belong in ordinary docs. Do not turn implementation progress
into a permanent task journal.

Use the git-porter-specific Ed25519 wrapping domain. Old bundles require a
one-time rewrap; never sign in the foreign age-plugin domain. Preserve the bounded
exact-key protocol and single-push lifecycle.
Default clients never forward agents or silently downgrade. Access and discovery
are distinct: hints and caches cannot authorize a repository.

Use the flake devShell: `nix develop -c cargo test --locked`,
`nix develop -c cargo fmt --check`,
`nix develop -c cargo clippy --all-targets -- -D warnings`, and
`nix develop -c python3 scripts/check_llp_refs.py`.
Never stage or commit the locally excluded extraction brief. Publication,
activation and source deletion require separate operator authorization.

Tests must isolate HOME and every XDG directory. Never write test data into the
account’s real git-porter data folder.
