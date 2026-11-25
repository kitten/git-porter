# Architecture map

The LLP corpus is the self-contained specification:

- [0000: Access and trust](../llp/0000-access.explainer.md)
- [0001: Protocol and credentials](../llp/0001-protocol.explainer.md)
- [0002: Clients and discovery](../llp/0002-clients.explainer.md)
- [0003: Contributor workflow](../llp/0003-using-llp.guide.md)
- [0004: Installation and qualification](../llp/0004-distribution.guide.md)

## Module boundaries

| Directory | Responsibility |
| --- | --- |
| [cli](cli/mod.rs) | Installed command dispatch, setup, terminal presentation, diagnostics and send/receive clients |
| [server](server/mod.rs) | Trusted policy, restricted access, discovery and publication transactions |
| [credentials](credentials/mod.rs) | Versioned wrapping/derivation, private-key parsing, atomic storage and approved provisioning jobs |
| [runtime](runtime/mod.rs) | Framing, SSH fields, bounded IPC, byte relay and owned subprocess lifetimes |

The publication agent/signers live in [their own module](server/publication/agent.rs);
[publication policy](server/publication/policy.rs) validates destinations and runtime
credential paths; [transaction orchestration](server/publication/mod.rs) owns when
those credentials may be used. The git_porter library is internal: binaries and tests
use these subsystem paths directly, without a second layer of compatibility aliases.

[Client orchestration](cli/client/mod.rs) owns branch operations;
[hydration](cli/client/hydration.rs) prepares sender objects and history; the
[transport role](cli/client/transport.rs) owns SSH negotiation and byte handoff,
[key commands](cli/keys.rs) handle enrollment and prompts,
[provisioning](cli/client/provision.rs) owns approved remote key participation,
[signing](cli/client/signing.rs) owns the supervised sender-agent bootstrap,
and [repository context](cli/client/repository.rs) pins local Git selection.

Discovery keeps [remote identity and selection rules](server/discovery/identity.rs)
separate from [bounded filesystem traversal](server/discovery/mod.rs).
A shared [metadata layout resolver](server/discovery/layout.rs) binds identity
reads and cache hashing to the same bounded pointer interpretation. Sender lookup uses its pinned Git context; receiver inventory uses libgit2 local/worktree
config entries, with the same authoritative-origin and single-URL policy.

Sender and forwarder agents share [private directory lifecycle and stale cleanup](runtime/agent_directory.rs)
and [child supervision](runtime/supervision.rs); their signing policies remain separate.

[Receiver access](server/access.rs) owns repository confinement, ref checks and
repository locking. Its private [session module](server/access/session.rs) owns
native transfer and final outcome reporting, with private modules for
[typed intent parsing](server/access/session/intent.rs) and
[credential approval and unlocking](server/access/session/signing.rs). Signing exchange
framing stays in session orchestration; the credential helper receives one signing
callback. Native forced
commands and the pre-receive role continue to use the same access checks.
