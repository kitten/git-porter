# LLP 0001: Protocol and credentials

**Type:** Explainer\
**Status:** Active\
**Systems:** Protocol, Credentials, Lifecycle\
**Related:** LLP 0000, LLP 0002, LLP 0004

## Framing

Automatic send/receive routing starts with one fixed-length ASCII line:
`git-porter-route-v1:porter` or `git-porter-route-v1:native`, followed by LF.
The former enters the protocol below; the latter carries raw native Git only.
The SSH shell command uses the literal `printf 'git-porter-route-v1:native\n'; cd "$HOME" && exec `
prefix; the forced command recognizes it without evaluating the suffix. Marker
errors are terminal, not a signal to downgrade. Explicit private-session callers
and key provisioning retain their direct git-porter-session-v1 entry.
See [route selection](0002-clients.explainer.md#ssh-route-selection).

[Framing](../src/runtime/protocol.rs) uses four-byte big-endian body length,
one-byte version 2 and one-byte type, then payload. Bound frames to 16 KiB, each
direction to 64 KiB/eight messages, and setup network I/O to 30 seconds. Every
receive requires its expected message kind before interpreting the payload;
straight-line sender/receiver control flow defines the sequence. An unexpected
kind poisons the same frame budget, so duplicates or resumed reads cannot bypass
the check. Require empty signing markers. Reject unknown versions/types,
truncation, oversized lengths and resumed use of poisoned channels. Consume
exactly one frame: READY closes control framing before native Git; never buffer
ahead. Publication uses the private data envelope below; other sessions remain
byte-exact raw Git. Key creation negotiates provision-v2. When
porter.skipWrappedKey=true, respond to a publish-v5 request with
publish-account-v3; retain intent-v2 publication fields but use the non-signing
sequence (RESOLVED then READY). The sender never consults its agent or sends
derivation/signature messages. This explicit mode is not a fallback when wrapped
credentials fail. Key creation participation is not needed and receiver-side
provisioning refuses it in account-agent mode.  Publication negotiates
publish-v5 and an intent-v2 payload containing operation, path/identity, mode,
ref, new commit and observed lease tip. Reject old publication intents rather
than guessing a lease. Any intent may end with bounded path-hint-v1 relative
checkout path ([LLP 0002](0002-clients.explainer.md#search-policy)). A
key-creation intent carries no job selector. Local-only force uses local-v1 with
a trailing force-v1 intent field before optional hints; explicit paths must
negotiate this intent too. Local-only lease sends negotiate intent-v2 with mode,
ref, new OID and observed old OID; explicit paths negotiate too. Raw
receive-pack and ordinary local intents have no permission to rewrite history.
Parse the mode once from the matched intent shape; origin text cannot grant force.
Validate nonempty discovery identity fields even for explicit paths. A single
preferred URL retains the plain identity field. Multiple/fallback identities use
`remotes-v1 ` (including the space) followed by bounded JSON with preferred (URL or null) and alternatives
(URL list); reject unknown fields, malformed URLs and oversized/count-exceeding
sets. Older receivers refuse this new field rather than guessing a match.
HELLO=1, INTENT=2, RESOLVED=3, DERIVE_ED25519_V2=4, SIGNATURE=5, READY=6,
COMPLETE=7, ERROR=8 (not a successful transcript), SIGNING=9, SIGNING_DONE=10,
RESULT=11, APPROVE_PUBLISH_V1=12.

A signer sends empty SIGNING before consulting its agent and empty SIGNING_DONE
when approval finishes, then SIGNATURE. Only this ordered, bounded prompt
subprotocol pauses both input and output network clocks; resume the remaining allowance for signature
bytes and subsequent messages. Mirror it across approved key-creation IPC. The receiver proxy's private owner
channel shares the receiver session cancellation token as well as its I/O deadline. Keep
cancellation and the 1200-second overall session/prompt ceiling, including the
pending owner’s private IPC wait; a prompt cannot reset that lifetime. Local
agent connect has a two-second deadline; identity/network I/O stays bounded.
[Local socket setup](../src/runtime/ipc.rs) uses socket2 for socket ownership
and Unix address construction. Retain an explicit nonblocking connect deadline
and retry a full listener backlog; writable readiness alone cannot prove that an
EAGAIN connection succeeded. The signing read may wait for user approval within
that session ceiling. The source agent client and restricted onward agent share
only the length-prefixed [SSH field codec](../src/runtime/ssh_wire.rs). Message
limits, expected fields and authorization remain the responsibility of each
role.


After signature submission (or the account-agent RESOLVED response), the sender
allows 150 seconds for READY: the receiver's 120-second origin pre-authentication
allowance plus 30 seconds for setup overhead and control traffic. The receiver
uses the same 150-second control allowance while preparing origin authentication.
The already-up-to-date inline publication starts after READY, under native-phase
supervision, so its origin query/push cannot consume the READY allowance.
Signing pauses never extend the enclosing 1200-second session ceiling.

## Signing

Each default wrapped-key publication has one bounded typed exchange containing
exactly two ordinary Ed25519 signatures: a fixed unwrap derivation and a fresh
operation approval. Consume the allowance before signing, even on refusal;
helper reconnects cannot obtain another allowance. Key creation still derives
once. [Derivation](../src/credentials/derivation.rs) binds the exact canonical
source key and metadata fingerprint. Match loaded key data, not comments or
agent order. List identities once and verify both returned signatures locally.
Derive the wrapping identity only where it is used to encrypt or decrypt. Local key creation may wait for remote participation when
its exact key is absent; an agent refusal or invalid signature must fail without
retrying or falling back. Reconstruct the challenge locally:
`git-porter/v2/publication` + NUL + 16-byte salt. Never allow a receiver to
request another domain or generic SSH signing. The 64-byte signature is verified
before HKDF-SHA256; its info is `git-porter/v2/publication/x25519` + NUL +
source fingerprint. Metadata uses `git-porter-` Bech32 version 2. The new bundle
header is `git-porter wrapped-key v2`. The reader also accepts matching
git-porter v1 header and metadata solely to unlock an existing copy under its
original v1 domain without rewriting it. New key creation uses v2 metadata/domain;
refuse a v1 fresh creation token or header/metadata version mismatch.
No protocol downgrade exists. Previous age-plugin-derived bundles are
deliberately incompatible and require one-time rewrapping from the original
private key. A git-porter signature cannot unlock the foreign domain even with
the same salt.

Key creation uses public OpenSSH key, NUL and metadata. Publication uses
APPROVE_PUBLISH_V1: the same fixed derivation request, NUL, then a version-1 JSON
approval record with unknown fields rejected. It contains a fresh random 32-byte
nonce, canonical receiver repository, forge URL, ref, intended commit, force/lease
mode and observed lease tip (empty for ff/force). The receiver generates the nonce
for each session. The sender checks repository against RESOLVED and ref/commit/
mode/lease against its pinned local intent before signing. Construct the second
challenge locally as git-porter/v1/publish-approval + NUL + that canonical encoded
request; no generic signing or caller-specified domain. This binds the approval
also to the exact source key and bundle metadata. Bound the whole request to
14 KiB, each key/URL/repository to 4096 bytes, ref to 1024, metadata to 512 and key
comment to 256. Validate version, nonzero nonce, absolute path, canonical OIDs,
mode and native identity syntax. The response is fixed unwrap signature followed
by approval signature (64 bytes each). Verify the approval before deriving the
unlock identity. Wrong-session replay and any context change refuse. Neither
publication path rewrites credentials. Keep the single-use signing allowance and
transaction/hook claim; no retries or second push with the same session.
Old publish-v4 peers fail explicitly; provisioning and stored bundles are unchanged.
Local-only send, receive and setup never sign. SSH connection authentication
independently uses the caller's normal SSH credentials.

Report receiver credential failures separately from sender refusal. Source/bundle
validation before the request and decryption or sidecar failures after
valid signatures are credential failures; only signing and signature verification
use the sender-refusal classification.

## Sender bootstrap

An existing nonempty SSH_AUTH_SOCK remains authoritative: connect to that agent,
require the exact source key and propagate connection/signing failures. Never
replace an existing agent after refusal or a missing-key response. Without that
variable, first use an explicit IdentityAgent from the sender's selected SSH
configuration with the same rules. SSH_AUTH_SOCK's special IdentityAgent value
supplies no agent when the environment variable is absent.

Otherwise bootstrap one temporary native ssh-agent, load only the configured
source key using ssh-add -q, suppressing successful identity/lifetime notices
while retaining loading errors and passphrase prompts. Use the bounded agent client for
wrapping. Select candidates from the same SSH command's -G output, bounded to 64
KiB/32 IdentityFiles; never search arbitrary directories. Absolute and ~/ paths
work; unresolved tokens fail clearly rather than guessing. Validate
account-owned, owner-only bounded files outside Nix, compare native ssh-keygen's
SHA256 fingerprint with the pinned source before loading, then require exactly
that canonical public key in the new agent. ssh-add skips certificates and
limits key lifetime to 1200s. Use native key loading, including passphrase input
from an available controlling terminal; stdin stays disconnected from Git's
protocol and askpass is disabled. Headless encrypted-key loading must fail
clearly, requiring a preloaded agent. Hardware/provider identities still require
an existing compatible source agent.

Keep the socket in a private operation directory and pass it only to the loader
and the Rust agent client. Never export it to Git, hooks, the receiver
connection, or the account environment. Bind foreground ssh-agent to the
existing session's exec guardian, fixed lifetime, parent liveness and
cancellation. Stop/reap it before emitting wrapping signatures or native Git
bytes, including errors and unwind. Reuse the receiver's recognized owner-only
agent directory, PID marker, dead-run sweep and cleanup reporting; keep receiver
session-bind/peer policy separate. The standard sender agent can sign arbitrary
agent requests from a process able to reach its socket: private directory
permissions and a short lifetime are not a sandbox against other processes with
the same UID or root.

Native agent loading is the sole bootstrap backend; no direct-file Rust signer.
Reuse exact-key derivation, domain reconstruction, the consumed signing budget
and signature verification. No private key copy is written by porter. Existing
SSH login identity selection is unchanged. Apply the bootstrap to key:create
--sign; receive, local-only, no-origin and skipWrappedKey publication never
start it.

## Ownership

The following bundle/temporary-agent lifecycle is the default. Explicit account
agent mode uses no bundle or temporary agent, leaves the external agent running,
and preserves publication/transport policy as specified in [LLP
0000](0000-access.explainer.md#account-agent-opt-in).

[Storage](../src/credentials/keys.rs) writes publication.wrapped,
publication.pub and publication.source.pub as plain atomic files in the data
directory. No generation directories, pointer or checksum manifest. Serialize
writers with the account key-creation lock; preflight all destinations before
replacement and write ciphertext last. Atomicity is per file, not across the
set. Interruption may leave an inconsistent set; source binding/private-public
correspondence checks fail closed and the operator reruns key creation to repair
it.

The forwarder key authenticates onward pushes to the forge; the separate sender
source key unlocks its encrypted bundle. Forwarder keys are Ed25519 only;
imports must be unencrypted OpenSSH private keys. key:create creates or replaces
the wrapped set, importing the forwarder private key with --key-import path|- if
requested. Its optional positional argument is a sender public-key file path,
one quoted OpenSSH public-key line, or a public wrapping token (also readable
from a file). Explicit input overrides the recorded source for this creation;
otherwise read publication.source.pub or prompt. Resolve public input before
--key-import - consumes private-key stdin. Save the source only on successful
wrapping.

Hostless key:create --sign creates fresh v2 metadata, signs locally, derives the
age identity, destroys the signature/private identity and prints only the public
wrapping token. Select the explicit sender key or, with no input, the sole
ordinary Ed25519 identity in SSH_AUTH_SOCK; reject ambiguous selection. Reuse
the exact-key agent client and supervised native agent loader for an explicit
.pub sibling when no agent exists. No host means no host-specific SSH config
lookup. Existing agents remain authoritative. Private keys never cross machines.

The checksummed git-porter-wrap Bech32 token has version byte 1, big-endian u16
request length, the existing bounded Request encoding and an age X25519 public
recipient string. Cap tokens at 4096 bytes; reject unknown versions, truncation,
invalid recipients, non-v2 metadata and bad source binding. It includes no
signature or age private identity. Its recipient/source relationship relies on
trusted public key enrollment and is checked by decryption on first publish; do
not claim a proof of possession from the public token alone. Generate a fresh
token per forwarder key; never deliberately reuse salts across independent
bundles. The receiver wraps directly to that public recipient, reusing locked
atomic storage and the existing bundle version/domain. This requires no agent,
SSH connection, pending process or plaintext-key persistence on the receiver.

Remote --sign user@host remains completion of a live receiver-approved request;
it cannot combine with positional input or --key-import or change the pinned
key. Without a token/local source, creation waits for this existing signing
exchange. Existing publication.* storage names and cryptographic domains remain
unchanged. Keep imported/generated private material only in memory. No secret is
persisted while waiting; termination abandons the request. In wrapped mode,
key:public needs no agent and reads the fixed XDG credential files. All outputs
use XDG data/git-porter without path overrides. An existing invalid policy or
unreadable/malformed account Git configuration is an error, never a reason to
ignore its paths or silently choose a default directory.

A pending key-creation job is receiver-approved, expiring and single-use. Bind
its identifier and exact metadata/source to the live owner via private IPC.
Authenticate SSH through the restricted authorizedKey account entry,
authenticate server host identity through normal SSH trust, then verify the
signature against the pinned Ed25519 source. A job identifier is not a bearer
credential. Same-account 0600 metadata/private IPC bind the exact request to its
live owner. Refuse multiple pending jobs rather than exposing a selector. Reject
unsolicited, ambiguous, wrong-source, changed, expired or duplicate jobs. Only
the approved process commits files; sender participation cannot change policy.
Local or remote participation passes the verified derived identity directly to
credential creation. Do not serialize/reparse the owner's request or derive an
unused identity merely to validate a response. Consume an imported private key
rather than cloning its signing material. The pending owner uses its existing
session for cancellation; do not register another independent signal state.
Report failures to remove pending metadata during cleanup.

The trusted receiver briefly owns the unwrapped key for origin
pre-authentication, receipt and one push. Destroy its in-process agent and owned
secrets on completion, error, disconnect, parent death or timeout. Keep only
ciphertext/public/socket artifacts. Disable core dumps; zeroize owned plaintext
and derivation buffers. Library allocations and kernel swap limit total-RAM
wiping guarantees. No persistent agent or credential reuse across publishes. The
receiver/forwarder keeps the encrypted forge-key copy unchanged. Verify fresh
operation approval before unwrapping; retain the bundle/key-creation flock across
the publish to prevent concurrent enrollment replacing the selected credential
set. Refused/incomplete signing refuses publication and never changes stored files.
This is protocol freshness, not cryptographic one-use encryption: the fixed
unwrap response remains reusable secret material. Anyone with it and its bundle
can decrypt the same forge key offline, regardless of approval nonces. SSH protects
transport; zeroization and bounded process ownership protect ordinary operation,
not a compromised trusted receiver retaining plaintext/signatures. Rotate the
actual forge key on compromise. Stable bundles can be seeded/restored by agenix
on multiple receivers, with matching public sidecars and the same sender key;
restoration needs no ratchet state. Explicit key creation/replacement still writes
new encrypted credentials atomically; normal publishing does not write them.

The temporary agent accepts only kernel-identified SSH peers (LOCAL_PEERPID on
macOS, SO_PEERCRED on Linux), pinned executable and UID, beneath a Git
executable in this receiver/forwarder's child tree. Pin executable file identity
(device and inode), so hard-linked Git entry points identify the same binary
while a copied binary does not. Revalidate a bounded
ancestry chain and process birth identities before each request. Unauthorized
peers consume no slot. Only trusted Ed25519 forge host keys are supported,
selected through built-in trust and ssh-keygen's matching account known_hosts
entries. OpenSSH must send session-bind@openssh.com with a valid host signature
of its session ID and no forwarding. Verify userauth session ID, expected user,
ssh-connection service, Ed25519 key, signature flag and optional hostbound key;
deny unbound/generic data. Each process birth identity gets at most one
signature across reconnects. Extra SSH descendants for pre-authentication, lazy
fetches, push and state re-checks may independently authenticate. The isolated
publication Git context configures only its pinned origin as promisor and
permits hydration there through the same restricted transport. Metadata/access
checks retain lazy-fetch suppression. Scoped peer threads always join, including
worker unwind; stop-aware socket reads bound teardown. Report join and cleanup
errors. Sweep only recognized owner-only temporary agent directories with
matching PID markers whose owning PID is gone; never remove a live/reused PID's
directory. SIGKILL cannot run destructors, so dead-run cleanup is deferred to
the next sweep. PID/ancestry inspection has TOCTOU limits; it is not a sandbox
against same-account ptrace/injection or root. Swapped/copied keys, kernel
swap/core handling, crypto backend temporaries and ssh-key Signature's private
non-zeroizing allocations limit total-RAM erasure. Owned plaintext,
response/derivation and request buffers are zeroizing; local agent responses
remain in their original zeroizing allocation through parsing rather than
passing through an ordinary buffer copy. No extra plaintext persistence is
introduced. Native Git/SSH children use the key-free exec guardian and bounded
process groups; owner liveness EOF must kill/reap descendants while preserving
Git's native streams. Before native launch, the guardian announces readiness and
requires an owner permit. The owner's entire readiness/permit/PID handshake is
cancellation-aware and bounded by two seconds or the remaining receiver lifetime.
The permit carries an absolute monotonic expiry; the guardian rejects missing,
expired or disconnected-owner permits before spawning native code. Before a
permit, cancellation can immediately kill the delayed guardian group: no native
group exists. After a permit authorizes launch, close liveness and let the guardian
reap any native group before escalation. No startup data enters Git's streams. Captured subprocess readers are scoped: close the owned
child/guardian before joining its reader on success, cancellation, wait errors
or unwind. Session checks, owned children and deadline-aware I/O share one
cancellation predicate and fixed lifetime; network prompt pauses never extend
that lifetime.

## Setup checks

[Setup checks](../src/cli/diagnostics.rs) inspect policy, key presence and host
trust without signing or repository transfer. No remote diagnostic
command/protocol exists. Only publication can prove private/public
correspondence and origin authentication.

## Publication results

[Results](../src/runtime/push_result.rs) negotiate publish-v5 (or the explicit
publish-account-v3 response). RESOLVED is a version-1 record with repository,
publication and signing booleans. No configured origin means no publication or
signing, but still requires the final result. Old capabilities fail explicitly.

After READY, receiver-to-sender bytes use a private envelope: four-byte
big-endian body length, version 1, type 0 for native Git data or 1 for the final
result. Data payloads are nonempty and at most 65536 bytes; final JSON is at
most 16382. The compiled helper strips the envelope; native Git sees only
byte-exact data. Sender-to-receiver Git bytes remain raw. Never scan pack or
remote diagnostic text for status. One final result follows the native output,
then EOF; reject missing, truncated, duplicate, trailing, oversized,
unknown-version or malformed records. Pre-READY failures instead send RESULT in
the bounded control channel.

The receiver retains one immutable transaction context in memory and writes its
private serialized copy solely for the separate hook process. Validate hook
results against that retained intent, not by rereading the hook handoff file.
The hook atomically records version-1 native onward porcelain rows and typed
attempt/acceptance state in its private transaction directory. The receiver
collects that record after Git exits, including inline up-to-date hooks,
failures before the hook and local-ref failures after it. After an attempted
failure, recheck origin through the same isolated credentials and classify
actual presence: intended SHA, expected old tip, another tip/absence, or
unknown. Presence never proves causation. Keep repository and bundle locks
through this recheck. Rechecks use a bounded child of the receiver session,
never a new independent lifetime. Key-held Git setup/ref queries and account-agent
validation also use owner cancellation. Child deadlines cannot extend the owner and
dropping a bounded child does not cancel its owner. On cancellation, refuse new
authentication, classify unfinished rechecks as unknown and destroy the key/agent
and locks before final output. Hook claims are create-once files in the private
transaction directory; a second hook cannot overwrite the first report or
initiate another publication.

Final records bind the requested branch and intended commit, receiver success,
short receiver reason and optional forge URL/rows/outcome. Validate exact
fields, version, bounded strings, direct branch syntax, OIDs, row count/flags
and matching ref/commit. The sender helper writes one private 0600 result file
in the parent operation's 0700 directory; the parent independently validates and
pins it before rendering. Missing result channels fail explicitly; never guess
an onward outcome.
