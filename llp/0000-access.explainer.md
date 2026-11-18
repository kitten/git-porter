# LLP 0000: Access and trust

**Type:** Explainer\
**Status:** Active\
**Systems:** Access, Policy\
**Related:** LLP 0001, LLP 0002, LLP 0004

## Boundary

Trust the receiver account, root, repository administrators and local
filesystem. This restricted entry is not a sandbox against them. Parse inbound
commands; never evaluate them as shell code. Resolve repository/common Git
metadata beneath receiver HOME, deny dot components, escapes and nonempty alternates.
With searchStrict enabled, also confine every repository and metadata path to
one of the canonical searchRoot directories (HOME if none are listed). Serve requires a
nonempty authorizedKey policy even for reads: removing receiver policy must fail
closed if a previously installed forced-command SSH entry remains. Setup may
still warn and succeed without keys, but cannot install authorization.
Cached paths and sender layout hints never confer access. searchRoot accepts
absolute or home-relative paths, including ~ and literal $HOME prefixes. Resolve
and canonicalize against receiver HOME, never process cwd; reject receiver roots
outside HOME. Defaults are searchRoot=HOME and searchStrict=false. Explicit paths
bypass discovery but retain the same home and strict-root boundaries. A symlink
or linked-worktree/common metadata path cannot escape those boundaries.

[Configuration](../src/server/config.rs) reads the receiver account's global Git
files: XDG_CONFIG_HOME/git/config (otherwise HOME/.config/git/config), then
HOME/.gitconfig. Require HOME; ignore GIT_CONFIG_GLOBAL and other Git
environment overrides. Disable includes and system/repository configuration.
Ignore unrelated settings, reject unknown porter.* keys and duplicate singleton
receiver settings. porter.destination is a sender setting; receiver loading does
not enforce its singleton policy. Check account-controlled file/link locations
and reject writable policy. There is no separate policy file or --config
selector. Serve resolves validated policy and absolute runtime paths once,
including all receiver keys, repeated prefixes/destinations, home/data/cache,
executables, known_hosts and credential locations. Pass one bounded, versioned
JSON snapshot in GIT_PORTER_HOOK_CONTEXT explicitly on each owned Git command.
Include the operation mode, expected ref/new OID/observed lease and publication
transaction path when applicable. Hook and onward transport load only that
snapshot, never Git configuration or HOME/XDG defaults; missing, malformed or
unknown versions fail closed. Raw pushes without serve's context are refused.
Quarantine object paths remain Git-provided per-receive context. Runtime file
safety checks still apply to the resolved paths; the snapshot is not a
credential or a same-UID sandbox. Incoming internal variables cannot select
top-level policy.

## Ref policy

Deny tags, deletions and symbolic updates. Require old to be an ancestor of new
for existing refs unless negotiated force or a matching lease permits rewriting,
including local-only sends. Validate the hook old OID against the observed lease
as well as the preflight check; raw receive-pack cannot supply a lease. Raw
receive-pack has no force permission. An empty allowedPushPrefix list is
read-only; writable namespaces are literal branch-directory prefixes. Refuse
branches checked out in any linked worktree. Re-read worktree membership at the
shared pre-receive boundary, after any signing approval and before onward work,
including an already-current inline publication. Keep native Git checks too.
Only the managed hook runs,
bypassing repository hooks. Suppress fsmonitor, maintenance, prompts, metadata
lazy fetching and inherited credentials/configuration while preserving Git
quarantine semantics. Force receive.fsckObjects=true as well as
transfer.fsckObjects. Require the compiled pre-receive link before write
advertisement or signing.

## Publication

[Publication policy](../src/server/publication/policy.rs) validates both resolved
origin push URL and final SSH argv; [transactions](../src/server/publication/mod.rs)
own credential use and outcome reporting. Optional repeated porter.publishTo entries match
origin destination hostnames; unset allows any configured SSH origin.
Authenticate and observe origin before local receipt, then publish from the
compiled pre-receive role using Git quarantine objects and alternates. Origin
rejection rejects the local update. The versioned intent binds mode, ref, new
commit and the client's observed lease tip; lease mode requires receiver and
origin to match it. Never refresh a lease. Force mode skips only
lease/fast-forward checks. Serialize porter write/publication operations with an
owner-only per-repo lock under the receiver data directory (keyed by common Git
directory, so linked worktrees share it) and retain native Git old-OID checks.
Read-only upload-pack sessions may run concurrently with a writer, including
nested promisor hydration; Git advertises committed refs/objects while
quarantine remains private. Read access need not create files inside a read-only
repository. If origin accepts but the local update subsequently fails, report
the receiver failure and rechecked origin state. Observed commit presence
establishes no causation. After any failed publication or receiver update,
re-read origin through the same isolated transport and the transaction’s
selected agent. Report published (intended tip), not published (preflight old
tip), moved (another tip), or unknown (re-check failed). Both normal and
already-present receipt paths use the same re-check.
Origin pre-authentication (including host-trust lookup) and rechecks inherit the
receiver's cancellation token and the earlier of the receiver deadline and their
120-second allowance. A canceled receiver never starts a fresh authentication.
An interrupted recheck is unknown. Drop the transaction agent/key and release both
locks before sending the final result or diagnostics; do not retain them for a
canceled connection. For an up-to-date receiver
ref, invoke the same hook after READY and before native receipt using existing
objects, since Git otherwise invokes no pre-receive hook. Each private publication
transaction has one atomic hook claim, taken before initializing its result.
Every subsequent hook refuses without altering that result or attempting another
onward push, including native receipt after an inline publish. Slow onward work uses
the native-phase deadline and all failures still produce the final framed result.

The complete configuration keys are porter.destination,
porter.allowedPushPrefix, porter.authorizedKey, porter.searchRoot,
porter.searchStrict, porter.publishTo, porter.allowDefaultBranch and
porter.skipWrappedKey. authorizedKey accepts Ed25519 public keys only. No
version, home, discovery tuning, path overrides or publication subsections
exist. Keys always occupy publication.wrapped, publication.pub and
publication.source.pub inside XDG data/git-porter. Secrets are owner-controlled
mode 0600 outside Nix. Before every onward push query ls-remote --symref origin
HEAD over the isolated transport. Refuse the resolved default branch and fail
closed if HEAD is unknown, independently of access prefixes or force mode. Only
porter.allowDefaultBranch=true opts out. Both receipt paths share this check and
existing failure-state reporting. Classify an ambiguous or invalid HEAD
advertisement as unknown, even if one of its entries names the protected branch.
Preflight and failure rechecks share the same single-ref advertisement parser,
requiring the requested ref and canonical OID. HEAD requires exactly one native-valid
branch symref and one canonical nonzero HEAD OID row; reject any malformed, missing
or duplicate row. Unicode branch names remain valid.

Check file safety, bundle/source binding and public-key syntax before
derivation. Only decryption can establish ciphertext authenticity and
private/public correspondence; reject those failures before origin
authentication or receipt. By default use only the transaction's in-memory
Ed25519 key for publication. SSH ignores user configuration for onward
credentials and disables agent forwarding/masters. Explicitly allow public-key
authentication only, disable certificate selection and password,
keyboard-interactive, GSSAPI and host-based alternatives. Select only the
transaction agent/socket and its public reference; never an ambient agent or
private identity file in wrapped mode. These settings apply to origin
pre-authentication, push and failure re-check. Origin pre-authentication, onward
pushes and default-branch queries have a 120-second overall deadline, a
15-second connect timeout, and ServerAliveInterval=15 / ServerAliveCountMax=3
(about 45 seconds without a server response). Keep the separate signing/session
allowance unchanged. Host trust uses built-in public forge keys plus
~/.ssh/known_hosts. No path override or extra trust settings exist; never
rewrite account known_hosts. Never accept an unknown key automatically.

Tailscale SSH can bypass OpenSSH forced commands. This utility cannot constrain
an entry never invoked; deployment must select the intended account/SSH route.

## Account agent opt-in

porter.skipWrappedKey is a boolean defaulting to false. When true, publication
uses the receiver/forwarder account's inherited SSH_AUTH_SOCK. Require an
absolute, account-owned socket that answers identity listing with usable keys;
actual origin pre-authentication must also succeed. Never fall back to a bundle
or identity file. Propagate SSH_AUTH_SOCK through controlled hook and transport
environments only for this explicit mode. No bundle, re-lock, source derivation
or temporary agent is used. The account agent remains owned by its account and
is never killed or modified by porter. Any process on the account can use those
forge credentials. Keep publishTo, live default-branch policy, mode/observed-tip
binding, force rules, ref/worktree rules, repository writer lock and outcome
rechecks unchanged. Onward SSH still ignores account SSH config, uses publickey
only, disables certificates, forwarding and multiplexing, strictly checks
built-in/account trust and retains connect/keepalive/overall deadlines. Set
IdentityFile=none and IdentitiesOnly=no for agent-only account identities; never
load default identity files. The wrapped mode's pinned
public-reference/IdentitiesOnly=yes behavior remains the default.
