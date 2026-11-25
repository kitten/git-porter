# LLP 0002: Clients and discovery

**Type:** Explainer\
**Status:** Active\
**Systems:** Clients, Discovery\
**Related:** LLP 0000, LLP 0001

## Installation boundary

Install git-porter, git-send and git-receive beside Git/OpenSSH. git send and
git receive are separate Git subcommands; there is no duplicate admin dispatch.
Clients need no porter setup, generated credentials, shell edits, manual
discovery prerequisite. Supply the receiver positionally or through
porter.destination. Send requests publication unless --local-only; the receiver
publishes only when the resolved repository has an origin push URL. No client
publication setting exists. Receive is always unsigned and fast-forward only.
Both clients accept --branch name with charset/check-ref-format validation and
refusal of symbolic branches. Detached HEAD requires --branch. Send
--force-with-lease observes the receiver's exact tip through unsigned ls-remote
--refs, pushes with that explicit lease (empty means absent), and carries lease
mode to onward publication. Do not refresh stale leases. A matching lease
permits non-fast-forward updates. Local-only or explicit-path receipt checks
only the receiver tip; origin is checked only when an onward publish actually
runs, in which case both tips must equal the observed receiver tip. Preserve the
observed old OID through the hook. A failed fast-forward retains FETCH_HEAD and
prints git log --left-right --graph <ref>...FETCH_HEAD. A branch switch during
fetch retains FETCH_HEAD and asks the caller to switch back. Non-current branch
fetch errors advise inspecting FETCH_HEAD before merging or rebasing divergent
history.

## SSH route selection

Mirror the original system scripts for an unrestricted SSH account: send/receive
use the source checkout's HOME-relative path on the receiver. For linked
worktrees use the main checkout when its common directory is .git. Bare and
separate-metadata repositories use their checkout/repository path. An explicit
host:path overrides this inference. Native transfers need no remote identity,
Porter setup, sender unwrap signature or forge credentials, and never forward to
origin. Preserve Git's force/lease flags, user hooks and fast-forward-only receive.
Git's own receiver/worktree rules still apply. Checkouts outside sender HOME or
with unsupported native path syntax need an explicit path; their Porter discovery
still works independently.

Select the route on the same SSH connection, before sending control or Git bytes.
The remote command has a fixed printf marker prefix followed by native Git with a
validated quoted path (or false when no native path is available). A normal SSH
shell emits NATIVE_ROUTE, changes to receiver HOME and execs Git; the restricted
forced command recognizes the literal prefix, never evaluates the suffix, emits PORTER_ROUTE and enters the
existing validated session. Read exactly the fixed-length marker with a deadline
and cancellation, without consuming Git advertisement bytes. Native then relays
raw Git bytes; Porter performs its existing bounded negotiation/signing/result
exchange. Missing, malformed or failed markers never trigger fallback. Once the
route is Porter, errors never retry native. Keep SSH forwarding/multiplexing off
and normal user SSH identity selection. No GPG-agent-specific detection is needed.
Explicit non-force/non-lease reads and local-only writes retain their direct
native Git request path, including git-shell-only endpoints.

Record routed selection atomically in the private operation directory and require
the same selection across lease observation and push, including explicit paths.
Clear inherited private mode/lease variables before constructing each operation;
lease observations select routing without granting write/force intent. The parent
suppresses the Porter result requirement only for an explicitly recorded native route; render
normal receiver rows with no Forwarded block. A Porter session with missing final
framing still fails. A read-only route decision is never inferred from an error,
exit code, SSH identity algorithm or unstructured diagnostics. Discovery failures
are deferred until the Porter route is identified, so originless repositories
still work over ordinary SSH. Receivers need a normal command-capable SSH shell
for automatic native routing; no helper installation is required there.

## Lookup

[Discovery](../src/server/discovery/mod.rs) runs on demand for both send and
receive when explicit paths cannot resolve the repository. Setup never surveys
the home and no discover command exists. Prefer the sender's origin identity.
If it has no receiver match, try the sender's other remotes, regardless of name,
against the receiver's authoritative identity (origin, or its sole secondary
remote when origin is absent). A preferred match wins over secondary matches;
ambiguity in either tier refuses rather than selecting by remote order. Deduplicate
normalized sender identities. Each remote must have exactly one usable URL;
an unusable origin is an error, while unusable secondary remotes provide no
evidence. With no origin, all usable secondary remotes form the fallback tier.
Bound sender enumeration to 16 remotes and the encoded identity set to 8192 bytes.
All receiver scans share the five-second lookup budget and reuse the inventory
cache. A relative-path shortcut applies only to the preferred tier; fallback
matching checks all alternatives so a hint cannot conceal ambiguity.
Normalize SSH/SCP/HTTPS identities conservatively, folding hostname case while
retaining port and repository path case. Reject credential-bearing URLs.
Sender lookup uses Git; receiver inventory reads remotes in-process using
libgit2, as does the direct relative-path shortcut. Receiver config
selection opens only the repository's config, plain includes and (when enabled)
its declared worktree config. Resolve gitdir and commondir files without opening a
libgit2 Repository, because that can load ambient settings. System, global and XDG
configuration is never loaded for discovery; global URL rewrites do not count.
An empty URL resets earlier values; exactly one surviving URL is required.
Conditional includeIf entries make the repository a nonmatch, regardless of
whether their condition might apply. Multiple URLs, unclear remote selection,
conflicting equal-length rewrites and malformed own config are also nonmatches.
Use a plain repo-config include or an explicit receiver path for such layouts.
Lease observation, origin preflight and outcome rechecks share one exact-ref
advertisement parser.

## Candidate scan primitive

Search trusted roots (receiver home by default),
learning flat/namespaced/deep layouts. Prioritize expected paths and nearby
sibling checkouts, including same-name repositories under neighbouring owners.
Check their actual remotes: org/repo alone is not fork identity. Then examine
wider candidates. Sibling enumeration is capped at 512 entries within the shared
search deadline; reusable cache hits skip it. Scan priorities do not establish
authority or uniqueness: require bounded coverage and report
duplicates/incomplete scans rather than selecting an arbitrary match. The
validated sender-relative shortcut below is separate from this full scan.

Fix depth at six, enumeration to 10,000 entries, and traversal to five seconds.
Check the deadline before and after each in-process repository inspection and
return explicit incomplete coverage on exhaustion. Filesystem/config reads cannot
be preempted; this backstop is not a hard I/O deadline. Deduplicate overlapping roots,
skip symlinks/dot directories and prune common build/dependency trees.
Revalidate repository/common metadata before transfer.

## Inventory and learned structures

Use one bounded pointer resolver for inventory hashing and identity lookup.
gitdir/commondir pointers are plain regular files of at most 4096 bytes; open
nonblocking and recheck the opened file type so a FIFO or file-swap race cannot
block the reader. Strip only CR/LF line endings and preserve path whitespace,
including a final space. Hash the resolver's raw pointer bytes and canonical
metadata paths. Invalid layouts are volatile nonmatches, never reusable positives.

[Cache](../src/server/discovery/cache.rs) is disposable public metadata under
XDG_CACHE_HOME/git-porter, otherwise home/.cache/git-porter. Use real owner-only
directories, atomic 0600 files, a 4 MiB bound and short non-sliding
coverage/negative expiry. Scope caches by search/access policy, using the
walker's sorted, deduplicated, non-overlapping roots so equivalent hints do not
create separate inventories. Keep per-repository path, normalized identity and
configuration-content digest across coverage refreshes. Reuse unchanged positive
identities even after expiry or an unrelated directory change; retry negative
entries when coverage refreshes. An incomplete lookup may retain validated
entries for subsequent bounded progress, but cannot claim a unique answer. Drop
paths absent from refreshed coverage and replace identities immediately when
their current remote no longer matches.

Coverage observations describe traversed non-repository directories. Ordinary
changes inside a repository, including untracked files and branch movement, do
not invalidate the directory census. Check each repository marker separately:
losing it requires a fresh walk, which may expose repositories previously nested
beneath that root. New/moved/duplicate repositories still invalidate parent
coverage.

Revalidate configuration contents, including linked-worktree/common paths and
volatile includes. Hash each distinct config directory only once; HEAD need not
enter a non-volatile remote digest because conditional includes are always
re-evaluated through libgit2. Recheck every matching identity in-process before
selection. Changed configs, includes, unknown entries and expired negatives
require fresh config inspection; hints and cached identities never authorize
access. Use sorted hint membership/prefix lookup to rank the bounded traversal
without formatting unused layout reports. Failed cache writes or corrupt data
must not affect correctness. Cache format is disposable/versioned, with no
secrets or authorization. Full access/metadata validation still follows
discovery.
Invalidate older inventories when traversal eligibility changes, so cached paths
cannot preserve locations excluded by the current walk.

## Search policy

porter.searchRoot is multi-valued, defaulting to HOME. searchStrict defaults to
false; when enabled it confines discovery and all repository/metadata access to
those roots. Without explicit roots use HOME. Non-strict search includes HOME;
receiver roots outside HOME are rejected, including symlink escapes. A sender sends only
the checkout path relative to the first containing sender root, or no hint.
Compute this once from the pinned repository and its Git config before launching
transfer helpers; explicit receiver paths need no hint. Unset roots default to
sender HOME; checkouts outside the roots send no hint. Malformed Git configuration
is an error. The optional path-hint-v1 intent
suffix is a single UTF-8 relative path, at most 4096 bytes, without controls,
backslashes, empty/dot/parent components or an absolute prefix. The receiver
validates it even under searchStrict, which ignores it. Otherwise try it beneath
receiver search roots, using the walker's exclusions and repository-boundary
predicate. Every path component must be a real directory: do not follow directory
symlinks, cross dot/excluded/cache directories, or descend through an ancestor
repository (including bare repositories and .git files). Measure depth from the
walker's non-overlapping roots; a redundant deeper configured root is only a
layout anchor and cannot reset depth or bypass a repository/excluded ancestor.
Shared exclusions recognize case aliases of the same filesystem directory;
distinct differently cased directories on case-sensitive filesystems stay distinct.
Canonicalize without escaping the root, validate access and confirm remote
identity. Missing, ineligible, ambiguous or mismatching hints are ignored and fall
back to normal remote matching, without a hint-specific error. Malformed protocol
hints still fail closed. Explicit host:path access remains governed by access
policy, including strict-root and home confinement. Sender absolute roots never
cross the connection. Configured roots accept home-relative/absolute paths, including ~/
and literal $HOME/. All runtime/cache/snapshot paths remain canonical absolute
paths. HOME is always the outer receiver access boundary; searchStrict can only
narrow it. Hints never grant access. Depth is fixed at 6, with
built-in excludes node_modules, target and Library.

## Local-only transport

[Clients](../src/cli/client/mod.rs) use a private per-operation remote name,
fixed URL and pushurl, excluding repository remote helpers and pushInsteadOf
redirects. Resolve the operation’s effective URL once without connecting, require native SSH syntax
(reject ssh:: external helpers), and whitelist GIT_ALLOW_PROTOCOL=ssh for
receiver-ref observation, push, lease observation and receive fetch. Force the adjacent compiled helper through
GIT_SSH_COMMAND and GIT_SSH; shell-quote the GIT_SSH_COMMAND path so TMPDIR
characters cannot split or substitute the helper. The helper pins intended
host/path/identity rather than rewritten argv. Disable forwarding and masters.
Failed negotiation never retries/downgrades.

Explicit local-only paths use ordinary Git requests; restricted publication always
negotiates publish-v5. Ordinary SSH routing transfers directly instead. Lease observation is a separate unsigned read-only
session. Receive into the current branch requires a clean worktree, fetches into
a temporary ref, rechecks HEAD, merges --ff-only without autostash and removes
the temp ref. Protect other checked-out worktrees and retain useful
partial-success diagnostics.

## Client SSH

[SSH selection](../src/cli/ssh.rs) uses GIT_SSH_COMMAND, core.sshCommand,
GIT_SSH, then plain ssh, in that order. Respect GIT_SSH_VARIANT, ssh.variant and
Git-style name/-G detection; reject effective variants other than OpenSSH.
Simple commands are split directly; shell syntax (including quotes) uses sh -c
with Git’s appended "$@" convention. Shell expressions place their own embedded
options before the appended guards; flag filtering and guard-first ordering
cannot be guaranteed for arbitrary shell expressions. Use simple commands for
those guarantees. Capture selection before installing the compiled Git helper
override; carry its command form through private operation context, not
inherited file descriptors. The helper pins the requested destination and
prepends -a -o ForwardAgent=no -S none and disabled master/persistence settings.
Discard direct -A/-M/-S overrides which bypass OpenSSH's first-config-value
rule. There are no client identity pin options. Without an agent socket,
wrapping participation may load the matching owner-controlled Ed25519
IdentityFile from that same SSH selection into a supervised temporary agent,
only for the sender's bounded negotiation ([sender
bootstrap](0001-protocol.explainer.md#sender-bootstrap)). The private socket is
not exposed to Git or SSH login, whose identity selection remains unchanged.
Onward publication ignores user SSH commands/configuration and uses its separate
in-memory agent by default; explicit account-agent mode follows LLP 0000.

## Destination selection

The explicit positional user@host or host wins. Otherwise use
porter.destination; without either, error. The binary has no built-in
destination or automatic user prefix. The system module may set an account
default such as user@localhost. host:path is a documented escape hatch for
discovery, never for access policy.

## Client Git configuration

Resolve the Git directory and worktree once per invocation, honoring inherited
repository selection only for that initial resolution. Reuse the pinned context
for metadata, transfer, merge and temporary-ref cleanup; do not rediscover it
for every command. After resolution, strip inherited GIT_CONFIG_*, GIT_DIR,
worktree/index/object/namespace/shallow overrides. Keep ordinary user Git
configuration and hooks. Use explicit --no-follow-tags --recurse-submodules=no
--signed=false, clear inherited push.pushOption and disable push.negotiate. Do
not override merge.verifySignatures or bypass client hooks.

Disable lazy fetching under the receiver-pinned SSH helper. Before each send
push from a shallow or partial sender, stream receiver refs to a private file
through receive-pack, without publication negotiation. Use a separate receiver
connection for this observation. Retain the Porter receiver's normal
receive-pack repository write lock during observation; fail if it is busy. Use
ref objects rather than peeled IDs from opaque receiver-only tags. Exclude
advertised commits available in the sender from hydration walks, peeling
annotated tags available locally. Skip observation and object catalogs for
full, non-shallow senders. Recognize partial senders by promisor configuration
or promisor packs.

Serialize git-send hydration with an advisory flock on the common Git
directory; do not treat this as serialization with native Git. Deepen outgoing
shallow roots through configured sender remotes, starting at 256 and doubling
each successful step until shared receiver history or full history is reached.
Prefer the last successful deepening remote and try other configured remotes
when it cannot advance the frontier. If no remote advances the combined
frontier, try roots separately until one advances so merged fork/upstream
histories can progress independently. Re-evaluate the same observed receiver
IDs after deepening; do not observe again. Treat receiver tips unknown locally
as unusable packing haves; permit full-history deepening and hydration when no
usable shared history remains, even if the receiver is merely ahead of a stale
sender. Preserve the invocation's fixed 1200-second lifetime across hydration
and the final push; fail before the push if deepening exhausts that budget. Do
not reserve a separate push quota; retain the existing uncertain-outcome
handling if the lifetime expires during a push or publication.

Resolve boundary trees before enumerating outgoing objects; keep excluded
historical blobs unhydrated. Request each walk's missing IDs together from a
sender promisor; try the remaining configured promisors if it cannot supply
them. If every promisor rejects a request, split it in halves and retry the
halves through the promisors. Fail when a single ID remains unavailable;
rewalk after successful requests and retain the no-progress check. Use a
separate SSH role with the selected user SSH command, actual configured remote
endpoints, forwarding off and multiplexing off. Preserve refs, configuration,
FETCH_HEAD, index and worktrees. Disable fetch.bundleURI for hydration fetches
so bundles cannot write refs or configuration. Use noop fetch negotiation so
local commit haves cannot imply that missing objects or delta bases are
available. For partial senders, use a command-scoped blob:none filter for
fetches, including deepening through plain remotes; rewalk fetched trees. Fail
before the push when neither objects nor shallow roots advance.

Keep lazy fetching disabled for the final push. Disable sparse packing so its
object selection agrees with the hydration catalog. Always use --no-thin
because receivers can be partial. Retain the isolated forwarder's origin-bound
hydration policy. On a receiver-ref change between observation and push,
report native push failure without an automatic retry.

## Push status

Refusals state the observed failure, not a presumed fix. A missing sender-key
match identifies the required key; incomplete receiver setup is reported as such.
Do not prescribe key creation, agent loading, policy changes or other speculative
remedies to the sender. Error messages do not name configuration options or
advertise policy overrides. Help and intentional setup/enrollment instructions
remain separate. Both negotiated preflight and the hook report rejected branch
prefixes with the allowed list and "Rename your branch before sending it."
Retain concrete recovery information, such as FETCH_HEAD and uncertain remote
state; inspect remote state before retrying, without suggesting force.

[Status rendering](../src/cli/status.rs) buffers native receiver porcelain and
the validated final result, then prints the receiver block followed by a
separate Forwarded to URL block on stderr. Use native ref-status flags and
friendly branch names for both source and destination, never the pinned SHA as
the source label. Native onward rows precede typed outcome summaries; suppress
raw porcelain and Done. Receiver hook failures use the structured short onward
failure/uncertainty reason. Ordinary Git/SSH/forge diagnostics remain
diagnostics; never parse them. Local sender hooks remain enabled; stdout lines
outside the tab-delimited native porcelain rows are retained as diagnostics on
stderr. Remote diagnostic text is never a status source. No configured onward
origin produces no forwarded block. Failed rechecks report uncertainty and
instruct inspection, never claim absence or successful causation.

Send accepts --quiet: suppress successful blocks, retain failed or uncertain
blocks, including confirmed presence after a failed operation. --porcelain and
--verbose are unsupported. The record format remains versioned independently of
rendering so a future machine surface need not parse human output.
