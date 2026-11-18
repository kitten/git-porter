# LLP 0004: Installation and qualification

**Type:** Guide\
**Status:** Active\
**Systems:** Setup, Packaging, Testing\
**Related:** LLP 0000, LLP 0001, LLP 0002, LLP 0003

## Distribution

Use a single MIT LICENSE, Cargo license metadata and publish=false. Do not ship
THIRD_PARTY_NOTICES, deny.toml or SECURITY.md. The [flake](../flake.nix) pins
tools and builds native arm64 macOS, x86_64 Linux and arm64 Linux packages.
Archives contain exactly three binaries, README and LICENSE. No crate/tap
initiative.

`python3 scripts/package_release.py --package result --system SYSTEM --output dist` normalizes archive modes, ownership, timestamps and gzip
headers, refuses overwrite/unexpected binaries/missing files and writes
checksums. `python3 scripts/package_release.py --manifest dist` requires exactly three matching platform
archives/checksums and verifies their bytes before SHA256SUMS. Compare release
tags to Cargo metadata. Inspect native linkage and reject concrete Nix store
dependencies in shipped executables, retaining the literal security policy
prefix constant. CI uses Rust tests/acceptance and pinned actions/read-only
default permissions. Release automation stops at a verified draft.
Publication/visibility are separate operator decisions; no successful test or
tag implies permission to activate.

## Setup

[Key command orchestration](../src/cli/keys.rs) owns argument parsing, public-input
loading, prompts and sender participation. Credential storage and wrapping remain
in [credentials](../src/credentials/keys.rs); read explicit public input once before
private-key stdin is consumed.

The visible surface is git send [--quiet] [--local-only]
[--force-with-lease|--force] [--branch name] [user@host], git receive [--branch
name] [user@host], git porter setup [--yes], key:create
[sender-key-or-public-wrapping-token] [--key-import path|-], key:create
[sender-public-key-or-path] --sign, key:create --sign user@host, and key:public.
The SSH entry is internal:serve; pre-receive and transport/ssh are compiled
links. Only documented user commands are visible.

[Setup](../src/cli/setup.rs) installs SSH glue: the forced-command entry,
compiled pre-receive/transport links and restricted authorized_keys line.
Replace stale role symlinks atomically when their target is named git-porter,
including removed older installations; preserve and refuse unrelated hooks or
plain files. Receiver policy is supplied separately by Home Manager or hand.
Never write main Git or porter policy configuration from setup. Show
configuration, key presence and host trust checks, warn about missing policy,
ask before applying; --yes skips the question. Planning tolerates an absent data
directory without creating it. After confirmation, create the account-owned data
directory with mode 0700 and its managed hook/transport directories on demand,
then revalidate resolved paths. Declining exits nonzero and leaves the
directories absent. SSH fails on missing required policy. Missing forwarder keys
in wrapped mode offer paste/wait/skip after installing SSH glue. Paste accepts
the sender's public wrapping token, with no receiver SSH prerequisite. Wait uses
the recorded source, or prints/selects the sole authorizedKey when no source is
recorded, otherwise prompts. It runs the existing approved live creation flow;
--sign user@host requires the restricted entry to be installed. The owner may
skip and choose another source through key:create. Paste and wait both enforce create-only enrollment. Setup creates only a missing
key, checking wrapped/public destinations under the provisioning lock; it never
replaces an existing forwarder key. A pre-existing source public file is
allowed. --yes remains glue-only/non-interactive: print only a short
key-creation reminder, not interactive paste/wait instructions. skipWrappedKey
never offers wrapped-key creation. With skipWrappedKey=true, skip bundle checks
and warn that any process on the receiver/forwarder account can push using its
SSH agent. Setup warnings retain exit 0. key:create reports that no wrapping is
needed without reading import files; key:public lists account-agent identities
and requires that agent, not a bundle. Setup attempts ~/.ssh/authorized_keys.
Its printed restricted entries may instead be installed through any
authorization source the owner configures SSH to read, including a separate
file. There is no porter authorization-path setting. Do not assume the standard
file is the only authorization source, edit sshd configuration, scan or migrate
other authorization files, or dictate a separate-file layout. Read-only managed
files print the exact entry and attempted file for their owner to configure,
without failing or replacing a link. Preserve unrelated entries and remove
marked porter entries whose key left porter.authorizedKey, so removing a key
revokes its restricted access there. Check duplicates only in the attempted
file; this cannot establish restrictions on other SSH authorization sources.
Index existing entries by exact key data for duplicate checks instead of
reparsing for each configured key; markers alone never establish key identity.

## Publication host trust

[Built-in trust](../src/server/host_trust.rs) includes provider public Ed25519
keys for well-known forges. Otherwise use the receiver account's
~/.ssh/known_hosts; Establish new hosts through normal Git/SSH use. Setup does
not keyscan, prompt for required trust files or manage trust data. Native
OpenSSH strictly checks the origin before authentication/receipt, with the
built-in keys as global trust and account file as user trust.

## Managed receivers

[Home Manager](../nix/home-manager.nix) installs binaries, Git/OpenSSH and
optional receiver policy in programs.git.settings.porter and compiled links.
Group optional outgoing defaults under sender (sender.destination) and all
receiver-only policy under receiver: authorizedKeys,
allowedPushPrefixes, searchStrict, publishTo, allowDefaultBranch and
skipWrappedKey. Keep searchRoot explicitly shared, because one Git setting
supplies local sender hints and receiver discovery roots. These are Nix option
groups only; generated porter.* Git settings remain flat and unchanged.

Shared searchRoot defaults to the account home and receiver.searchStrict defaults
to false. Strict roots constrain explicit access and metadata as well as discovery;
receiver access never extends outside home. With no receiver.authorizedKeys,
install commands only and reject receiver-only policy. A nonempty
receiver.authorizedKeys enables SSH setup.
These are sender Ed25519 access public keys, not the receiver's forwarder key;
select the unlocking source separately during enrollment. Root options accept
home-relative or absolute paths. Shared searchRoot and sender.destination never
enable receiver activation. An account may use both roles. Authorized keys,
write prefixes and forge destinations define receiver policy; sender defaults
never become prerequisites. receiver.publishTo is an optional forge hostname
allowlist; unset allows any origin. receiver.allowDefaultBranch and dangerous
opt-in receiver.skipWrappedKey default to false. Private key/bundle paths are
runtime-only and outside the Nix store. Never read secrets at evaluation/build
time, import agenix files automatically or restore an older active bundle.

Activation calls setup --yes for SSH glue only, passing HOME and XDG config,
data and cache paths. With a custom XDG_CONFIG_HOME, SSH forced-command sessions
rely on the account shell/session environment (for example .zshenv) to export
the same value; porter does not configure sshd or shell startup files.
Automated activation leaves key creation to the owner. It executes no unrelated
profile/account services and never rotates existing complete credentials
automatically. Credentials use XDG data/git-porter; receiver policy uses
programs.git.settings.porter in the global Git configuration; there are no
module path overrides or external bundles. Installation assumes no predecessor
authorization system. Do not add legacy-route migration, cleanup, backup or
activation dependencies. Preserve unrelated existing SSH entries and update only
porter-owned entries; external SSH authorization management remains the account
owner's responsibility.

## Qualification

Run locked Rust workspace tests (unit logic plus focused porter-boundary tests),
formatting/clippy, Python LLP fixtures/checker, Nix builds, explicit OpenSSH and
Home Manager acceptance, and extracted-package install checks. CI runs workspace
tests once per advertised platform through the Nix package check phase, not again
in the quality job. Run OpenSSH and extracted-package checks on each platform;
run generated Home Manager integration once on x86_64 Linux. Per-platform
OpenSSH acceptance covers runtime portability. Use synthetic credentials,
isolated homes and fixture daemons.
Exercise default publication, local-only send, receive, remote/inline key
creation, missing/malformed metadata, domain separation,
rewrite/ref/worktree/lease protection, prompt/network timeouts and cancellation.
Report native vs emulated and actual vs unrun checks accurately. Real-account
acceptance, activation, source deletion and public release retain separate
gates.

## Terminal output

[Terminal presentation](../src/cli/terminal.rs) follows terminal-palette labels:
bold headings/prompts, green success, yellow warnings, red failures. All meaning
remains in the text. Style generated stderr labels only when stderr is a
terminal. Any nonempty NO_COLOR, TERM=dumb/unknown, CI=1/true, or zero-valued
CLICOLOR, COLOR or FORCE_COLOR disables styling. Comparisons are ASCII
case-insensitive except NO_COLOR's nonemptiness. Force settings never override
disable controls or style a pipe. No animations, cursor control, terminal
queries or new color flags. Keep public keys, wrapping tokens, help/version and
protocol/native Git payloads plain. Setup plans, warnings, instructions and
completion notices use stderr; stdout contains only returned key/token payloads
(or requested help/version). Push output keeps receiver/forwarded ordering and
Git ref-status semantics; color only its generated headings and status
summaries, preserving refs/URLs/reasons.

Human guidance uses short, calm sentences and the sender and receiver/forwarder
roles. Explain what each key does: the forwarder key authenticates forge pushes;
the sender key unlocks it. Use normal case for public/private key descriptions,
full copyable command names in intentional setup/enrollment instructions, and
factual failure descriptions in errors. Do not infer that the sender should
create keys, load an agent or change receiver policy. Errors do not disclose
configuration option names or suggest overrides. Keep low-level validation errors
precise, without disguising a refusal as success. Confirm key storage only after it succeeds and keep registration
instructions on stderr. Preserve the original branch-prefix rename instruction
and Git-style status wording. Help explains options and the paste/SSH approval
choices; terminal styling and prose never alter public payloads or protocol bytes.

Prompts have explicit defaults and always terminate/flush their stderr line on
success, EOF or error; never rely on terminal echo. Bound confirmation lines to
64 bytes and public-key/token input to 4096 bytes. Accept y/yes and n/no
ignoring case; blank/EOF declines mandatory consent and skips optional
enrollment. Retry other confirmation words. Preserve explicit piped setup
responses; TTY detection controls presentation, not consent. --yes stays
non-interactive. Never consume piped private-key import as a source-key prompt:
require explicit public input when --key-import - owns stdin. Do not add
echo-suppression machinery for public tokens or read native Git/SSH protocol
stdin as interactive input.
