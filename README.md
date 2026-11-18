**git-porter** sends a Git branch over SSH to a receiver repository, which can then forward it to its `origin`.

```sh
git send user@receiver
```

Running an agent on a dedicated machine with a dedicated account is a popular and sensible option to limit its blast radius. But giving this agent unrestricted push access to your repositories defeats that purpose. So you give it its own SSH key and its own GitHub account. Now, it's isolated with its own identity. But how will you get your diff out of there now?

git-porter lets a sender `git send` branches to, and `git receive` them from, an account or machine that does have access. It restricts the changes it accepts, and forwards them to your checkout's `origin`.

So working across machines keeps the usual Git workflow, and an agent can call these different commands to hand off work to you or update a PR's branch, without needing access to your SSH identity or account.

- **Split knowledge.** The forwarder key for your Git forge is encrypted at rest on the receiver. The receiver can only unlock it after the sender signs an unlock request, so neither side can use it alone. (Your main key can stay pinentry-protected.)
- **Automatically matches checkouts.** The receiver matches repositories by their remotes, so you don't have to keep paths in sync between machines. (Any messy `~/Development` folder works.)
- **Receiver-side policy.** The receiver chooses which sender keys may connect, which directories they can reach, which branch prefixes they can write, and which forge hosts it may push to.
- **Fast-forward by default.** History rewrites need `--force-with-lease` or `--force`, and `git receive` only ever fast-forwards.
- **Plain SSH and Git.** git-porter uses your normal SSH command and a restricted entry in `~/.ssh/authorized_keys`. It doesn't change your SSH server.

[Skip to receiver setup](#set-up-a-receiver)

## Sending and receiving

To send the current branch from a sender to the receiver, which also forwards it to origin, use `git send`:

```sh
git send user@localhost
```

A receiver could be on another account or any other machine that has `git-porter` set up on SSH.

Other forms:

```sh
git send --local-only user@localhost # Skip forwarding to origin
git send --branch @agent/a-fix user@localhost  # Send another branch
git send --force-with-lease user@localhost # Send a history rewrite
git receive user@receiver # Fetch the receiver's branch and fast-forward yours
```

If you always send to the same receiver, save it as the default:

```sh
git config --global porter.destination user@localhost
git send
```

### Rewriting history

`--force-with-lease` and `--force` work like they do with `git push`. When the send is forwarded, `--force-with-lease` also checks that origin is still at the last known commit. With `--local-only`, nothing is forwarded, so only the receiver's tip is checked. Sending to an explicit path still forwards and still checks origin. `--force` skips both checks.

`git receive` always fast-forwards, so your agent does not blindly accept a rewritten commit history. If the fetched branch can't be applied that way, its history stays in `FETCH_HEAD` to inspect.

### Finding the checkout

The sender’s and receiver’s checkouts don’t have to both be in the same spot. The receiver will search for a repository with an `origin` matching one of the sender’s remotes. A strict receiver may have additional restrictions on this.

If discovery can't pick a single checkout, the receiver-side path can be passed manually:

```sh
git send user@localhost:git/org/repo
```

### What a send reports

A forwarded send reports the receiver update and the origin update separately:

```text
To user@localhost:/home/user/git/org/repo
   1111111..2222222 @agent/a-fix -> @agent/a-fix
Forwarded to git@github.com:org/repo.git
   1111111..2222222 @agent/a-fix -> @agent/a-fix
```

If the origin rejects the push, the receiver's update is rejected too. If a push fails at a point where it may still have reached origin, git-porter rechecks the origin when possible. It reports one of these results, or a refusal when it never pushed:

```text
 = [published] @agent/a-fix -> @agent/a-fix (intended commit confirmed at origin)
 ! [not published] @agent/a-fix -> @agent/a-fix (origin still at expected old tip)
 ! [moved] @agent/a-fix -> @agent/a-fix (inspect before retrying)
 ! [unknown] @agent/a-fix -> @agent/a-fix (may have published)
 ! [not attempted] @agent/a-fix -> @agent/a-fix (default branch protected)
```

## Set up a receiver

Your receiving machine needs an explicit setup that'll set git-porter up as an SSH entry point for `git-send`. While the sender only needs its usual, single SSH identity, the receiver will need:

- The `porter.authorizedKey` option in your Git config to know the sender's authorized public SSH key (and other `porter.*` configs to set up its policies)
- The "forwarder key", which is a private key just for forwarding to your origin remotes (typically your forge, e.g. GitHub), which is encrypted at rest, and unlocked with the sender's key
- An entry in that account's `authorized_keys` SSH file, to direct the sender's key to use the git-porter hook

To get started, on the receiver's account, add the sender's public SSH key and the branch prefixes it may write, then run `git porter setup`:

```sh
git config --global --add porter.authorizedKey 'ssh-ed25519 AAAA... sender'
git config --global --add porter.allowedPushPrefix '@agent/'
git porter setup
```

Use the sender's full Ed25519 public key in place of the example string.

`git porter setup` checks these settings, then adds the `authorized_keys` entry. If that file is managed elsewhere or read-only, it prints the entry for you to add.

Until a forwarder key is set up, nothing can be forwarded to origin. `git send --local-only` and `git receive` already work.

### Add a forwarder key

By default, forwarding branches to origin requires a forwarder key on the receiver. This is a separate SSH key that you can add to your Git forge.

The receiver keeps the forwarder private key encrypted at rest. For each forwarded send, the sender signs an unlock request with its private key. The receiver then unlocks the forwarder key in memory for that one push. The stored copy stays encrypted. Neither private key is sent between machines.

Interactive setup offers to create a missing forwarder key. The simplest way needs no SSH connection between the machines. On the **sender**, run:

```sh
git porter key:create --sign
```

It prints a public wrapping token. Paste it into receiver setup, or pass it directly on the receiver:

```sh
git porter key:create '<public-wrapping-token>'
```

The receiver prints the forwarder public key. Register it with your forge as a key that can push to the repository. You can print it again later with `git porter key:public`. Use a new wrapping token for each forwarder key.

<details>
<summary><strong>Other ways to create the key</strong></summary>

**Approve over SSH.** Choose `wait` in receiver setup, then run `git porter key:create --sign user@receiver` on the sender. This needs the restricted SSH entry to work already.

**Import an existing key.** Add `--key-import <path>` to `git porter key:create` on the receiver to import an unencrypted OpenSSH Ed25519 private key. `--key-import -` reads it from stdin.

Running `key:create` yourself replaces an existing forwarder key. Setup only creates one when it's missing.

</details>

## Configuration

All settings live under `porter` in the account's global Git configuration.

| Setting              | Purpose                                                                                            | Default                            |
| -------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `destination`        | Receiver for `git send` and `git receive` (e.g. `user@receiver`)                                   | None, pass one on the command line |
| `authorizedKey`      | Sender Ed25519 public keys allowed SSH access (repeatable)                                         | None, **required**                 |
| `allowedPushPrefix`  | Branch prefixes the sender may push to                                                             | None, read-only                    |
| `searchRoot`         | Paths the receiver searches for Git repos                                                          | `$HOME`                            |
| `searchStrict`       | Restricts paths the receiver accepts to just the `searchRoot`s                                     | `false`                            |
| `publishTo`          | Hostnames the receiver is allowed to forward to (e.g. `github.com`)                                | Any                                |
| `allowDefaultBranch` | Allows forwarding to origin's default branch                                                       | `false`                            |
| `skipWrappedKey`     | Push with the receiver account's own SSH agent instead of the forwarder key (dangerous, see below) | `false`                            |

## Security model

The receiver enforces its policy on every send:

- Tags, deletions and symbolic branches are refused
- A branch that's checked out in one of the receiver's worktrees is refused
- Origin's default branch is protected unless `allowDefaultBranch` is true
- Branches may only be forwarded when a forwarder key is set up, unless `skipWrappedKey` is true
- Forwarding requires a trusted Ed25519 host key for the forge (GitHub and GitLab keys are built in)

The receiver's account and its SSH server are trusted.

The sender needs no setup beyond `git send` and `git receive`, plus one `git porter key:create --sign` to approve the forwarder key.

`skipWrappedKey` is a dangerous opt-in and isn't recommended. It removes the sender's approval for each push, and any process running as the receiver account can then push with that account's SSH agent.
