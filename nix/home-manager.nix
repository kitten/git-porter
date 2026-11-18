# @ref LLP 0004#managed-receivers
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.programs.git-porter;
  receiver = cfg.receiver;
  receiverEnabled = receiver.authorizedKeys != [ ];
  senderSettings =
    lib.optionalAttrs (cfg.sender.destination != null) { destination = cfg.sender.destination; }
    // lib.optionalAttrs (cfg.searchRoot != [ ]) { searchRoot = cfg.searchRoot; };
  hasSenderSettings = senderSettings != { };
  rootPath = types.addCheck types.str (s: s != "" && !(lib.hasInfix "\n" s));
  data = "${config.xdg.dataHome}/git-porter";
  receiverSettings = {
    allowedPushPrefix = receiver.allowedPushPrefixes;
    authorizedKey = receiver.authorizedKeys;
    searchRoot = cfg.searchRoot;
    searchStrict = receiver.searchStrict;
    publishTo = receiver.publishTo;
    allowDefaultBranch = receiver.allowDefaultBranch;
    skipWrappedKey = receiver.skipWrappedKey;
  };
  escape = lib.escapeShellArg;
  porter = "${cfg.package}/bin/git-porter";

in
{
  options.programs.git-porter = {
    enable = mkEnableOption "git send, git receive and git porter, with optional restricted receiver setup";
    package = mkOption {
      type = types.package;
      default = pkgs.git-porter;
      description = "Package containing the three installed binaries.";
    };
    sender.destination = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Optional default receiver for this account's git send and git receive
        commands. An explicit command-line destination takes precedence.
        This does not enable a receiver or select a sender signing key.
      '';
    };
    searchRoot = mkOption {
      type = types.listOf rootPath;
      default = [ config.home.homeDirectory ];
      description = ''
        Shared local repository directories, absolute or relative to this account's
        home. As a sender, the first containing root supplies a checkout-relative
        discovery hint; absolute sender paths are never sent. As a receiver,
        these directories guide discovery and, with searchStrict, bound all access,
        including explicit paths and Git metadata. Receiver roots must stay within
        home; omitted roots default to home. Strict receivers ignore sender hints.
      '';
    };
    receiver = {
      authorizedKeys = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Sender Ed25519 public keys allowed restricted SSH access to this account,
          without authorized_keys options. A nonempty list enables receiver setup.
          These are access keys, not the receiver's forwarder key for forge pushes.
          The key used to unlock that forwarder key is enrolled separately.

          Activation installs SSH glue with setup --yes. It does not create or
          import a forwarder key, wait for sender approval, or read agenix secrets.
          Missing forwarder keys leave onward publishing unavailable but do not
          block Home Manager activation. Enroll them separately with key:create.
        '';
      };
      allowedPushPrefixes = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Literal branch-directory prefixes writable on this receiver.
          Empty makes receiver access read-only; it does not restrict branches
          this account sends to another receiver.
        '';
      };
      searchStrict = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Confine discovery and all repository/metadata access, including explicit
          paths, to searchRoot (home when none are set). Access never extends outside
          home. False searches and permits access throughout home.
        '';
      };
      publishTo = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Optional forge hostname allowlist for this receiver's onward pushes to
          repository origins. Empty permits any origin host. These are forge
          hosts, not destinations for outgoing git send or git receive commands.
        '';
      };
      allowDefaultBranch = mkOption {
        type = types.bool;
        default = false;
        description = "Allow this receiver to publish to origin's live default branch; protected by default.";
      };
      skipWrappedKey = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Dangerous opt-in: onward pushes use this receiver account's SSH agent
          instead of a wrapped forwarder key and sender approval. Any process on
          the account can use those forge credentials. This does not select or
          modify the agent used for outgoing sender connections.
        '';
      };
    };

  };
  config = mkIf cfg.enable (
    lib.mkMerge [
      {
        home.packages = [
          cfg.package
          pkgs.git
          pkgs.openssh
        ];
        assertions = [
          {
            assertion =
              receiver.authorizedKeys != [ ]
              || (
                receiver.authorizedKeys == [ ]
                && !receiver.searchStrict
                && receiver.allowedPushPrefixes == [ ]
                && receiver.publishTo == [ ]
                && !receiver.allowDefaultBranch
                && !receiver.skipWrappedKey
              );
            message = "git-porter receiver settings require at least one authorized sender public key.";
          }

        ];
        programs.git.settings.porter = lib.optionalAttrs receiverEnabled receiverSettings // senderSettings;
      }
      (mkIf (hasSenderSettings || receiverEnabled) { programs.git.enable = lib.mkDefault true; })
      (mkIf receiverEnabled {
        home.file."${data}/hooks/pre-receive".source = "${cfg.package}/bin/git-porter";
        home.file."${data}/transport/ssh".source = "${cfg.package}/bin/git-porter";
        home.activation.gitPorter = lib.hm.dag.entryAfter [ "linkGeneration" ] ''
          export PATH=${
            lib.makeBinPath [
              pkgs.git
              pkgs.openssh
            ]
          }:$PATH
          run ${pkgs.coreutils}/bin/install -d -m 700 ${escape data} ${escape "${data}/hooks"} ${escape "${data}/transport"}
          export HOME=${escape config.home.homeDirectory}
          export XDG_CONFIG_HOME=${escape config.xdg.configHome}
          export XDG_DATA_HOME=${escape config.xdg.dataHome}
          export XDG_CACHE_HOME=${escape config.xdg.cacheHome}
          run ${porter} setup --yes
        '';
      })

    ]
  );
}
