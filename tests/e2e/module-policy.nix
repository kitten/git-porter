# @ref LLP 0004#managed-receivers
{ flake, pkgs }:
let
  evaluate =
    settings:
    (flake.inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        flake.homeManagerModules.default
        {
          home.username = "fixture";
          home.homeDirectory = "/home/fixture";
          home.stateVersion = "26.05";
          programs.git-porter = {
            enable = true;
          }
          // settings;
        }
      ];
    }).config;
  valid = settings: (builtins.tryEval (evaluate settings).home.activationPackage.drvPath).success;
  hints = evaluate { searchRoot = [ "git" ]; };
  sender = evaluate {
    sender.destination = "operator@receiver";
    searchRoot = [ "git" ];
  };
  receiverPolicy = {
    authorizedKeys = [ "fixture-sender-public-key" ];
    allowedPushPrefixes = [ "contributors/" ];
    searchStrict = true;
    publishTo = [ "forge.example" ];
    allowDefaultBranch = true;
    skipWrappedKey = true;
  };
  combined = evaluate {
    sender.destination = "operator@receiver";
    searchRoot = [ "git" ];
    receiver = receiverPolicy;
  };
  receiverDefaults = evaluate { receiver.authorizedKeys = receiverPolicy.authorizedKeys; };
in
assert valid { };
assert valid { searchRoot = [ "git" ]; };
assert hints.programs.git.settings.porter.searchRoot == [ "git" ];
assert !(hints.home.activation ? gitPorter);
assert
  sender.programs.git.settings.porter == {
    destination = "operator@receiver";
    searchRoot = [ "git" ];
  };
assert !(sender.home.activation ? gitPorter);
assert valid { receiver = receiverPolicy; };
assert combined.home.activation ? gitPorter;
assert
  combined.programs.git.settings.porter == {
    destination = "operator@receiver";
    allowedPushPrefix = [ "contributors/" ];
    authorizedKey = receiverPolicy.authorizedKeys;
    searchRoot = [ "git" ];
    searchStrict = true;
    publishTo = [ "forge.example" ];
    allowDefaultBranch = true;
    skipWrappedKey = true;
  };
assert receiverDefaults.home.activation ? gitPorter;
assert receiverDefaults.programs.git.settings.porter.searchRoot == [ "/home/fixture" ];
assert receiverDefaults.programs.git.settings.porter.searchStrict == false;
assert builtins.all (settings: !(valid { receiver = settings; })) [
  { searchStrict = true; }
  { allowedPushPrefixes = [ "contributors/" ]; }
  { publishTo = [ "example.org" ]; }
  { allowDefaultBranch = true; }
  { skipWrappedKey = true; }
];
pkgs.runCommand "git-porter-module-policy" { } "touch $out"
