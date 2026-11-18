{
  flake,
  home,
  username,
  publicKey,
}:
let
  pkgs = flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
  data = "${home}/.local/share/git-porter";
  cfg =
    (flake.inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        flake.homeManagerModules.default
        {
          home.username = username;
          home.homeDirectory = home;
          home.stateVersion = "26.05";
          xdg.configHome = "${home}/custom-config";
          programs.git-porter = {
            enable = true;
            searchRoot = [ "projects" ];
            receiver = {
              # Default access and discovery stay within the account home.
              searchStrict = true;
              authorizedKeys = [ publicKey ];
              allowedPushPrefixes = [ "contributors/" ];
              publishTo = [ "127.0.0.1" ];
            };
          };
        }
      ];
    }).config;
in
{
  package = toString cfg.programs.git-porter.package;
  activation = cfg.home.activation.gitPorter.data;
  files =
    pkgs.lib.mapAttrsToList
      (_: file: {
        target = "${home}/${file.target}";
        inherit (file) text;
        source = if file.text == null then toString file.source else null;
      })
      (
        pkgs.lib.filterAttrs (
          name: _:
          pkgs.lib.hasPrefix "${data}/" name
          || name == "${home}/.gitconfig"
          || name == "${home}/custom-config/git/config"
        ) cfg.home.file
      );
}
