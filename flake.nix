{
  description = "Restricted Git-over-SSH access and controlled onward publication";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.home-manager = {
    url = "github:nix-community/home-manager";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      nixpkgs,
      home-manager,
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      each = nixpkgs.lib.genAttrs systems;
      package =
        pkgs:
        import ./nix/package.nix {
          inherit pkgs;
          src = self;
        };
    in
    {
      overlays.default = final: _: { git-porter = package final; };
      homeManagerModules.default =
        {
          lib,
          pkgs,
          ...
        }:
        {
          imports = [ ./nix/home-manager.nix ];
          programs.git-porter.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        };
      packages = each (
        system:
        let
          porter = package nixpkgs.legacyPackages.${system};
        in
        {
          default = porter;
          git-porter = porter;

        }
      );
      apps = each (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/git-porter";
        };
      });
      devShells = each (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
              python3
              git
              openssh
              age
              pkg-config
              bash
              zsh
              fish
              actionlint
              nixfmt
            ];
          };
        }
      );
      checks = each (system: {
        package = self.packages.${system}.default;
        module-policy = import ./tests/e2e/module-policy.nix {
          flake = self;
          pkgs = nixpkgs.legacyPackages.${system};
        };

      });
      formatter = each (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
