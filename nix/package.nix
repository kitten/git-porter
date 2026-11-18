{
  pkgs,
  src,
}:
let
  native = pkgs;
  buildPkgs = if pkgs.stdenv.hostPlatform.isLinux then pkgs.pkgsStatic else pkgs;
  metadata = builtins.fromTOML (builtins.readFile (src + /Cargo.toml));
in
buildPkgs.rustPlatform.buildRustPackage {
  pname = "git-porter";
  version = metadata.package.version;
  inherit src;
  cargoLock.lockFile = src + /Cargo.lock;
  nativeCheckInputs = [
    native.git
    native.openssh
  ];
  postInstall = ''
    mkdir -p "$out/share/doc/git-porter"
    cp README.md LICENSE "$out/share/doc/git-porter/"
  '';
  preBuild = ''
    export LIBGIT2_NO_VENDOR=0
    export CFLAGS="''${CFLAGS:+$CFLAGS }-ffile-prefix-map=$NIX_BUILD_TOP=/build -ffile-prefix-map=/nix/store=/build/store"
    export RUSTFLAGS="''${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$NIX_BUILD_TOP=/build --remap-path-prefix=/nix/store=/build/store"
  '';
  postFixup = ''
    for binary in "$out"/bin/*; do
  ''
  + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
    install_name_tool -change ${pkgs.libiconv}/lib/libiconv.2.dylib /usr/lib/libiconv.2.dylib "$binary"
    if otool -L "$binary" | tail -n +2 | grep /nix/store; then
      echo "release executable retains a Nix dynamic dependency" >&2; exit 1
    fi
    if strings "$binary" | grep -E '/nix/store/[a-z0-9]{32}-|/nix/var/nix/'; then
      echo "release executable retains a Nix path" >&2; exit 1
    fi
  ''
  + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
    if ${native.binutils}/bin/readelf -l "$binary" | grep 'Requesting program interpreter'; then
      echo "release executable requires a dynamic loader" >&2; exit 1
    fi
    if ${native.binutils}/bin/strings "$binary" | grep -E '/nix/store/[a-z0-9]{32}-|/nix/var/nix/'; then
      echo "release executable retains a Nix path" >&2; exit 1
    fi
  ''
  + ''
    done
  '';
  meta = {
    description = "Restricted Git-over-SSH access and controlled onward publication";
    platforms = [
      "aarch64-darwin"
      "x86_64-linux"
      "aarch64-linux"
    ];
    license = pkgs.lib.licenses.mit;
    mainProgram = "git-porter";
  };
}
