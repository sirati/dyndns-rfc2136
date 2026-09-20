{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-compat = {
      url = "github:NixOS/flake-compat";
      flake = false;
    };
    self.submodules = true;
  };

  outputs = inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;
      perSystem = { pkgs, ... }:
        let
          package = pkgs.rustPlatform.buildRustPackage {
            pname = "dyndns-rfc2136";
            version = "0.1.0";
            src = pkgs.lib.cleanSource ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = with pkgs; [ cmake perl pkg-config rustfmt ];
            dontUseCmakeConfigure = true;
            doCheck = true;
          };
        in {
          packages.default = package;
          packages.dyndns-rfc2136 = package;
          checks.default = package;
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [ cargo clippy cmake ninja perl pkg-config rust-analyzer rustc rustfmt ];
          };
          formatter = pkgs.nixfmt-tree;
        };
    };
}
