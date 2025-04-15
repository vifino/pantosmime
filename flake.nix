{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    {
      nixosModules.pantosmime = import ./module.nix;
    }
    // flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
    (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        checkArgs = {
          inherit self pkgs system;
        };
      in {
        packages = rec {
          pantosmime = pkgs.callPackage ./. {};
          pantosmime-static = pkgs.pkgsStatic.callPackage ./. {};
          pantosmime-coverage = pantosmime.overrideAttrs (o: {
            RUSTFLAGS = "-C instrument-coverage";
            dontStrip = true;
          });
          default = pantosmime;
        };
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [pkg-config];
          buildInputs = with pkgs; [
            (rust-bin.stable."1.86.0".default.override {
              extensions = ["llvm-tools-preview"];
            })
            cargo-bloat
            cargo-llvm-cov
            llvmPackages_19.bintools
            openssl
          ];
        };
        formatter = pkgs.alejandra;
      }
    );
}
