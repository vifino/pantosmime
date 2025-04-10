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
    flake-utils.lib.eachSystem ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
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

        checks = {
          #loop = import ./tests/loop.nix checkArgs;
          #tcp = import ./tests/tcp.nix checkArgs;
          #tcp-ipv6 = import ./tests/tcp-ipv6.nix checkArgs;
          #rdma = import ./tests/rdma.nix checkArgs;
        };

        formatter = pkgs.alejandra;
      }
    );
}
