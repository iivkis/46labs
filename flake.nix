{
  description = "Development environment for 46labs network experiments";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forEachSystem = fn:
        nixpkgs.lib.genAttrs systems (system: fn (import nixpkgs { inherit system; }));
    in {
      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            bash
            coreutils
            curl
            gawk
            gnugrep
            gnused
            iproute2
            iputils
            procps
            python3
            tcpdump
            util-linux
          ];
        };
      });
    };
}
