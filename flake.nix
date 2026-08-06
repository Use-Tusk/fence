{
  description = "Fence development package";

  # These commands require Nix with flakes enabled. Nix uses flake.lock and
  # does not install the development tools globally.
  #
  # Enter the development shell:          nix develop
  # Run the Go tests:                      nix develop -c make test
  # Build Fence:                           nix build
  # Check the current system:              nix flake check
  # Check all systems:                     nix flake check --all-systems
  # Build one Linux integration test:      nix build .#checks.aarch64-linux.bootstrap
  # Use `x86_64-linux` instead when required. Linux checks need a matching
  # local or remote Linux builder.

  # Update nixpkgs with `nix flake update`. Review the flake.lock change and
  # run the tests above before you commit the update.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      linuxSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
      forAllLinuxSystems = nixpkgs.lib.genAttrs linuxSystems;

      pkgsFor = system: import nixpkgs { inherit system; };

      fenceFor =
        system:
        let
          pkgs = pkgsFor system;
          commit = self.shortRev or self.dirtyShortRev or "dirty";
        in
        pkgs.fence.overrideAttrs (
          _finalAttrs: _previousAttrs: {
            version = "dev";
            src = self // {
              rev = commit;
            };

            # Update this hash after a change to go.mod or go.sum:
            # 1. Set vendorHash to pkgs.lib.fakeHash.
            # 2. Run `nix build .#fence`.
            # 3. Copy the reported "got:" hash here.
            vendorHash = "sha256-WjhfAw8wgxvTbTkYwURm9vN2oSvQWiMP2RhwZDCQ0DU=";
          }
        );

      bootstrapTestFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.callPackage ./nix/tests/bootstrap.nix {
          fence = fenceFor system;
        };
    in
    {
      packages = forAllSystems (system: rec {
        fence = fenceFor system;
        default = fence;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                go
                gopls
                gotestsum
                python3
                nodejs
                git
              ]
              ++ lib.optionals stdenv.isLinux [
                bubblewrap
                socat
              ];
          };
        }
      );

      checks = forAllLinuxSystems (system: rec {
        bootstrap = bootstrapTestFor system;
        default = bootstrap;
      });
    };
}
