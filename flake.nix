{
  description = "badrabbit-sec-scan: security gate for CI (secrets, SAST, SCA, IaC, SBOM) + promptfoo LLM red team";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: rec {
        # Every scanner comes from nixpkgs (cache.nixos.org): CI downloads
        # binaries, nothing is compiled on the runner.
        sec-scan = pkgs.writeShellApplication {
          name = "sec-scan";
          runtimeInputs = with pkgs; [
            semgrep gitleaks trivy osv-scanner bandit syft jq git coreutils findutils
          ];
          # Scanner exit codes are handled explicitly; errexit would get in the way.
          bashOptions = [ "nounset" "pipefail" ];
          text = builtins.readFile ./sec-scan.sh;
        };

        # Telemetry and update checks off. Red team attack generation stays
        # remote by default (better attacks); PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
        # keeps everything local.
        promptfoo = pkgs.writeShellScriptBin "promptfoo" ''
          export PROMPTFOO_DISABLE_TELEMETRY="''${PROMPTFOO_DISABLE_TELEMETRY:-1}"
          export PROMPTFOO_DISABLE_UPDATE="''${PROMPTFOO_DISABLE_UPDATE:-1}"
          exec ${pkgs.promptfoo}/bin/promptfoo "$@"
        '';

        # pytest for the project's own security tests in .sec/test: HTTP clients,
        # JWT, YAML and schema checks out of the box, no pip on the runner.
        sec-pytest =
          let
            python = pkgs.python3.withPackages (ps: with ps; [
              pytest pytest-asyncio pytest-timeout
              requests httpx websockets pyjwt cryptography pyyaml jsonschema
            ]);
          in
          pkgs.writeShellScriptBin "sec-pytest" ''exec ${python}/bin/python -m pytest "$@"'';

        default = sec-scan;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ self.packages.${pkgs.stdenv.hostPlatform.system}.sec-scan pkgs.actionlint pkgs.shellcheck ];
        };
      });

      checks = forAll (pkgs: {
        # writeShellApplication already runs shellcheck on sec-scan.sh.
        sec-scan = self.packages.${pkgs.stdenv.hostPlatform.system}.sec-scan;
        workflow = pkgs.runCommand "actionlint" { nativeBuildInputs = [ pkgs.actionlint pkgs.shellcheck ]; } ''
          actionlint ${./badrabbit-sec-scan.yaml}
          touch "$out"
        '';
      });
    };
}
