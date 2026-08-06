{
  bash,
  coreutils,
  fence,
  gnugrep,
  lib,
  testers,
  writeShellScript,
  writeText,
}:

let
  settings = writeText "fence-multicall-bootstrap.json" ''
    {
      "command": {
        "useDefaults": false,
        "deny": [ "chroot" ]
      }
    }
  '';

  checkSetup = writeShellScript "check-fence-multicall-setup" ''
    set -eu

    export PATH=${
      lib.makeBinPath [
        coreutils
      ]
    }

    # Nixpkgs coreutils uses one multicall binary. This reproduces the case where
    # identifying bootstrap tools by executable identity incorrectly denies all of them.
    chroot_target=$(readlink -f "$(command -v chroot)")
    for utility in mkdir sleep; do
      utility_target=$(readlink -f "$(command -v "$utility")")
      if [ "$utility_target" != "$chroot_target" ]; then
        echo "$utility does not share the chroot executable" >&2
        echo "chroot: $chroot_target" >&2
        echo "$utility: $utility_target" >&2
        exit 1
      fi
    done
  '';

  checkSandboxWorks = writeShellScript "check-fence-sandbox-works" ''
    set -eu

    export HOME=/home/alice
    export PATH=${
      lib.makeBinPath [
        bash
        coreutils
        fence
        gnugrep
      ]
    }
    cd "$HOME"

    set +e
    output=$(
      ${fence}/bin/fence \
        --debug \
        --settings ${settings} \
        -c 'if test -n "''${FENCE_LINUX_BOOTSTRAP_PLAN+x}"; then echo "bootstrap plan leaked into sandbox" >&2; exit 1; fi; printf "%s\n" bootstrap-ok' \
        2>&1
    )
    status=$?
    set -e
    printf '%s\n' "$output"
    if [ "$status" -ne 0 ]; then
      echo "fence exited with status $status" >&2
      exit "$status"
    fi
    printf '%s\n' "$output" | grep -F "Using Go-based Linux bootstrap"
    printf '%s\n' "$output" | grep -Fx "bootstrap-ok"
  '';
in
testers.runNixOSTest {
  name = "fence-multicall-bootstrap";

  # Run Fence unprivileged so root capabilities cannot mask failures in
  # namespace-based sandbox initialization.
  nodes.machine = {
    users.users.alice = {
      isNormalUser = true;
      createHome = true;
    };
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    with subtest("check_setup"):
        machine.succeed("runuser -u alice -- ${checkSetup}")
    with subtest("check_sandbox_works"):
        machine.succeed("runuser -u alice -- ${checkSandboxWorks}")
  '';
}
