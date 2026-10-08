# Reproducible recording script for the README demo GIF (task T3-01/D-013).
#
# Run it from a host that has the lab at hand, with the lab directory mounted at
# /data (the paths below are relative to the lab root). On an SELinux-enforcing
# host the :Z label and --userns=keep-id are what make the mount writable by the
# container under rootless podman:
#
#   podman run --rm --userns=keep-id \
#     -v "$HOME/nhi-reach-lab":/data:Z \
#     -w /data \
#     ghcr.io/charmbracelet/vhs:latest /data/demo.tape
#
# The recording is deterministic: the snapshot under out/ was captured from the
# nhi-reach-lab cluster and the analysis output is byte-stable, so re-running the
# tape reproduces the same GIF. The width is sized so the report table (about
# 190 columns) never wraps.
Output demo.gif

Set FontSize 14
Set Width 2900
Set Height 700
Set Padding 30
Set Shell bash
Set CursorBlink false

Sleep 600ms
Type "bin/nhi-reach analyze --from out/snapshot -o table --target cluster-admin --from-identity lab-app/deployer --max-depth 2 --paths-per-pair 8" Enter
Sleep 5s
