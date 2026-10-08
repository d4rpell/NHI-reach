#!/usr/bin/env bash
# Reproducible driver for the nhi-reach lab (task T3-01, D-013).
#
# Runs on the host that owns the cluster (the Oracle VPS, arm64, podman
# rootless). It captures a live snapshot with `nhi-reach snapshot`, analyses it
# offline and live, checks that both analyses are byte-identical, and compares
# the bounded table against expected/lab-table.txt.
#
# It never creates, modifies or deletes anything but the tool's own snapshot
# output under $LAB/out. The cluster is assumed to exist already (see README.md).
set -euo pipefail

LAB="${LAB:-$HOME/nhi-reach-lab}"
KUBECONFIG="${KUBECONFIG:-$LAB/state/kubeconfig}"
OUT="$LAB/out"
BIN="$LAB/bin/nhi-reach"
EXPECTED="${EXPECTED:-$LAB/expected/lab-table.txt}"
export KUBECONFIG

snapshot() {
  rm -rf "$OUT/snapshot"
  "$BIN" snapshot -o "$OUT/snapshot"
}

# The bounded invocation keeps the result independent of the default RBAC that
# kind installs: a single origin, depth 2, both non-node targets. It exercises
# every edge type of the catalog (NR-001..NR-006 plus the direct cluster-admin
# and secret-read edges) and a via_system path through kube-system.
bounded() {
  "$BIN" analyze --from "$OUT/snapshot" -o table \
    --target cluster-admin --target secrets \
    --from-identity lab-app/deployer \
    --max-depth 2 --paths-per-pair 8
}

snapshot
bounded > "$OUT/table.txt"

"$BIN" analyze --from "$OUT/snapshot" -o json > "$OUT/offline.json"
"$BIN" analyze --live -o json > "$OUT/live.json"
if ! cmp -s "$OUT/offline.json" "$OUT/live.json"; then
  echo "FAIL: offline and live analyses differ" >&2
  exit 1
fi
echo "OK: offline analysis == live analysis"

if [ -f "$EXPECTED" ]; then
  if cmp -s "$OUT/table.txt" "$EXPECTED"; then
    echo "OK: bounded table matches $EXPECTED"
  else
    echo "FAIL: bounded table differs from $EXPECTED" >&2
    diff "$EXPECTED" "$OUT/table.txt" || true
    exit 1
  fi
fi
