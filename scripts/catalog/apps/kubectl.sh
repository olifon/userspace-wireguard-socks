#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# kubectl against a real Kubernetes API server through the wrapper.
# Full lifecycle: wrapped kubectl launches a fresh pod, waits for
# Ready, exec's into it, reads logs, deletes it. Every kubectl call
# transits the WG tunnel via uwgsocks.
#
# Flows the existing catalog can't test, exercised here:
#   - `kubectl run` / `apply` — POST to the API.
#   - `kubectl get pods` — vanilla HTTPS GET.
#   - `kubectl wait --for=condition=Ready` — HTTP/2 long-poll.
#   - `kubectl exec <pod> -- ...` — WEBSOCKET UPGRADE on a 200 OK.
#     New signal vs every other HTTPS client in the catalog: the
#     wrapper has to keep the proxied fd alive across the protocol
#     switch and tunnel bidirectional binary frames through.
#   - `kubectl logs` — streaming HTTPS GET.
#   - `kubectl delete` — DELETE verb, cleanup.
#
# Topology:
#   - Cluster: kubernetes API on `<wg-ip>:16443` (microk8s by default).
#   - Client: this host wraps kubectl; kubeconfig at /root/.kube/config
#     must already point at the cluster's WG addr.
#   - Insecure-skip-tls in the kubeconfig because microk8s's apiserver
#     cert CN is the internal cluster IP (10.152.183.1), not the WG
#     addr we dial.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="kubectl"
if ! bin_exists kubectl; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 \
    "install: curl -L 'https://dl.k8s.io/release/v1.34.1/bin/linux/\$(arch)/kubectl' -o /usr/local/bin/kubectl"
  exit 0
fi
if [[ ! -f /root/.kube/config ]]; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" no-kubeconfig 0 \
    "/root/.kube/config missing — copy a kubeconfig from your cluster and rewrite the server URL to its WG addr (e.g. https://10.200.0.3:16443). Add insecure-skip-tls-verify: true if the API server cert was issued for an internal cluster IP."
  exit 0
fi

work=$(mktemp -d)
POD="uwg-catalog-$$-$RANDOM"
WRAP() { "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto "$@"; }
cleanup() {
  # delete via wrapper so the cleanup goes through the same network
  # path as the rest of the test
  WRAP -- kubectl delete pod "$POD" --grace-period=1 --now 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

err="$work/wrapper.err"
start=$(date +%s.%N)

# 1. GET — basic API reachability
nodes_out=$(WRAP -- kubectl get nodes -o name 2>"$err") || true

# 2. POST — launch a fresh pod through the wrapper
launch_out=$(WRAP -- kubectl run "$POD" --image=busybox --restart=Never --command -- \
    sh -c 'echo "kubectl-wrapped-launch-$(hostname)"; sleep 120' 2>>"$err") || true

# 3. wait — HTTP/2 long-poll until pod reports Ready
wait_out=$(timeout 60 "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
    kubectl wait pod "$POD" --for=condition=Ready --timeout=50s 2>>"$err") || true

# 4. exec — WEBSOCKET UPGRADE, the load-bearing new signal
exec_out=$(timeout 15 "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
    kubectl exec "$POD" -- sh -c 'echo "kubectl-wrapped-exec-ok"; uname -m' 2>>"$err") || true

# 5. logs — streaming HTTPS GET
logs_out=$(timeout 10 "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
    kubectl logs "$POD" --tail=10 2>>"$err") || true

# 6. watch — HTTP/2 long-poll, bounded by short timeout (= success)
watch_lines=$(timeout 4 "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
    kubectl get pods --watch 2>>"$err" | wc -l) || true

end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' "$err"; then
  transport=$(grep 'auto: chose ' "$err" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

# Pass requires the full lifecycle: at minimum, a fresh launch + a
# successful exec (which is the websocket-upgrade leg) + logs showing
# our launch marker. The wait/watch are bonuses that confirm long-poll
# semantics survived but aren't load-bearing for the pass criterion.
wrapped_ok=false
if [[ "$nodes_out" == node/* \
   && "$launch_out" == *"pod/$POD created"* \
   && "$exec_out" == *"kubectl-wrapped-exec-ok"* \
   && "$logs_out" == *"kubectl-wrapped-launch-"* ]]; then
  wrapped_ok=true
fi

notes="pod=$POD nodes=$(echo $nodes_out | head -c 80) launch=$(echo $launch_out | head -c 50) exec=$(printf '%s' "$exec_out" | tr '\n' '|' | head -c 80) wait=$(echo $wait_out | head -c 60) watch-lines=$watch_lines | err-tail: $(tail -c 200 $err 2>/dev/null | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
