#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
# vast.ai GPU AutoML smoke: PyTorch + MNIST single-epoch train on CUDA.
# Demonstrates that the wrapper survives PyTorch's enormous Python/C++/CUDA
# import graph and that dataset download routes through the tunnel.
set -u
cd "$(dirname "$0")/.."
. ./lib.sh

app="pytorch-mnist"

# Only run where a CUDA GPU is plausibly available — vast.ai. We treat the
# script as a wrapper survival test elsewhere (no CUDA), and skip when no
# GPU AND no torch installed.
need_gpu=true
if ! bin_exists nvidia-smi; then need_gpu=false; fi

if ! command -v python3 >/dev/null; then
  record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" missing-bin 0 "python3 missing"
  exit 0
fi

# Make sure torch is installed (idempotent). On vast.ai we expect torch
# already; elsewhere skip the heavy install.
torch_ok=false
if python3 -c 'import torch' 2>/dev/null; then
  torch_ok=true
fi

if [[ "$torch_ok" == "false" ]]; then
  if [[ "$need_gpu" == "true" ]]; then
    log "torch not present; trying pip install via wrapper..."
    "$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -- \
      python3 -m pip install --quiet --disable-pip-version-check torch torchvision 2>&1 | tail -10 || true
    python3 -c 'import torch' 2>/dev/null && torch_ok=true
  else
    record_result "$app" false "${UNWRAPPED_BLOCKED:-true}" "no-cuda" 0 "no NVIDIA GPU detected and no torch installed; skipping heavyweight install on this host"
    exit 0
  fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat >"$work/mnist_smoke.py" <<'PY'
import os, time, sys
os.environ.setdefault("UWGS_FORCE_LOOPBACK_DNS", "1")
t0=time.time()
import torch
from torch import nn, optim
from torch.utils.data import DataLoader
from torchvision import datasets, transforms
dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"device={dev} torch={torch.__version__}", flush=True)
tfm = transforms.Compose([transforms.ToTensor(), transforms.Normalize((0.1307,),(0.3081,))])
ds = datasets.MNIST(root=os.environ.get("DATA_ROOT","/tmp/mnist"), train=True, download=True, transform=tfm)
dl = DataLoader(ds, batch_size=512, shuffle=True, num_workers=0)
class Net(nn.Module):
    def __init__(self):
        super().__init__()
        self.c1=nn.Conv2d(1,32,3,1); self.c2=nn.Conv2d(32,64,3,1)
        self.d1=nn.Dropout(0.25); self.fc1=nn.Linear(9216,128); self.fc2=nn.Linear(128,10)
    def forward(self,x):
        x=torch.relu(self.c1(x)); x=torch.relu(self.c2(x))
        x=torch.max_pool2d(x,2); x=self.d1(x); x=torch.flatten(x,1)
        x=torch.relu(self.fc1(x)); return self.fc2(x)
m = Net().to(dev); opt = optim.Adam(m.parameters(), lr=1e-3); lo = nn.CrossEntropyLoss()
steps = 0
for x,y in dl:
    x=x.to(dev); y=y.to(dev)
    opt.zero_grad(); o=m(x); l=lo(o,y); l.backward(); opt.step()
    steps += 1
    if steps == 5: break
print(f"trained_steps={steps} elapsed={time.time()-t0:.1f}s loss={float(l):.3f}", flush=True)
PY

export DATA_ROOT="$work/mnist"
start=$(date +%s.%N)
out=$("$UWGWRAPPER_BIN" --api="$UWGSOCKS_API" --transport=auto -v -- \
    python3 "$work/mnist_smoke.py" 2>&1) || true
end=$(date +%s.%N)
dur=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e-s}')

transport=""
if grep -q 'auto: chose ' <<<"$out"; then
  transport=$(grep 'auto: chose ' <<<"$out" | head -1 | sed -E 's/.*auto: chose ([a-z-]+).*/\1/')
fi

wrapped_ok=false
[[ "$out" == *"trained_steps=5"* ]] && wrapped_ok=true

notes="out-tail: $(printf '%s' "$out" | tail -c 800 | tr '\n' '|')"
record_result "$app" "$wrapped_ok" "${UNWRAPPED_BLOCKED:-true}" "$transport" "$dur" "$notes"
[[ "$wrapped_ok" == "true" ]]
