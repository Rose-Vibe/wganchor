#!/usr/bin/env bash
# Fill in the four values below, then run:  bash scripts/setup-env.sh
# It writes ../.env (mode 0600) and verifies the VPS is reachable.

VPS_HOST=""       # public IP of the VPS, e.g. 203.0.113.7
VPS_USER=""       # ssh username, e.g. root
VPS_PASSWORD=""   # ssh password
VPS_SSH_PORT="22" # leave as 22 unless you changed it

# ---------------------------------------------------------------- no edits below
set -euo pipefail
cd "$(dirname "$0")/.."

for v in VPS_HOST VPS_USER VPS_PASSWORD; do
  [ -n "${!v}" ] || { echo "error: $v is empty — fill it in at the top of $0" >&2; exit 1; }
done

if [ -e .env ]; then
  cp -p .env ".env.bak.$(date +%Y%m%d-%H%M%S)"
  echo "existing .env backed up"
fi

umask 077
cat > .env <<EOF
# VPS relay host — written by scripts/setup-env.sh. Never commit this file.
VPS_HOST=$VPS_HOST
VPS_USER=$VPS_USER
VPS_PASSWORD=$VPS_PASSWORD
VPS_SSH_PORT=$VPS_SSH_PORT
EOF
chmod 600 .env
echo "wrote .env (0600)"

if command -v sshpass >/dev/null && command -v ssh >/dev/null; then
  echo -n "checking ssh... "
  if SSHPASS="$VPS_PASSWORD" sshpass -e ssh \
      -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=10 \
      -p "$VPS_SSH_PORT" "$VPS_USER@$VPS_HOST" \
      'echo ok: $(hostname) $(uname -sr)' 2>&1; then
    :
  else
    echo "ssh check failed — .env is still written; re-check host/user/password" >&2
  fi
else
  echo "sshpass/ssh not found — skipping connectivity check"
fi
