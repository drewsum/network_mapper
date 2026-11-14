#!/usr/bin/env bash
# Build netmap:local on the server from a git ref, without a checkout there.
# Streams `git archive` over SSH into `docker build`. Usage: scripts/build-on-host.sh [ref]
# Needs an SSH host alias (default `truenas`, override with NETMAP_SSH_HOST) whose user may
# run `sudo docker`. Committed changes only: uncommitted edits aren't included.
set -euo pipefail
ref="${1:-HEAD}"
host="${NETMAP_SSH_HOST:-truenas}"
cd "$(git rev-parse --show-toplevel)"
echo "building netmap:local from $(git rev-parse --short "$ref") on $host"
git archive --format=tar "$ref" | ssh "$host" 'sudo -n /usr/bin/docker build -t netmap:local -'
