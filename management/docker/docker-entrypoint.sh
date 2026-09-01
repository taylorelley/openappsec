#!/bin/sh
# Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The manager writes into two volumes it shares with containers that run as
# root: the agent's config volume (the rendered local_policy.yaml) and the
# smartsync shared storage (decisions.data). Docker creates bind-mount targets
# owned by root, so an image that runs unprivileged from PID 1 cannot write to
# either — and both failures are only warnings in the server, which means the
# stack comes up looking healthy while policy never reaches the agent.
#
# So: start as root, take ownership of just those two locations, then drop to
# an unprivileged user for the server itself. A container that is already
# started unprivileged (compose `user:`, Kubernetes `runAsUser`) skips all of
# this and execs straight through, so nothing is imposed on deployments that
# manage volume ownership themselves.

set -eu

if [ "$(id -u)" -ne 0 ]; then
    exec "$@"
fi

if [ "${MANAGER_FIX_VOLUME_OWNERSHIP:-true}" = "false" ]; then
    exec "$@"
fi

PUID="${PUID:-10001}"
PGID="${PGID:-10001}"

if [ "$PUID" = "0" ]; then
    exec "$@"
fi

# Both paths are configurable and an empty value disables that delivery
# mechanism entirely, so read them the same way the server does rather than
# hard-coding the defaults here.
policy_output="${MANAGER_POLICY_OUTPUT-/ext/appsec/local_policy.yaml}"
policy_dir=""
if [ -n "$policy_output" ]; then
    policy_dir="$(dirname "$policy_output")"
fi
shared_storage="${MANAGER_SHARED_STORAGE_PATH-/db}"

for dir in "$policy_dir" "$shared_storage"; do
    [ -n "$dir" ] || continue

    if ! mkdir -p "$dir" 2>/dev/null; then
        echo "entrypoint: cannot create $dir, leaving it alone" >&2
        continue
    fi

    # Recursive, because a sibling container running as root may already own
    # subdirectories the manager needs to create files inside — most often
    # <tenant>/<asset>/ under the shared storage. Guarded on the root's
    # current owner so this is a one-time cost on first start rather than a
    # full walk of the learning volume on every restart.
    owner="$(stat -c %u "$dir" 2>/dev/null || echo unknown)"
    if [ "$owner" = "$PUID" ]; then
        continue
    fi
    if ! chown -R "$PUID:$PGID" "$dir" 2>/dev/null; then
        echo "entrypoint: cannot chown $dir to $PUID:$PGID, continuing" >&2
    fi
done

exec su-exec "$PUID:$PGID" "$@"
