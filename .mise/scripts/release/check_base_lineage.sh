#!/usr/bin/env bash
# Refuse a base commit that is not part of the repository's own history. The caller's base-sha comes from a
# job that executes dependency code, so it is untrusted: GitHub also serves commits that exist only in a fork.
#
# Run in a full-history checkout of BASE_SHA (fetch-depth: 0, so every branch is under refs/remotes/origin).
# Accepts BASE_SHA when it is an ancestor of origin/REF (existing branch) or of origin/DEFAULT_BRANCH.
# Environment: REF, BASE_SHA, DEFAULT_BRANCH (default develop).
set -euo pipefail

: "${REF:?}" "${BASE_SHA:?}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-develop}"
[[ "${BASE_SHA}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "::error::base-sha is not a full commit SHA" >&2
  exit 1
}

for branch in "${REF}" "${DEFAULT_BRANCH}"; do
  if git rev-parse --verify --quiet "refs/remotes/origin/${branch}^{commit}" >/dev/null &&
    git merge-base --is-ancestor "${BASE_SHA}" "refs/remotes/origin/${branch}"; then
    echo "base-sha ${BASE_SHA} is part of origin/${branch}."
    exit 0
  fi
done
echo "::error::base-sha ${BASE_SHA} is not reachable from origin/${REF} or origin/${DEFAULT_BRANCH}" >&2
exit 1
