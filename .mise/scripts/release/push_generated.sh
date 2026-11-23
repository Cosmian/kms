#!/usr/bin/env bash
# Publish the commit made by commit_generated.sh to branch REF. The ONLY step that sees PAT_TOKEN.
#
# The token reaches Git through GIT_CONFIG_* environment variables of the network commands below: never a URL,
# argv or a persisted config. No force-push, no delete: a conflicting or non-fast-forward state fails.
#
# Environment: REF, PAT_TOKEN, CHANGED (true|false), GITHUB_REPOSITORY, BASE_SHA,
#              REMOTE_URL (default https://github.com/${GITHUB_REPOSITORY}.git; tests use a local path).
set -euo pipefail
set +x

: "${REF:?}" "${PAT_TOKEN:?}" "${BASE_SHA:?}"
CHANGED="${CHANGED:-false}"
REMOTE_URL="${REMOTE_URL:-https://github.com/${GITHUB_REPOSITORY:?}.git}"
[[ "${REF}" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ && "${REF}" != *..* && "${REF}" != *.lock && "${REF}" != */ ]] || {
  echo "::error::invalid ref '${REF}'" >&2
  exit 1
}

encoded="$(printf 'x-access-token:%s' "${PAT_TOKEN}" | base64 | tr -d '\n')"
echo "::add-mask::${encoded}"
# Scope the header to the remote's scheme://host/ (the form actions/checkout uses); other URLs never match.
scope="$(sed -E 's#^(https?://[^/]+/).*#\1#' <<<"${REMOTE_URL}")"
git_net() {
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="http.${scope}.extraheader" \
    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic ${encoded}" GIT_TERMINAL_PROMPT=0 \
    git -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"
}

status=0
git_net ls-remote --exit-code --heads "${REMOTE_URL}" "refs/heads/${REF}" >/dev/null || status=$?
case "${status}" in
  0)
    if [ "${CHANGED}" != "true" ]; then
      echo "Nothing to publish to ${REF}."
      exit 0
    fi
    git_net fetch --quiet --no-tags "${REMOTE_URL}" "+refs/heads/${REF}:refs/remotes/target/${REF}"
    # --onto BASE_SHA transplants only the generated commit; a plain rebase would also replay every commit of
    # BASE_SHA that the target branch lacks (e.g. develop commits into an existing release branch).
    if ! git -c core.hooksPath=/dev/null -c commit.gpgsign=false rebase --quiet --onto "refs/remotes/target/${REF}" "${BASE_SHA}"; then
      git rebase --abort || true
      echo "::error::generated commit does not apply on top of ${REF}; resolve manually" >&2
      exit 1
    fi
    if [ "$(git rev-parse HEAD)" = "$(git rev-parse "refs/remotes/target/${REF}")" ]; then
      echo "${REF} already carries the generated changes."
      exit 0
    fi
    ;;
  2) echo "Branch ${REF} does not exist yet: creating it from ${BASE_SHA}." ;;
  *)
    echo "::error::cannot query ${REF} on the remote (exit ${status})" >&2
    exit 1
    ;;
esac
git_net push --quiet "${REMOTE_URL}" "HEAD:refs/heads/${REF}"
echo "Pushed ${REF}."
