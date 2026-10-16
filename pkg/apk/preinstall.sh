#!/bin/sh
# Creates the dedicated, unprivileged system user/group the server runs as
# (see cosmian_kms.initd's command_user). Must run as a *preinstall* script,
# not postinstall: apk-tools resolves the "kms" owner/group named in this
# package's file_info against /etc/passwd at file-extraction time, silently
# falling back to root:root (no error) if the user does not exist yet — this
# was verified empirically against a fresh Alpine container. Idempotent so
# package upgrades (where the user already exists) do not fail.
addgroup -S kms 2>/dev/null || true
adduser -S -D -H -h /var/lib/cosmian -s /bin/false -G kms kms 2>/dev/null || true
exit 0
