#!/bin/sh
if command -v rc-service >/dev/null 2>&1 && [ -x /etc/init.d/cosmian_kms ]; then
  rc-service cosmian_kms stop >/dev/null 2>&1 || true
fi
exit 0
