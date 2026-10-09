#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drive `gnupg-pkcs11-scd --server` over its Assuan protocol.

Exercises the same wire protocol GnuPG's gpg-agent uses against a
smartcard daemon:

  LEARN --force                 -> enumerate certificate/key pairs
  SETDATA <hex> + PKSIGN        -> sign a SHA-256 digest with the card key

Exit status is 0 only if every requested step succeeded. Stdlib only.
"""

import argparse
import hashlib
import subprocess
import sys


class AssuanSession:
    """Minimal line-oriented Assuan client over a subprocess."""

    def __init__(self, argv):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.transcript = []

    def _read_line(self):
        raw = self.proc.stdout.readline()
        if raw == b'':
            raise RuntimeError('gnupg-pkcs11-scd closed its output unexpectedly')
        # Assuan data lines may carry raw bytes; latin-1 maps bytes 1:1.
        line = raw.decode('latin-1').rstrip('\n')
        self.transcript.append(f"< {line}")
        return line

    def _write_line(self, line):
        self.transcript.append(f"> {line}")
        self.proc.stdin.write((line + '\n').encode('latin-1'))
        self.proc.stdin.flush()

    def _collect(self):
        """Read until OK / ERR. Answer INQUIRE NEEDPIN defensively."""
        lines = []
        while True:
            line = self._read_line()
            lines.append(line)
            if line == 'OK' or line.startswith('OK ') or line.startswith('ERR'):
                return lines
            if line.startswith('INQUIRE NEEDPIN'):
                # Not expected with CKF_PROTECTED_AUTHENTICATION_PATH +
                # `provider-<name>-allow-protected-auth`; answered so the
                # script can never hang on a PIN prompt.
                self._write_line('D 0000')
                self._write_line('END')

    def banner(self):
        return self._collect()

    def send(self, command):
        self._write_line(command)
        return self._collect()

    def dump(self):
        return '\n'.join(self.transcript)

    def close(self):
        try:
            self._write_line('BYE')
        except (BrokenPipeError, ValueError, OSError):
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def fail(session, message):
    print(f"ERROR: {message}", file=sys.stderr)
    print('---- Assuan transcript ----', file=sys.stderr)
    print(session.dump(), file=sys.stderr)
    session.close()
    sys.exit(1)


def is_ok(lines):
    return bool(lines) and (lines[-1] == 'OK' or lines[-1].startswith('OK '))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scd-bin', default='gnupg-pkcs11-scd')
    parser.add_argument('--homedir', required=True)
    parser.add_argument('--options', required=True)
    parser.add_argument('--expect-subject', required=True)
    parser.add_argument('--sign', action='store_true')
    parser.add_argument('--message', default='gnupg smartcard smoke test')
    parser.add_argument('--sig-out')
    args = parser.parse_args()

    if args.sign and not args.sig_out:
        parser.error('--sig-out is required with --sign')

    session = AssuanSession(
        [args.scd_bin, '--server', '--homedir', args.homedir, '--options', args.options]
    )

    banner = session.banner()
    if not is_ok(banner):
        fail(session, 'gnupg-pkcs11-scd did not send an OK banner')

    learn = session.send('LEARN --force')
    if not is_ok(learn):
        fail(session, 'LEARN --force failed')

    fingerprint = None
    subject = None
    for line in learn:
        # The upstream daemon spells this status line "KEY-FRIEDNLY".
        if line.startswith('S KEY-FRIEDNLY ') or line.startswith('S KEY-FRIENDLY '):
            fields = line.split()
            fingerprint = fields[2]
            subject = ' '.join(fields[3:])
            if args.expect_subject in subject:
                break
            fingerprint = None
    if fingerprint is None:
        fail(
            session,
            f"no KEY-FRIEDNLY entry with subject containing '{args.expect_subject}'",
        )
    print(f"LEARN: fingerprint={fingerprint} subject={subject}")

    if args.sign:
        digest = hashlib.sha256(args.message.encode()).hexdigest()
        if not is_ok(session.send(f"SETDATA {digest}")):
            fail(session, 'SETDATA failed')
        sign = session.send(f"PKSIGN --hash=sha256 {fingerprint}")
        if not is_ok(sign):
            fail(session, 'PKSIGN failed')
        payload = ''.join(line[2:] for line in sign if line.startswith('D '))
        if not payload:
            fail(session, 'PKSIGN returned no data')
        # Assuan percent-escapes '%', CR and LF in D lines.
        raw = bytearray()
        i = 0
        while i < len(payload):
            if payload[i] == '%' and i + 3 <= len(payload):
                raw.append(int(payload[i + 1 : i + 3], 16))
                i += 3
            else:
                raw.append(ord(payload[i]))
                i += 1
        with open(args.sig_out, 'wb') as handle:
            handle.write(bytes(raw))
        print(f"PKSIGN: wrote {len(raw)} signature bytes to {args.sig_out}")

    session.close()


if __name__ == '__main__':
    main()
