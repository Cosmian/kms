# -*- coding: utf-8 -*-
import logging
import os
import sys
import base64
import pprint
import json
import argparse
import httplib2
from pyasn1_modules.rfc2459 import CertificateSerialNumber
from requests_oauthlib import OAuth2Session
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography import x509

CSE_CMD = 'cse'
WRAP_EXT = 'wrap'


class CseCmd:
    def __init__(self, parser):
        self.parser = parser
        self.subparsers = self.parser.add_subparsers(
            dest='subparser_name', title='top level sub-commands'
        )
        self.cmd_mapping = {}
        self.add_keypair_cmds(self.subparsers)
        self.add_identity_cmds(self.subparsers)
        # self.add_composite_cmds(self.subparsers)
        return

    def add_keypair_cmds(self, parser):
        insert_keypair_parser = parser.add_parser(
            'insert_keypair', help='insert wrappedkey/cert pairs for multiple users'
        )
        self._add_common_args(insert_keypair_parser)
        insert_keypair_parser.add_argument(
            '--inkeydir',
            required=True,
            help='input directory with wrapped key files, with email as basename',
        )
        insert_keypair_parser.add_argument(
            '--incertdir',
            required=True,
            help='input directory with p7 pem certs with extension p7pem, with email as basename',
        )

        list_keypair_parser = parser.add_parser(
            'list_keypair', help='list inserted keypairs for a specific user'
        )
        self._add_common_args(list_keypair_parser)
        list_keypair_parser.add_argument(
            '--userid', required=True, help='email id of user'
        )

        insert_parser = parser.add_parser(
            'insert',
            help=(
                'create cse key pairs and identities for multiple users, '
                'same as running insert_keypair followed by insert_identity'
            ),
        )
        self._add_common_args(insert_parser)
        insert_parser.add_argument(
            '--inkeydir',
            required=True,
            help='input directory with wrapped key files, with email as basename and a .wrap extension',
        )
        insert_parser.add_argument(
            '--incertdir',
            required=True,
            help='input directory with p7 pem certs, with email as basename and .p7pem extension',
        )

        disable_keypair_parser = parser.add_parser(
            'disable_keypair', help='disable an existing keypair'
        )
        self._add_common_args(disable_keypair_parser)
        disable_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        disable_keypair_parser.add_argument('--kpid', required=True, help='key pair id')

        enable_keypair_parser = parser.add_parser(
            'enable_keypair', help='enable an existing keypair'
        )
        self._add_common_args(enable_keypair_parser)
        enable_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        enable_keypair_parser.add_argument('--kpid', required=True, help='key pair id')

        obliterate_keypair_parser = parser.add_parser(
            'obliterate_keypair', help='obliterate an existing keypair'
        )
        self._add_common_args(obliterate_keypair_parser)
        obliterate_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        obliterate_keypair_parser.add_argument(
            '--kpid', required=True, help='key pair id'
        )

        return

    def add_identity_cmds(self, parser):
        insert_identity_parser = parser.add_parser(
            'insert_identity', help='create a cse identity for a user'
        )
        self._add_common_args(insert_identity_parser)
        insert_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        insert_identity_parser.add_argument('--kpid', required=True, help='key pair id')
        insert_identity_parser.add_argument(
            '--kpemail', required=True, help='key pair email address'
        )

        list_identity_parser = parser.add_parser(
            'list_identity', help='list all cse identities for a user'
        )
        self._add_common_args(list_identity_parser)
        list_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )

        delete_identity_parser = parser.add_parser(
            'delete_identity', help='delete cse identity for email/alias'
        )
        self._add_common_args(delete_identity_parser)
        delete_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        delete_identity_parser.add_argument(
            '--kpemail', required=True, help='email for identity to delete'
        )

        patch_identity_parser = parser.add_parser(
            'patch_identity', help='patch a cse identity for a user'
        )
        self._add_common_args(patch_identity_parser)
        patch_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        patch_identity_parser.add_argument(
            '--kpemail', required=True, help='email for identity to patch'
        )
        patch_identity_parser.add_argument(
            '--kpid', required=True, help='updated keypair id'
        )

        return

    def add_composite_cmds(self, parser):
        insert_parser = parser.add_parser(
            'insert',
            help=(
                'create cse key pairs and identities for multiple users, '
                'same as running insert_keypair followed by insert_identity'
            ),
        )
        self._add_common_args(insert_parser)
        insert_parser.add_argument(
            '--inkeydir',
            required=True,
            help='input directory with wrapped key files, with email as basename and a .wrap extension',
        )
        insert_parser.add_argument(
            '--incertdir',
            required=True,
            help='input directory with p7 pem certs, with email as basename and .p7pem extension',
        )

        return

    def add_args(self, subparsers):
        cse_parser = subparsers.add_parser(CSE_CMD)
        sub_sub_parsers = cse_parser.add_subparsers(
            dest='cse_parser_name', title='sub-commands'
        )

        insert_keypair_parser = sub_sub_parsers.add_parser(
            'insert_keypair', help='insert wrappedkey/cert pairs for multiple users'
        )
        self._add_common_args(insert_keypair_parser)
        insert_keypair_parser.add_argument(
            '--inkeydir',
            required=True,
            help='input directory with wrapped key files, with email as basename',
        )
        insert_keypair_parser.add_argument(
            '--incertdir',
            required=True,
            help='input directory with p7 pem certs with extension p7pem, with email as basename',
        )

        list_keypair_parser = sub_sub_parsers.add_parser(
            'list_keypair', help='list inserted keypairs for a specific user'
        )
        self._add_common_args(list_keypair_parser)
        list_keypair_parser.add_argument(
            '--userid', required=True, help='email id of user'
        )

        insert_identity_parser = sub_sub_parsers.add_parser(
            'insert_identity', help='create a cse identity for a user'
        )
        self._add_common_args(insert_identity_parser)
        insert_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        insert_identity_parser.add_argument('--kpid', required=True, help='key pair id')
        insert_identity_parser.add_argument(
            '--kpemail', required=True, help='key pair email address'
        )

        list_identity_parser = sub_sub_parsers.add_parser(
            'list_identity', help='list all cse identities for a user'
        )
        self._add_common_args(list_identity_parser)
        list_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )

        delete_identity_parser = sub_sub_parsers.add_parser(
            'delete_identity', help='delete cse identity for email/alias'
        )
        self._add_common_args(delete_identity_parser)
        delete_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        delete_identity_parser.add_argument(
            '--kpemail', required=True, help='email for identity to delete'
        )

        patch_identity_parser = sub_sub_parsers.add_parser(
            'patch_identity', help='patch a cse identity for a user'
        )
        self._add_common_args(patch_identity_parser)
        patch_identity_parser.add_argument(
            '--userid', required=True, help='user_id for the identities'
        )
        patch_identity_parser.add_argument(
            '--kpemail', required=True, help='email for identity to patch'
        )
        patch_identity_parser.add_argument(
            '--kpid', required=True, help='updated keypair id'
        )

        insert_parser = sub_sub_parsers.add_parser(
            'insert',
            help=(
                'create cse key pairs and identities for multiple users, '
                'same as running insert_keypair followed by insert_identity'
            ),
        )
        self._add_common_args(insert_parser)
        insert_parser.add_argument(
            '--inkeydir',
            required=True,
            help='input directory with wrapped key files, with email as basename and a .wrap extension',
        )
        insert_parser.add_argument(
            '--incertdir',
            required=True,
            help='input directory with p7 pem certs, with email as basename and .p7pem extension',
        )

        disable_keypair_parser = sub_sub_parsers.add_parser(
            'disable_keypair', help='disable an existing keypair'
        )
        self._add_common_args(disable_keypair_parser)
        disable_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        disable_keypair_parser.add_argument('--kpid', required=True, help='key pair id')

        enable_keypair_parser = sub_sub_parsers.add_parser(
            'enable_keypair', help='enable an existing keypair'
        )
        self._add_common_args(enable_keypair_parser)
        enable_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        enable_keypair_parser.add_argument('--kpid', required=True, help='key pair id')

        obliterate_keypair_parser = sub_sub_parsers.add_parser(
            'obliterate_keypair', help='obliterate an existing keypair'
        )
        self._add_common_args(obliterate_keypair_parser)
        obliterate_keypair_parser.add_argument(
            '--userid', required=True, help='user_id for keypair'
        )
        obliterate_keypair_parser.add_argument(
            '--kpid', required=True, help='key pair id'
        )

        return CSE_CMD

    def process_args(self, args):
        if not os.path.isfile(args.creds):
            sys.exit(f'non-existent creds file:{args.creds}')

        if args.subparser_name == 'insert_keypair' or args.subparser_name == 'insert':
            if not os.path.isdir(args.inkeydir):
                sys.exit(f'Input wrapped keys directory does not exist:{args.inkeydir}')
            if not os.path.isdir(args.incertdir):
                sys.exit(f'Input p7 certs directory does not exist:{args.incertdir}')
        return

    def process_cmd(self, args):
        self.process_args(args)
        if args.subparser_name not in self.cmd_mapping:
            print(f'Unknown command:args.subparser_name')
        self.cmd_mapping[args.subparser_name](args)
        return

    def process_list_keypair_cmd(self, args):
        """List CSE key pairs

        Lists all the key pairs uploaded for a specific user

        Args:
          args.userid: user id for the mail account

        Returns:
          Prints the keypair info to screen, which includes the keypair id
        """

        email = args.userid
        user_id = email

        try:
            service = self._setup_service(args.creds, email)
            results = {}
            results = (
                service.users()
                .settings()
                .cse()
                .keypairs()
                .list(userId=user_id)
                .execute()
            )
            print(f'results: {results}')

            keypairs = results.get('cseKeyPairs', [])
            pp = pprint.PrettyPrinter(indent=4)
            for kp in keypairs:
                cert = x509.load_pem_x509_certificate(kp['pem'].encode('utf-8'))
                cert_info = {
                    'version': cert.version,
                    'serial_number': cert.serial_number,
                    'subject': cert.subject,
                    'issuer': cert.issuer,
                }

                pp.pprint(kp)
                pp.pprint(cert_info)
        except Exception as exc:
            print(exc)

        return

    def process_insert_keypair_cmd(self, args):
        """Insert CSE key pairs

        Uploads and creates a CSE KeyPairs for multiple users

        Args:
          args.inkeydir: directory containing all the wrapped key files, each file
                        has the basename of userid and .wrap extension.
                        Ex: user1@example.com.wrap, user2@example.com.wrap
          args.incertdir: directory containing all the certs file in p7 pem format,
                        each file has the basename of userid and .p7pem extension.
                        Ex: user1@example.com.p7pem, user2@example.com.p7pem

        Returns:
          Prints the inserted key pair info to screen, which includes the
          keypair id generated by the Gmail backend.
        """

        wrapped_key_files = self._get_input_files(args.inkeydir, WRAP_EXT)
        p7_cert_files = self._get_input_files(args.incertdir, 'p7pem')

        email_key_file_map = self._get_email_to_file(wrapped_key_files, WRAP_EXT)
        email_cert_file_map = self._get_email_to_file(p7_cert_files, 'p7pem')

        email_kpid_dict = {}

        print(f'wrapped_key_files: {wrapped_key_files}')
        print(f'p7_cert_files: {p7_cert_files}')
        for email, key_file in email_key_file_map.items():
            if not email in email_cert_file_map:
                print(f'skipping {email}, missing cert file')
                continue

            print(f'Processing user: {email}')

            try:
                with open(key_file, 'r') as kf, open(
                    email_cert_file_map[email], 'rb'
                ) as cf:
                    kf_resp = json.loads(kf.read())
                    kacls_url = kf_resp['kacls_url']
                    wrapped_private_key = kf_resp['wrapped_private_key']

                    certs = cf.read().decode('utf-8')

                    key_pair_info = {
                        'pkcs7': certs,
                        'privateKeyMetadata': [
                            {
                                'kaclsKeyMetadata': {
                                    'kaclsUri': kacls_url,
                                    'kaclsData': wrapped_private_key,
                                }
                            }
                        ],
                    }

                    print(f'key_pair_info: {key_pair_info}')
                    # print(f"Creating keypair for KACLS: {kacls_url}")
                    service = self._setup_service(args.creds, email)

                    results = (
                        service.users()
                        .settings()
                        .cse()
                        .keypairs()
                        .create(userId=email, body=key_pair_info)
                        .execute()
                    )

                    print(results)
                    print(f'Keypair created for {email}')

                    email_kpid_dict[email] = results['keyPairId']
            except Exception as exc:
                print(exc)

        return email_kpid_dict

    def process_insert_identity_cmd(self, args):
        """Insert CSE Identity

        Uploads and creates a CSE Identity, associating a keypair with an email

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpid: keypair id, associated with a given cert/key. You can get the
                     by listing the keypairs associated with the userid
          args.kpemail: the email alias to associate with the keypair id. Currently,
                        it has to be same as the userid (until we have sendas
                        support).
                        Ex: user1@example.com

        Returns:
          Prints the inserted identity info to screen
        """

        email = args.userid
        kp_id = args.kpid
        kp_email = args.kpemail

        identity = {'primaryKeyPairId': kp_id, 'emailAddress': kp_email}

        try:
            print(f'Creating identity for user: {email}')

            service = self._setup_service(args.creds, email)
            results = (
                service.users()
                .settings()
                .cse()
                .identities()
                .create(userId=email, body=identity)
                .execute()
            )

            print(results)
            print(f'Identity created for {email}')
        except Exception as exc:
            print(exc)

        return

    def process_list_identity_cmd(self, args):
        """List CSE Identity

        List all the CSE Identities for a specific user

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com

        Returns:
          Prints identities info to screen
        """

        email = args.userid
        user_id = 'me'

        try:
            service = self._setup_service(args.creds, email)
            results = {}
            results = (
                service.users()
                .settings()
                .cse()
                .identities()
                .list(userId=email)
                .execute()
            )

            identities = results.get('cseIdentities', [])
            pp = pprint.PrettyPrinter(indent=4)
            print('Identities:')
            for kp in identities:
                pp.pprint(kp)
        except Exception as exc:
            print(exc)

        return

    def process_delete_identity_cmd(self, args):
        """Delete CSE Identity

        Deletes a CSE identity associated with a given alias

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpemail: the email alias for which identity will be deleted.
                        Currently, it has to be same as the userid (until we have
                        send as support).

        Returns:
          Prints the deleted identity info to screen
        """

        email = args.userid
        kp_email = args.kpemail

        try:
            service = self._setup_service(args.creds, email)
            results = (
                service.users()
                .settings()
                .cse()
                .identities()
                .delete(userId=email, cseEmailAddress=kp_email)
                .execute()
            )
            print(results)
        except Exception as exc:
            print(exc)

        return

    def process_patch_identity_cmd(self, args):
        """Patch CSE Identity

        Patches a CSE identity associated with a given alias

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpemail: email id of the alias to patch
          args.kpid: new key pair id for the alias

        Returns:
          Prints the new patch identity info to screen
        """

        email = args.userid
        kp_email = args.kpemail
        kp_id = args.kpid

        identity = {'primaryKeyPairId': kp_id, 'emailAddress': kp_email}

        try:
            service = self._setup_service(args.creds)
            results = (
                service.users()
                .settings()
                .cse()
                .identities()
                .patch(userId=email, emailAddress=kp_email, body=identity)
                .execute()
            )
            print(results)
        except Exception as exc:
            print(exc)

        return

    def process_insert_cmd(self, args):
        """Insert CSE Key Pair and Identity

        Uploads and creates a CSE KeyPair and then creates a CSE Identity.
        It runs the insert_keypair for all the users, followed by insert_identity
        for each of the user, for their userid.

        Args:
          args.inkeydir: directory containing all the wrapped key files, each file
                        has the basename of userid and .wrap extension.
                        Ex: user1@example.com.wrap, user2@example.com.wrap
          args.incertdir: directory containing all the certs file in p7 pem format,
                        each file has the basename of userid and .p7pem extension.
                        Ex: user1@example.com.p7pem, user2@example.com.p7pem

        Returns:
          Prints the inserted key pair and identity info to the screen.
        """

        email_kpid_dict = self.process_insert_keypair_cmd(args)
        for email, kpid in email_kpid_dict.items():
            args.userid = email
            args.kpemail = email
            args.kpid = kpid

            self.process_insert_identity_cmd(args)

        return

    def process_disable_keypair_cmd(self, args):
        """Disable Key Pair

        Disables the given KeyPair from being used for encryption and decryption

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpid: the keypair id for the user

        Returns:
          Prints the disabled keypair info to screen
        """

        email = args.userid
        kpid = args.kpid

        try:
            service = self._setup_service(args.creds, email)
            results = (
                service.users()
                .settings()
                .cse()
                .keypairs()
                .disable(userId=email, keyPairId=kpid)
                .execute()
            )
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(results)
        except Exception as exc:
            print(exc)

        return

    def process_enable_keypair_cmd(self, args):
        """Enable Key Pair

        Enables the given KeyPair from being used for encryption and decryption

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpid: the keypair id for the user

        Returns:
          Prints the enabled keypair info to screen
        """

        email = args.userid
        kpid = args.kpid

        try:
            service = self._setup_service(args.creds, email)
            results = (
                service.users()
                .settings()
                .cse()
                .keypairs()
                .enable(userId=email, keyPairId=kpid)
                .execute()
            )
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(results)
        except Exception as exc:
            print(exc)

        return

    def process_obliterate_keypair_cmd(self, args):
        """Obliterate Key Pair

        Obliterate the given KeyPair, which must be disabled for >= 30 days

        Args:
          args.userid: email id of the mail account.
                       Ex: user1@example.com
          args.kpid: the keypair id for the user

        Returns:
          Prints the disabled key info to screen
        """

        email = args.userid
        kpid = args.kpid

        try:
            service = self._setup_service(args.creds, email)
            results = (
                service.users()
                .settings()
                .cse()
                .keypairs()
                .obliterate(userId=email, keyPairId=kpid)
                .execute()
            )
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint(results)
        except Exception as exc:
            print(exc)

        return

    def _setup_service(self, creds_path, email):
        API_scopes = [
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/gmail.settings.sharing',
            'https://www.googleapis.com/auth/gmail.readonly',
        ]
        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=API_scopes
        )
        creds_delegated = creds.with_subject(email)

        gmail_service = build('gmail', 'v1', credentials=creds_delegated)
        return gmail_service

    def _get_email_to_file(self, files, ext):
        email_file_map = {}
        for file in files:
            bname = os.path.basename(file)
            email, xtn = os.path.splitext(bname)
            if not xtn[1:] == ext:
                continue
            email_file_map[email] = file

        return email_file_map

    def _get_input_files(self, indir, ext):
        full_names = [os.path.join(indir, f) for f in os.listdir(indir)]
        all_files = [f for f in full_names if os.path.isfile(f)]
        input_files = [f for f in all_files if f.endswith(ext)]
        return input_files

    def _add_common_args(self, parser):
        parser.add_argument(
            '--creds', required=True, help='service account creds json file'
        )
        sub_command_name = parser.prog.split()[1]
        sub_command_func = 'process_' + sub_command_name + '_cmd'
        self.cmd_mapping[sub_command_name] = getattr(self, sub_command_func)
        return


def main():
    parser = argparse.ArgumentParser(
        sys.argv[0], formatter_class=argparse.RawDescriptionHelpFormatter
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    cse_cmd = CseCmd(parser)
    args = parser.parse_args()
    cse_cmd.process_cmd(args)


if __name__ == '__main__':
    main()
