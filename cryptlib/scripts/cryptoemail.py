#!/usr/bin/env python
import argparse
import base64
import getpass
import importlib
import logging
import os
import shlex
import smtplib
import socket
import ssl
import string
import subprocess
import sys
from email.mime.text import MIMEText
from secrets import choice
from urllib import parse

import gnupg

from googleapiclient import errors
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import cryptlib

logging.basicConfig(format='%(levelname)-8s %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


class CryptoEmail:
    def __init__(self, args):
        sys.path.append(os.path.expanduser('~/.cryptoemail'))
        self.config = importlib.import_module('config')
        self.args = args
        self.config.send_emails['encryption']['enable_encryption'] = True
        self.subject = ''

    def run(self):
        if self.args.send_email:
            self._send_email()
        elif self.args.read_emails:
            self._read_emails()
        elif self.args.run_tests:
            logger.info('Running tests from config file ...')
        elif self.args.test_encryption:
            logger.info('Testing encryption and decryption ...')
        elif self.args.test_signature:
            logger.info('Testing signature ...')
        elif self.args.test_connection:
            logger.info('Testing connection ...')
        else:
            logger.info('No action!')

    @staticmethod
    def _check_fingerprint_in_keyring(fingerprint, gpg):
        logger.debug("Checking fingerprint='{}' ...".format(fingerprint))
        if fingerprint not in gpg.list_keys().fingerprints:
            logger.warning("The fingerprint='{}' was not found in the "
                           "keyring".format(fingerprint))
            return False
        return True

    @staticmethod
    def _check_gnupghome(gnupghome):
        if gnupghome is None:
            logger.warning('gnupghome is None and will thus take whatever gpg '
                           'defaults to (e.g. ~/.gnupg)')
        return os.path.expanduser(gnupghome) if gnupghome else None

    @staticmethod
    def _connect_with_tokens(email_account, conn_config):
        logger.info('Connecting to the email server with {}'.format(
            conn_config['connection_type']))
        logger.debug('Logging to the email server using TOKENS (more secure than '
                     'with PASSWORD)')
        domain = parse.splituser(email_account)[1]
        if domain != 'gmail.com':
            error_msg = "The email domain is invalid: '{}'. Only 'gmail.com' " \
                        "addresses are supported when using TOKENS-based " \
                        "authentication".format(domain)
            raise ValueError(error_msg)
        conn_config['credentials_path'] = os.path.expanduser(
            conn_config['credentials_path'])
        if not os.path.exists(conn_config['credentials_path']):
            error_msg = "The path to the credentials doesn't exist: " \
                        "{}".format(conn_config['credentials_path'])
            raise ValueError(error_msg)
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        dirname = os.path.dirname(conn_config['credentials_path'])
        tokens_path = os.path.join(dirname, 'token.json')
        if os.path.exists(tokens_path):
            creds = Credentials.from_authorized_user_file(
                tokens_path, conn_config['scopes'])
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    conn_config['credentials_path'],
                    conn_config['scopes'])
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(tokens_path, 'w') as token:
                token.write(creds.to_json())
        service = build('gmail', 'v1', credentials=creds)
        return service

    def _encrypt_message(self, unencrypted_msg, sign=False):
        config = self.config.send_emails
        try:
            cmd = 'gpg --full-generate-key --expert --homedir /Users/nova/test/gpg'
            import ipdb
            ipdb.set_trace()
            output = subprocess.run(shlex.split(cmd), capture_output=True)
            result = subprocess.check_output(shlex.split(cmd),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            logger.error('Error with log command: {}'.format(e.__repr__()))
            exit_code = 1

        def encrypt(msg, fingerprint, passphrase):
            start = 'Signing and encrypting' if sign else 'Encrypting'
            logger.info("{} the message (fingerprint='{}') "
                        "...".format(start, config['encryption']['fingerprint']))
            import ipdb
            ipdb.set_trace()
            passphrase = get_pgp_passphrase(
                prompt=config['prompt_passphrase'],
                gpg=gpg,
                fingerprint=fingerprint,
                message='Enter your PGP passphrase for signing and encrypting',
                use_pinentry_mac=config['use_pinentry_mac'],
                passphrase=passphrase)
            test = gpg.encrypt(msg, fingerprint, sign=sign, passphrase='mom')
            return gpg.encrypt(msg, fingerprint, sign=sign,
                               passphrase=passphrase)

        choices = ['PGP']
        encryption = config['encryption'].get('program')
        if encryption in choices:
            logger.debug('Encrypting the message with {}'.format(encryption))
        elif encrypt is None:
            raise ValueError("Encryption program missing")
        else:
            error_msg = "'{}' is not supported as an encryption " \
                        "method".format(encryption)
            raise ValueError(error_msg)
        if encryption == 'PGP':
            if sign:
                gnupghome = config['signature'].get('gnupghome')
                fingerprint = config['signature']['fingerprint']
            else:
                gnupghome = config['encryption'].get('gnupghome')
                fingerprint = config['encryption']['fingerprint']
            gpg = gnupg.GPG(gnupghome=self._check_gnupghome(gnupghome))
            if self._check_fingerprint_in_keyring(fingerprint, gpg):
                encrypted_msg = encrypt(unencrypted_msg, fingerprint, None)
                status = encrypted_msg.status
                stderr = encrypted_msg.stderr.strip()
            else:
                encrypted_msg = ''
                status = 'invalid recipient'
                stderr = ''
            if status == 'invalid recipient':
                if config['encryption']['prompt_generate_keys']:
                    key, passphrase = generate_keys(
                        gpg, config['prompt_passphrase'],
                        use_pinentry_mac=config['use_pinentry_mac'],
                        message='### Generating keys for encryption ###',
                        return_passphrase=True)
                    fingerprint = key.fingerprint
                    if not sign:
                        config['encryption']['fingerprint'] = fingerprint
                    encrypted_msg = encrypt(unencrypted_msg, fingerprint, passphrase)
                    if encrypted_msg.status == 'encryption ok':
                        logger.info('Message encrypted!')
                    else:
                        # TODO: important, another exception type (or OSError)?
                        raise ValueError(encrypted_msg.stderr)
                else:
                    error_msg = "Couldn't generate keys for encryption"
                    # TODO: important, another exception type?
                    raise ValueError(error_msg)
            elif status == 'encryption ok':
                logger.info('Message encrypted')
            else:
                error_msg = "Status from encrypt(): {}\n" \
                            "{}".format(status, stderr)
                # TODO: important, another exception type?
                raise ValueError(error_msg)
            # gpg.list_keys()
            # gpg.delete_keys()
        else:
            raise NotImplementedError('Only PGP supported!')
        return encrypted_msg

    # TODO: important, implement it
    def _get_email_password(self):
        password = ""
        return password

    def _get_message_text(self):
        return ''

    def _read_emails(self):
        logger.info('Reading emails ...')

    def _send_email(self):
        message_text = self._get_message_text()
        config = self.config.send_emails
        result = Result()
        if config['use_single_pass'] and \
                config['signature']['enable_signature'] \
                and config['encryption']['enable_encryption'] \
                and config['encryption']['encryption_type']['name'] == 'asymmetric':
            try:
                # Sign and encrypt in a single pass
                logger.info('Signing and encrypting in a single pass')
                encrypted_message = self._encrypt_message(message_text, sign=True)
                message_text = str(encrypted_message)
            except ValueError as e:
                error_msg = "The email couldn't be encrypted with the program " \
                            "{}\n{}\n".format(config['encryption']['program'], e)
                logger.error(error_msg)
                return result.set_error(error_msg)
        else:
            # Sign and encrypt separately
            if config['signature']['enable_signature']:
                try:
                    signed_message = self._sign_message(message_text)
                    message_text = str(signed_message)
                except ValueError as e:
                    error_msg = "The email couldn't be signed with the program" \
                                "{}\n{}".format(config['signature']['program'], e)
                    logger.error(error_msg)
                    return result.set_error(error_msg)
            else:
                logger.info("No signature will be applied on the email")
            if config['encryption']['enable_encryption']:
                try:
                    encrypted_message = self._encrypt_message(message_text)
                    message_text = str(encrypted_message)
                except ValueError as e:
                    error_msg = "The email couldn't be encrypted with the " \
                                "program {}\n{}\n".format(
                                    config['encryption']['program'], e)
                    logger.error(error_msg)
                    return result.set_error(error_msg)
            else:
                logger.info('No encryption will be applied on the email')
        if config['connection_method']['name'] == 'googleapi':
            return self._send_email_with_tokens(message_text)
        else:
            return self._send_email_with_password(message_text)

    def _send_email_with_password(self, message_text):
        config = self.config.send_emails
        logger.info('Connecting to the email server with {}'.format(
            config['connection_method']['name']))
        logger.debug('Logging to the smtp server using a PASSWORD (less '
                     'secure than with TOKENS)')
        result = Result()
        message = """\
        {}

        {}""".format(self.subject, message_text)
        password = self._get_email_password()
        if not password:
            logger.debug("An email password couldn't be found saved locally")
            if config['connection_method']['prompt_email_password']:
                logger.info('Enter your email password for '
                            '{}'.format(config['sender_email_address']))
                password = getpass.getpass(prompt='Email password: ')
            else:
                error_msg = "No email password could be retrieved. Thus, the " \
                            "email can't be sent."
                logger.error(error_msg + '\n')
                return result.set_error(error_msg)
        context = ssl.create_default_context()
        logger.info('Connecting to the smtp server...')
        with smtplib.SMTP(config['connection_method']['smtp_server'],
                          config['connection_method']['tls_port']) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            # Success: (235, b'2.7.0 Accepted')
            # Fail (printed): *** smtplib.SMTPAuthenticationError: (535, b'5.7.8 Username and Password not accepted.
            try:
                server.login(config['sender_email'], password)
                del password
            except smtplib.SMTPAuthenticationError as e:
                error_msg = "Login to '{}' failed".format(config['sender_email'])
                logger.error(e)
                logger.warning(error_msg + '\n')
                return result.set_error(error_msg)
            # Success: {}
            # Fail (printed): *** smtplib.SMTPServerDisconnected: please run connect() first
            logger.debug('Message to be sent to {}:\n{}'.format(
                config['receiver_email'], message))
            logger.info('Sending email...')
            server.sendmail(config['sender_email'], config['receiver_email'], message)
            logger.info('Message sent!\n')
        return result.set_success()

    def _send_email_with_tokens(self, message_text):
        result = Result()
        service = self._connect_with_tokens(
            self.config.send_emails['sender_email_address'],
            self.config.send_emails['connection_method'])
        # Call the Gmail API
        msg = create_message(self.config.send_emails['sender_email_address'],
                             self.config.send_emails['receiver_email_address'],
                             self.subject, message_text)
        logger.debug('Message to be sent to {}:\n{}'.format(
            self.config.send_emails['receiver_email'], message_text))
        logger.info('Sending email...')
        result_send = send_message(service,
                                   self.config.send_emails['sender_email'], msg)
        if result_send.get('id') and 'SENT' in result_send.get('labelIds', []):
            logger.info('Message sent!\n')
            return result.set_success()
        else:
            error_msg = "Couldn't find SENT in labelIds. Thus, message (ID='{}') " \
                        "couldn't be sent".format(result_send.get('id', 'None'))
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)

    def _sign_message(self, message_text):
        config = self.config.send_emails
        if config['signature']['program'] == 'PGP':
            logger.info("Signing message (fingerprint='{}') "
                        "...".format(config['signature']['fingerprint']))
        else:
            error_msg = "Signature program not supported: " \
                        "{}\n".format(config['signature']['signature_program'])
            raise ValueError(error_msg)
        gpg = gnupg.GPG(
            gnupghome=self._check_gnupghome(config['signature'].get('gnupghome')))
        passphrase = None
        if config['encryption']['fingerprint'] == config['signature']['fingerprint']:
            same_keys = True
        else:
            same_keys = False
        if config['encryption']['enable_encryption'] and same_keys:
            logger.warning('Signing with the same encrypting keys. Both encryption '
                           'and signature fingerprints are the same')
        if not self._check_fingerprint_in_keyring(config['signature']['fingerprint'], gpg) \
                or (config['encryption']['enable_encryption'] and same_keys):
            if config['reuse_keys']:
                logger.warning(
                    "Reusing previous encryption keys for signing "
                    "(fingerprint='{}')".format(config['encryption']['fingerprint']))
                config['signature']['fingerprint'] = config['encryption']['fingerprint']
            else:
                logger.debug('The encryption keys will not be reused for signing')
                if config['signature']['prompt_generate_keys']:
                    key, passphrase = generate_keys(
                        gpg, config['prompt_passphrase'],
                        use_pinentry_mac=config['use_pinentry_mac'],
                        message='### Generating keys for signing ###',
                        return_passphrase=True)
                    config['signature']['fingerprint'] = key.fingerprint
                    logger.info("Signing message (fingerprint='{}') "
                                "...".format(config['signature']['fingerprint']))
                else:
                    error_msg = "Couldn't generate keys for signing"
                    # TODO: important, another exception type?
                    raise ValueError(error_msg)
        passphrase = get_pgp_passphrase(
            prompt=config['prompt_passphrase'],
            gpg=gpg,
            fingerprint=config['signature']['fingerprint'],
            message='Enter your PGP passphrase for signing',
            use_pinentry_mac=config['use_pinentry_mac'],
            passphrase=passphrase)
        message = gpg.sign(message_text, keyid=config['signature']['fingerprint'],
                           passphrase=passphrase)
        del passphrase
        if message.status == 'signature created':
            logger.info('Message signed')
            return message
        else:
            error_msg = "{}\n".format(message.stderr.strip())
            raise ValueError(error_msg)


class Result:
    def __init__(self):
        self.error_msg = ''
        self.warning_msg = ''
        self.exit_code = None
        self.cmd = ''

    def set_error(self, msg, exit_code=1):
        self.error_msg = msg
        self.exit_code = exit_code
        return self

    def set_success(self, cmd='', exit_code=0):
        self.cmd = cmd
        self.exit_code = exit_code
        return self

    def set_warning(self, msg, exit_code=1):
        self.warning_msg = msg
        self.exit_code = exit_code
        return self


# TODO: add reference (google)
def create_message(sender, to, subject, message_text):
    """Create a message for an email.

    Args:
      sender: Email address of the sender.
      to: Email address of the receiver.
      subject: The subject of the email message.
      message_text: The text of the email message.

    Returns:
      An object containing a base64url encoded email object.
    """
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}


def generate_keys(gpg, prompt_passphrase, use_pinentry_mac=False, message=None,
                  return_passphrase=False):
    if message:
        print('\n' + message)
    else:
        print('')
    print('Enter the following data to generate the new keys \nNOTE: '
          'if nothing is entered for a field, then the default '
          'value will be used\n')
    name_email = prompt_name_email()
    print()
    key_type = prompt_key_type()
    print()
    key_length = prompt_key_length()
    if use_pinentry_mac:
        passphrase = ''
    else:
        print()
        passphrase = get_pgp_passphrase(prompt_passphrase)
    print('\nGenerating keys...')
    input_data = gpg.gen_key_input(
        name_email=name_email,
        key_type=key_type,
        key_length=key_length,
        passphrase=passphrase)
    key = gpg.gen_key(input_data)
    print('\nFingerprint associated with the newly generated keys: {}'.format(key))
    input('Press any key to continue...\n')
    if return_passphrase:
        passphrase = None if passphrase == '' else passphrase
        return key, passphrase
    else:
        del return_passphrase
        return key


# Ref.: https://stackoverflow.com/a/41464693
def generate_random_string(n=10):
    return ''.join([choice(string.ascii_uppercase + string.digits) for _ in range(n)])


def get_pgp_passphrase(prompt=False, gpg=None, fingerprint=None, message=None,
                       use_pinentry_mac=False, passphrase=''):
    if (passphrase or passphrase is None) and use_pinentry_mac:
        return passphrase

    # TODO: urgent, remove the following (not necessary anymore)
    if gpg and fingerprint:
        logger.debug('Checking if the passphrase is already cached '
                     '(by gpg-agent or keychain)')
        msg = 'test'
        encrypted_data = gpg.encrypt(msg, fingerprint)
        decrypted_data = gpg.decrypt(str(encrypted_data),
                                     passphrase=generate_random_string())
        if msg == decrypted_data.data.decode():
            logger.warning("The PGP passphrase is already cached")
            return None

    if prompt:
        if message:
            print(message)
        password = getpass.getpass(prompt='PGP passphrase: ')
    else:
        # TODO: important, get passphrase from os.environ
        error_msg = "No PGP passphrase could be retrieved. Thus, PGP " \
                    "encryption can't be applied"
        raise ValueError(error_msg)
    return password


def prompt_key_length():
    default = 4096
    while True:
        print('Enter key length (int) of the generated key in bits (default: '
              '{})'.format(default))
        key_length = input('key length: ')
        if key_length == '':
            # TODO: important, show default value for key length
            print('Default value ({}) will be used'.format(default))
            return 4096
        try:
            key_length = int(key_length)
            if key_length <= 0:
                raise ValueError
        except ValueError:
            print('Invalid key length!')
        else:
            return key_length


def prompt_key_type():
    default = 'RSA'
    choices = ['RSA', 'DSA', 'ELG-E']
    while True:
        print('Enter key type (choices: {})'.format(', '.join(choices)))
        key_type = input('key type: ')
        if key_type in choices:
            return key_type
        elif key_type == '':
            # TODO: important, show default value for key type
            print('Default value will be used: {}'.format(default))
            return default
        else:
            print('Invalid key type!')


def prompt_name_email():
    # print('Enter name email')
    # From gnupg.gen_key_input()
    logname = (os.environ.get('LOGNAME') or os.environ.get('USERNAME') or
               'unspecified')
    # default = '{}@{}'.format(getpass.getuser(), socket.gethostname())
    default = '{}@{}'.format(logname.replace(' ', '_'), socket.gethostname())
    print('Enter name email (default: {})'.format(default))
    name_email = input('Name email: ')
    if name_email == '':
        # TODO: important, check if this is the default value for name_email
        print('Default value will be used: {}'.format(default))
        name_email = default
    return name_email


# TODO: add reference (google)
def send_message(service, user_id, message):
    """Send an email message.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      message: Message to be sent.

    Returns:
      Sent Message.
    """
    try:
        message = (service.users().messages().send(userId=user_id, body=message).execute())
        print('Message Id: {}'.format(message['id']))
        return message
    except errors.HttpError as e:
        print('An error occurred: {}'.format(e))


def setup_argparser():
    # Setup the parser
    parser = argparse.ArgumentParser(
        # usage="%(prog)s [OPTIONS]",
        # prog=os.path.basename(__file__),
        description='Command-line program for sending and receiving encrypted '
                    'emails.',
        # formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # ===============
    # General options
    # ===============
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {}'.format(cryptlib.__version__))
    # ===============
    # Testing options
    # ===============
    # ===============
    # Testing options
    # ===============
    testing_group = parser.add_argument_group('Testing options')
    testing_group.add_argument(
        '--rt', '--run-cfg-tests', dest='run_tests', action='store_true',
        help='Run a battery of tests as defined in the config file.')
    testing_group.add_argument(
        '--te', '--test-encryption', dest='test_encryption',
        action='store_true',
        help='Test encrypting and decrypting a message. The encryption program '
             'used (e.g. PGP) is the one defined in the config file.')
    testing_group.add_argument(
        '--ts', '--test-signature', dest='test_signature', action='store_true',
        help='Test signing a message.')
    # TODO: important add support for test-connection
    testing_group.add_argument(
        '--tc', '--test-connection', metavar='CONNECTION',
        dest='test_connection', choices=['googleapi', 'smtp'],
        help='Test connecting to an email server either with tokens '
             '(`googleapi`) or with an email password (`smtp`).')
    # =================
    # Uninstall options
    # =================
    # TODO: important, use subcommands
    uninstall_group = parser.add_argument_group('Uninstall options')
    uninstall_group.add_argument(
        '--uninstall', choices=['program', 'everything'],
        help="Uninstall the '{}' program or everything (including config and "
             "log files).".format(cryptlib.__project_name))
    # ============
    # Edit options
    # ============
    edit_group = parser.add_argument_group('Edit options')
    # ========================
    # Send/read emails options
    # ========================
    send_group = parser.add_argument_group('Send options')
    send_group.add_argument(
        '-s', '--send', dest='send_email', action='store_true',
        help="Send an email encrypted. The encryption applied is the one "
             "defined in the config file.")
    send_group.add_argument(
        '-u', '--unencrypt', action='store_true',
        help="Don't encrypt the email.")
    send_group.add_argument(
        '--sign', action='store_true',
        help="Sign the email based on the config file.")
    send_group.add_argument('-m', '--email-message', metavar='STRING',
                            nargs=2,
                            help='Email subject and text.')
    send_group.add_argument(
        '-p', '--email-path', metavar='PATH',
        help='Path to a text file containing the email to be sent.')
    # ===================
    # Read emails options
    # ===================
    send_group = parser.add_argument_group('Read options')
    send_group.add_argument(
        '-r', '--read', dest='read_emails',
        action='store_true',
        help="Read emails from your inbox which might contain "
             "unencrypted and encrypted emails.")
    return parser


def main():
    # Parse command-line arguments
    parser = setup_argparser()
    args = parser.parse_args()
    if args.uninstall:
        logger.info('Uninstalling program ...')
    else:
        CryptoEmail(args).run()


if __name__ == '__main__':
    sys.exit(main())
