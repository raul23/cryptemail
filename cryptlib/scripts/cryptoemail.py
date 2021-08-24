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
logger.setLevel(logging.INFO)
# Change logging level for googleapiclient and gnupg loggers
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger('gnupg').setLevel(logging.ERROR)


class CryptoEmail:
    def __init__(self, args):
        # TODO: create directory if not found
        sys.path.append(os.path.expanduser('~/.cryptoemail'))
        self.config = importlib.import_module('config')
        self._check_config(self.config.__dict__)
        self.args = args
        self._check_args()
        self.subject = None
        self.original_message_text = None
        self._get_message()

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
            self._test_connection()
        else:
            logger.info('No action!')

    def _check_args(self):
        logger.debug('Checking args ...')
        if self.args.unencrypt:
            logger.debug('enable_encryption = False')
            self.config.send_emails['encryption']['enable_encryption'] = False
        else:
            logger.debug('enable_encryption = True')
            self.config.send_emails['encryption']['enable_encryption'] = True
        if self.args.sign:
            logger.debug('enable_signature = True')
            self.config.send_emails['signature']['enable_signature'] = True
        for k, v in self.args.__dict__.items():
            if k.endswith('path') and v:
                setattr(self.args, k, os.path.expanduser(v))

    def _check_config(self, config):
        for k, v in config.items():
            if isinstance(v, dict):
                self._check_config(v)
            if not (k.startswith('__') and k.endswith('__')):
                if k == 'HOMEDIR' or k.endswith('path'):
                    config[k] = os.path.expanduser(v)
        self._check_gnupghome(self.config.HOMEDIR)

    @staticmethod
    def _check_email_subject(subject):
        if not subject.startswith('Subject:'):
            logger.info('Subject line:\n{}'.format(subject))
            error_msg = "The subject line should start with 'Subject:'"
            raise ValueError(error_msg)

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
        return gnupghome if gnupghome else None

    @staticmethod
    def _connect_with_tokens(email_account, connection_type, credentials_path, scopes):
        logger.info(f"Connecting to the email server with '{connection_type}'")
        logger.debug('Logging to the email server using TOKENS (more secure than '
                     'with PASSWORD)')
        domain = parse.splituser(email_account)[1]
        if domain != 'gmail.com':
            error_msg = "The email domain is invalid: '{}'. Only 'gmail.com' " \
                        "addresses are supported when using TOKEN-based " \
                        "authentication".format(domain)
            raise ValueError(error_msg)
        if not os.path.exists(credentials_path):
            error_msg = "The path to the credentials doesn't exist: " \
                        "{}".format(credentials_path)
            raise ValueError(error_msg)
        creds = None
        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        dirname = os.path.dirname(credentials_path)
        tokens_path = os.path.join(dirname, 'token.json')
        if os.path.exists(tokens_path):
            creds = Credentials.from_authorized_user_file(tokens_path, scopes)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, scopes)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(tokens_path, 'w') as token:
                token.write(creds.to_json())
        service = build('gmail', 'v1', credentials=creds)
        return service

    def _encrypt_message(self, unencrypted_msg, sign=None):
        config = self.config.send_emails
        recipient = self.config.ASYMMETRIC['recipient_fingerprint']
        # TODO: remove following lines
        """
        try:
            cmd = 'gpg --full-generate-key --expert --homedir ' \
                  f'{self.config.HOMEDIR}'
            import ipdb
            ipdb.set_trace()
            output = subprocess.run(shlex.split(cmd), capture_output=True)
            result = subprocess.check_output(shlex.split(cmd),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            logger.error('Error with log command: {}'.format(e.__repr__()))
            exit_code = 1
        """

        def encrypt_using_gpg(msg):
            start = 'Signing and encrypting' if sign else 'Encrypting'
            logger.info("{} the message (recipient='{}') "
                        "...".format(start, recipient))
            passphrase = None
            if sign:
                passphrase = get_gpg_passphrase(
                    prompt=self.config.PROMPT_PASSPHRASE,
                    gpg=gpg,
                    recipient=recipient,
                    message='Enter your GPG passphrase for signing')
            return gpg.encrypt(msg, recipient, sign=sign, passphrase=passphrase)

        encryption_program = config['encryption'].get('program')
        if encryption_program in ['GPG']:
            logger.debug("Encrypting the message with the encryption program "
                         "'{}'".format(encryption_program))
        elif encryption_program is None:
            raise ValueError("Encryption program missing")
        else:
            error_msg = "'{}' is not supported as an encryption " \
                        "program".format(encryption_program)
            raise ValueError(error_msg)
        if encryption_program == 'GPG':
            gpg = gnupg.GPG(gnupghome=self._check_gnupghome(self.config.HOMEDIR))
            if self._check_fingerprint_in_keyring(recipient, gpg):
                encrypted_msg = encrypt_using_gpg(unencrypted_msg)
                status = encrypted_msg.status
                stderr = encrypted_msg.stderr.strip()
            else:
                encrypted_msg = ''
                status = 'invalid recipient'
                stderr = "The recipient='{}' was not found in the " \
                         "keyring".format(recipient)
            if status == 'encryption ok':
                logger.info('Message encrypted')
            else:
                error_msg = "Status from encrypt(): {}\n" \
                            "{}".format(status, stderr)
                # TODO: important, another exception type?
                raise ValueError(error_msg)
            # gpg.list_keys()
            # gpg.delete_keys()
        else:
            raise NotImplementedError('Only GPG supported!')
        return encrypted_msg

    # TODO: important, implement it
    def _get_email_password(self, email_account, prompt=False):
        password = None
        if not password:
            logger.debug("An email password couldn't be found saved locally")
            if prompt:
                logger.info("Enter your email password for "
                            "'{}'".format(email_account))
                password = getpass.getpass(prompt='Email password: ')
                # TODO: ask email password again
        return password

    def _get_message(self):
        if self.args.email_message:
            self.subject, self.original_message_text = self.args.email_message
            if not self.subject.startswith('Subject:'):
                self.subject = f'Subject: {self.subject}'
        elif self.args.email_path:
            with open(self.args.email_path, 'r') as f:
                email_message = f.read()
            lines = email_message.splitlines()
            self.subject = lines[0]
            self._check_email_subject(self.subject)
            self.original_message_text = '\n'.join(lines[2:])
            # Check email message text
            if not lines[1] == '':
                logger.info('Email message content:\n{}'.format(email_message))
                error_msg = "Empty line missing after the 'Subject:' line"
                raise ValueError(error_msg)
        else:
            error_msg = f"No email message given; Subject: {self.subject} " \
                        f"and Text: {self.original_message_text}"
            raise ValueError(error_msg)
        # Remove "Subject:" if connecting to email server with googlapi
        if self.config.send_emails['connection_method']['name'] == 'googleapi':
            if self.subject.startswith('Subject:'):
                logger.debug(f"Removing 'Subject:' from '{self.subject}'")
                self.subject = self.subject[len('Subject:'):].strip()

    def _read_emails(self):
        logger.info('Reading emails ...')

    def _send_email(self):
        message_text = self.original_message_text
        config = self.config.send_emails
        result = Result()
        sign = None
        if self.config.ASYMMETRIC['recipient_fingerprint'] == self.config.ASYMMETRIC['signature_fingerprint'] \
                and config['encryption']['enable_encryption']:
            logger.warning('Signing with the same encryption key. Both encryption '
                           'and signature fingerprints are the same')
        if not config['signature']['enable_signature']:
            logger.info("No signature will be applied on the email")
        elif config['signature']['enable_signature'] and not config['use_single_pass']:
            try:
                signed_message = self._sign_message(message_text)
                message_text = str(signed_message)
            except ValueError as e:
                error_msg = "The email couldn't be signed with the program " \
                            "{}\n{}".format(config['signature']['program'], e)
                logger.error(error_msg)
                return result.set_error(error_msg)
        elif config['signature']['enable_signature'] and \
                config['encryption']['enable_encryption'] \
                and config['use_single_pass']:
            sign = self.config.ASYMMETRIC['signature_fingerprint']
        if config['encryption']['enable_encryption']:
            try:
                encrypted_message = self._encrypt_message(message_text, sign)
                message_text = str(encrypted_message)
            except ValueError as e:
                error_msg = "The email couldn't be encrypted with the " \
                            "program {}\n{}\n".format(
                                config['encryption']['program'], e)
                logger.error(error_msg)
                return result.set_error(error_msg)
        else:
            logger.info('No encryption will be applied on the email')
        # Connect to the email provider server and send the encrypted email
        if config['connection_method']['name'] == 'googleapi':
            return self._send_email_with_tokens(message_text)
        else:
            return self._send_email_with_password(message_text)

    def _send_email_with_password(self, message_text):
        config = self.config.send_emails
        smtp_config = self.config.send_emails['connection_method']
        logger.info(f"Connecting to the email server with '{smtp_config['name']}'")
        logger.debug('Logging to the smtp server using a PASSWORD (less '
                     'secure than with TOKENS)')
        result = Result()
        message = """\
{}

{}""".format(self.subject, message_text)
        password = self._get_email_password(config['sender_email_address'],
                                            smtp_config['prompt_email_password'])
        if password is None:
            error_msg = "No email password could be retrieved. Thus, the " \
                        "email can't be sent."
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)
        logger.info('Connecting to the smtp server...')
        with smtplib.SMTP(smtp_config['smtp_server'],
                          smtp_config['tls_port']) as server:
            retval = self._login_stmp(server, password)
            if retval:
                return retval
            # Success: {}
            # Fail (printed): *** smtplib.SMTPServerDisconnected: please run connect() first
            logger.debug('Message to be sent to {}:\n{}'.format(
                config['receiver_email_address'], message))
            logger.info('Sending email...')
            server.sendmail(config['sender_email_address'],
                            config['receiver_email_address'], message)
            logger.info('Message sent!\n')
        return result.set_success()

    def _login_stmp(self, server, password):
        result = Result()
        context = ssl.create_default_context()
        server.ehlo()  # Can be omitted
        server.starttls(context=context)
        server.ehlo()  # Can be omitted
        # Success: (235, b'2.7.0 Accepted')
        # Fail (printed): *** smtplib.SMTPAuthenticationError: (535, b'5.7.8 Username and Password not accepted.
        try:
            server.login(self.config.send_emails['sender_email_address'], password)
            del password
        except smtplib.SMTPAuthenticationError as e:
            error_msg = "Login to '{}' failed".format(
                self.config.send_emails['sender_email_address'])
            logger.error(e)
            logger.warning(error_msg + '\n')
            return result.set_error(error_msg)
        else:
            return 0

    def _send_email_with_tokens(self, message_text):
        result = Result()
        auth_config = self.config.send_emails['connection_method']
        service = self._connect_with_tokens(
            email_account=self.config.send_emails['sender_email_address'],
            connection_type=auth_config['name'],
            credentials_path=auth_config['sender_auth']['credentials_path'],
            scopes=auth_config['sender_auth']['scopes'])
        # Call the Gmail API
        msg = create_message(self.config.send_emails['sender_email_address'],
                             self.config.send_emails['receiver_email_address'],
                             self.subject, message_text)
        logger.debug('Message to be sent to {}:\nSubject: {}\n\n{}'.format(
            self.config.send_emails['receiver_email_address'],
            self.subject,
            message_text))
        logger.info('Sending email...')
        result_send = send_message(service,
                                   self.config.send_emails['sender_email_address'], msg)
        if result_send.get('id') and 'SENT' in result_send.get('labelIds', []):
            logger.info('Message sent!\n')
            return result.set_success()
        else:
            error_msg = "Couldn't find SENT in labelIds. Thus, message (ID='{}') " \
                        "couldn't be sent".format(result_send.get('id', 'None'))
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)

    # TODO: provide signature fingerprint as param?
    def _sign_message(self, message_text):
        config = self.config.send_emails
        if config['signature']['program'] == 'GPG':
            logger.info("Signing message (recipient='{}') ...".format(
                self.config.ASYMMETRIC['recipient_fingerprint']))
        else:
            error_msg = "Signature program not supported: " \
                        "{}\n".format(config['signature']['program'])
            raise ValueError(error_msg)
        gpg = gnupg.GPG(gnupghome=self._check_gnupghome(self.config.HOMEDIR))
        passphrase = get_gpg_passphrase(
            prompt=self.config.PROMPT_PASSPHRASE,
            gpg=gpg,
            recipient=self.config.ASYMMETRIC['signature_fingerprint'],
            message="Enter your GPG passphrase for signing with fingerprint="
                    f"'{self.config.ASYMMETRIC['signature_fingerprint']}'")
        message = gpg.sign(message_text,
                           keyid=self.config.ASYMMETRIC['signature_fingerprint'],
                           passphrase=passphrase)
        del passphrase
        if message.status == 'signature created':
            logger.info('Message signed')
            return message
        else:
            error_msg = "{}\n".format(message.stderr.strip())
            raise ValueError(error_msg)

    def _test_connection(self):
        logger.info(f"Testing connection with '{self.args.test_connection}'")
        result = Result()
        if self.args.test_connection == 'googleapi':
            self.config.send_emails['connection_method'] = self.config.googleapi
            auth_config = self.config.send_emails['connection_method']
            service = self._connect_with_tokens(
                email_account=self.config.send_emails['sender_email_address'],
                connection_type=auth_config['name'],
                credentials_path=auth_config['sender_auth']['credentials_path'],
                scopes=auth_config['sender_auth']['scopes'])
            logger.debug("Scopes: "
                         f"{service._rootDesc['auth']['oauth2']['scopes']['https://mail.google.com/']['description']}")
        elif self.args.test_connection == 'smtp':
            smtp_config = self.config.send_emails['connection_method']
            password = self._get_email_password(
                self.config.send_emails['sender_email_address'],
                smtp_config['prompt_email_password'])
            logger.info('Connecting to the smtp server...')
            with smtplib.SMTP(smtp_config['smtp_server'],
                              smtp_config['tls_port']) as server:
                retval = self._login_stmp(server, password)
                if retval:
                    return retval
        else:
            error_msg = 'Connection method not supported: ' \
                        f'{self.args.test_connection }'
            return result.set_error(error_msg)
        logger.info('Connection successful!')
        return result.set_success()


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
        passphrase = get_gpg_passphrase(prompt_passphrase)
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


def get_gpg_passphrase(prompt=False, gpg=None, recipient=None, message=None):
    if gpg and recipient:
        logger.debug('Checking if the passphrase is already cached '
                     '(by gpg-agent)')
        msg = 'test'
        encrypted_data = gpg.encrypt(msg, recipient)
        decrypted_data = gpg.decrypt(str(encrypted_data),
                                     passphrase=generate_random_string())
        if msg == decrypted_data.data.decode():
            logger.info("The GPG passphrase is already cached")
            return None
    if prompt:
        if message:
            print(message)
        password = getpass.getpass(prompt='GPG passphrase: ')
    else:
        # TODO: important, get passphrase from keyring
        error_msg = "No GPG passphrase could be retrieved"
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
    testing_group = parser.add_argument_group('Testing options')
    testing_group.add_argument(
        '--rt', '--run-cfg-tests', dest='run_tests', action='store_true',
        help='Run a battery of tests as defined in the config file.')
    testing_group.add_argument(
        '--te', '--test-encryption', dest='test_encryption',
        action='store_true',
        help='Test encrypting and decrypting a message. The encryption program '
             'used (e.g. GPG) is the one defined in the config file.')
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
    # ===================
    # Send emails options
    # ===================
    send_group = parser.add_argument_group('Send options')
    send_group.add_argument(
        '-s', '--send', dest='send_email', action='store_true',
        help="Send an encrypted email. The encryption applied is the one "
             "defined in the config file.")
    send_group.add_argument(
        '-u', '--unencrypt', action='store_true',
        help="Don't encrypt the email.")
    send_group.add_argument(
        '--sign', action='store_true',
        help="Sign the email. The signature applied is the one defined in the "
             "config file.")
    send_group.add_argument('-m', '--email-message', metavar='STRING', nargs=2,
                            help='The email subject and text.')
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
