#!/usr/bin/env python
import base64
import getpass
import smtplib
import ssl
import string
import traceback
from email.mime.text import MIMEText
from functools import wraps
from secrets import choice
from urllib import parse

import gnupg

from googleapiclient import errors
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import cryptlib
from cryptlib.configs import default_config
from cryptlib.utils.genutils import *

logger = init_log(__name__, __file__)
# Change logging level for googleapiclient and gnupg loggers
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger('gnupg').setLevel(logging.ERROR)

# ==================================
# Default cryptoemail config options
# ==================================
PROJECT_NAME = cryptlib.__project_name__
# Logs
# ====
# Logs directory
LOGS_DIR = f'/var/log/{PROJECT_NAME}'
# Logs file
LOGS_PATH = os.path.join(LOGS_DIR, 'logs.txt')
# Project
# =======
# Project directory
PROJECT_DIR = os.path.expanduser(f'~/.{PROJECT_NAME}')
# Configuration files within project directory
CONFIG_PATH = os.path.join(PROJECT_DIR, 'config.py')
LOGGING_PATH = os.path.join(PROJECT_DIR, 'logging.py')


class CryptoEmail:
    def __init__(self, config):
        self.config = config
        self._check_config(self.config.__dict__)
        self._check_gnupghome(self.config.homedir)
        self._check_args()
        self.subject = ''
        self.original_message_text = ''
        self._get_message()
        self.tester = Tester()

    def run(self):
        if self.config.send:
            self._send_email()
        if self.config.read:
            self._read_emails()
        if self.config.run_tests:
            self._run_tests()
        if self.config.test_encryption:
            self._test_encryption(self.config.test_message)
        if self.config.test_signature:
            self._test_signature(self.config.test_message)
        if self.config.test_connection != 'not_used':
            self._test_connection(self.config.test_connection)
        if self.tester.n_tests:
            logger.info('### Test results ###')
            logger.info('Success rate: {}/{} = {}%\n'.format(
                self.tester.n_success, self.tester.n_tests,
                int(self.tester.success_rate * 100)))
        return 0

    def _check_args(self):
        logger.debug('Checking args ...')
        if getattr(self.config, 'unencrypt', None):
            logger.debug('enable_encryption = False')
            self.config.send_emails['encryption']['enable_encryption'] = False
        else:
            logger.debug('enable_encryption = True')
            self.config.send_emails['encryption']['enable_encryption'] = True
        if getattr(self.config, 'sign', None):
            logger.debug('enable_signature = True')
            self.config.send_emails['signature']['enable_signature'] = True

    def _check_config(self, config):
        for k, v in config.items():
            if v is None:
                continue
            if isinstance(v, dict):
                self._check_config(v)
            if not (k.startswith('__') and k.endswith('__')):
                if k == 'homedir' or k.endswith('path'):
                    config[k] = os.path.expanduser(v)

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

    @staticmethod
    def _check_subject_and_text(subject, text):
        if (subject.startswith('Subject:') and not subject.strip('Subject:')) \
                or not subject:
            logger.warning('Message subject is empty')
        if not text:
            error_msg = f"No message text given"
            raise ValueError(error_msg)

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
        recipient = self.config.asymmetric['recipient_fingerprint']
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
                    prompt=self.config.prompt_passphrase,
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
            gpg = gnupg.GPG(gnupghome=self.config.homedir)
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
        if self.config.email_message:
            self.subject, self.original_message_text = self.config.email_message
            if not self.subject.startswith('Subject:'):
                self.subject = f'Subject: {self.subject}'
        elif self.config.email_path:
            with open(self.config.email_path, 'r') as f:
                email_message = f.read()
            lines = email_message.splitlines()
            self.subject = lines[0]
            if not self.subject.startswith('Subject:'):
                logger.info('Subject line:\n{}'.format(self.subject))
                error_msg = "The subject line should start with 'Subject:'"
                raise ValueError(error_msg)
            self.original_message_text = '\n'.join(lines[2:])
            # Check email message text
            if not lines[1] == '':
                logger.info('Email message content:\n{}'.format(email_message))
                error_msg = "Empty line missing after the 'Subject:' line"
                raise ValueError(error_msg)
        # Remove "Subject:" if connecting to email server with googlapi
        if self.config.send_emails['connection_method'] == 'googleapi':
            if self.subject.startswith('Subject:'):
                logger.debug(f"Removing 'Subject:' from '{self.subject}'")
                self.subject = self.subject[len('Subject:'):].strip()

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

    def _read_emails(self):
        logger.info('Reading emails ...')

    def _run_tests(self):
        logger.info('Running tests from config file ...\n')
        if self.config.test_encryption:
            self._test_encryption(self.config.test_message)
        if self.config.test_signature:
            self._test_signature(self.config.test_message)
        if self.config.test_connection:
            self._test_connection(self.config.test_connection)
        logger.info('End tests from config file\n')

    def _send_email(self):
        self._check_subject_and_text(self.subject, self.original_message_text)
        message_text = self.original_message_text
        config = self.config.send_emails
        result = Result()
        sign = None
        if self.config.asymmetric['recipient_fingerprint'] \
                == self.config.asymmetric['signature_fingerprint'] \
                and config['encryption']['enable_encryption'] \
                and config['signature']['enable_signature']:
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
            sign = self.config.asymmetric['signature_fingerprint']
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
        logger.info(f"sender email address: "
                    f"{self.config.send_emails['sender_email_address']}")
        logger.info(f"receiver email address: "
                    f"{self.config.send_emails['receiver_email_address']}")
        if config['connection_method'] == 'googleapi':
            return self._send_email_with_tokens(message_text)
        else:
            return self._send_email_with_password(message_text)

    def _send_email_with_password(self, message_text):
        config = self.config.send_emails
        smtp_config = self.config.send_emails['connection_method']
        logger.info(f"Connecting to the email server with 'smtp'")
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

    def _send_email_with_tokens(self, message_text):
        result = Result()
        connection_type = self.config.send_emails['connection_method']
        auth_config = getattr(self.config, connection_type)
        service = self._connect_with_tokens(
            email_account=self.config.send_emails['sender_email_address'],
            connection_type=connection_type,
            credentials_path=auth_config['sender_auth']['credentials_path'],
            scopes=auth_config['sender_auth']['scopes'])
        # Call the Gmail API
        msg = create_message(self.config.send_emails['sender_email_address'],
                             self.config.send_emails['receiver_email_address'],
                             self.subject, message_text)
        logger.debug("Message to be sent to "
                     f"{self.config.send_emails['receiver_email_address']}:\n"
                     f"Subject: {self.subject}\n\n{message_text}")
        logger.info('Sending email...')
        result_send = send_message(
            service, self.config.send_emails['sender_email_address'], msg)
        if result_send is None:
            error_msg = "send_message() returned None. Thus, email couldn't " \
                        "be sent"
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)
        elif result_send.get('id') and 'SENT' in result_send.get('labelIds', []):
            logger.info('Message sent!\n')
            return result.set_success()
        else:
            error_msg = "Couldn't find SENT in labelIds. Thus, message " \
                        f"(ID='{result_send.get('id', 'None')}') couldn't be " \
                        "sent"
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)

    # TODO: provide signature fingerprint as param?
    def _sign_message(self, message_text):
        config = self.config.send_emails
        if config['signature']['program'] == 'GPG':
            logger.info("Signing message (recipient='{}') ...".format(
                self.config.asymmetric['recipient_fingerprint']))
        else:
            error_msg = "Signature program not supported: " \
                        "{}\n".format(config['signature']['program'])
            raise ValueError(error_msg)
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        passphrase = get_gpg_passphrase(
            prompt=self.config.prompt_passphrase,
            gpg=gpg,
            recipient=self.config.asymmetric['signature_fingerprint'],
            message="Enter your GPG passphrase for signing with fingerprint="
                    f"'{self.config.asymmetric['signature_fingerprint']}'")
        message = gpg.sign(message_text,
                           keyid=self.config.asymmetric['signature_fingerprint'],
                           passphrase=passphrase)
        del passphrase
        if message.status == 'signature created':
            logger.info('Message signed')
            return message
        else:
            error_msg = "{}\n".format(message.stderr.strip())
            raise ValueError(error_msg)

    def _update_report(test_type):
        def update_decorator(func):
            @wraps(func)
            def wrapped_function(*args, **kwargs):
                # self is always the first argument
                self = args[0]
                try:
                    result = func(*args, **kwargs)
                except Exception as e:
                    result = Result()
                    # TODO: logger.error(e) if no traceback to be shown
                    error_msg = f'{traceback.format_exc()}'.strip()
                    logger.error(f'{error_msg}\n')
                    result.set_error(e)
                self.tester.update_report(test_type=test_type, result=result)
                return result
            return wrapped_function
        return update_decorator

    @_update_report('testing connection')
    def _test_connection(self, connection):
        logger.info(f"### Testing connection with '{connection}' ###")
        result = Result()
        if connection == 'googleapi':
            self.config.send_emails['connection_method'] = connection
            connection_type = self.config.send_emails['connection_method']
            auth_config = getattr(self.config, connection_type)
            service = self._connect_with_tokens(
                email_account=self.config.send_emails['sender_email_address'],
                connection_type=connection_type,
                credentials_path=auth_config['sender_auth']['credentials_path'],
                scopes=auth_config['sender_auth']['scopes'])
            logger.debug("Scopes: "
                         f"{service._rootDesc['auth']['oauth2']['scopes']['https://mail.google.com/']['description']}")
        elif connection == 'smtp':
            self.config.send_emails['connection_method'] = self.config.smtp
            smtp_config = self.config.send_emails['connection_method']
            password = self._get_email_password(
                self.config.send_emails['sender_email_address'],
                smtp_config['prompt_email_password'])
            logger.info('Connecting to the smtp server...')
            with smtplib.SMTP(smtp_config['smtp_server'],
                              smtp_config['tls_port']) as server:
                retval = self._login_stmp(server, password)
                result = retval if retval else result
        else:
            error_msg = f'Connection method not supported: {connection}\n'
            result.set_error(error_msg)
        if not result.exit_code:
            logger.info('Connection successful!\n')
            result.set_success()
        return result

    @_update_report('testing encryption/decryption')
    def _test_encryption(self, plaintext_message):
        logger.info('### Testing encrypting/decrypting a message ###')
        result = Result()
        logger.info('Plaintext message: {}'.format(plaintext_message))
        try:
            encrypted_message = self._encrypt_message(plaintext_message)
        except ValueError as e:
            error_msg = "The email couldn't be encrypted with the " \
                        "program {}\n{}\n".format(
                            self.config.send_emails['encryption']['program'], e)
            logger.error(error_msg)
            return result.set_error(error_msg)
        logger.info('')
        logger.info('## Encryption results ##')
        logger.info('ok: {}'.format(encrypted_message.ok))
        logger.info('status: {}'.format(encrypted_message.status))
        logger.debug('stderr: {}'.format(encrypted_message.stderr))
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        decrypted_message = gpg.decrypt(str(encrypted_message))
        logger.info('')
        logger.info('## Decryption results ##')
        logger.info('ok: {}'.format(decrypted_message.ok))
        logger.info('status: {}'.format(decrypted_message.status))
        logger.debug('stderr: {}'.format(decrypted_message.stderr))
        logger.info('')
        logger.debug('Encrypted message:\n{}'.format(str(encrypted_message)))
        logger.info('Decrypted message: {}'.format(decrypted_message.data.decode()))
        if plaintext_message == decrypted_message.data.decode():
            logger.info('Encryption/decryption successful!\n')
            result.set_success()
        else:
            error_msg = "The message couldn't be decrypted " \
                        "correctly\n{}".format(decrypted_message.stderr)
            logger.error(error_msg)
            result.set_error(error_msg)
        return result

    @_update_report('testing signing')
    def _test_signature(self, message):
        logger.info('### Testing signing a message ###')
        result = Result()
        logger.info('Message to be signed: {}'.format(message))
        try:
            signed_message = self._sign_message(message)
        except ValueError as e:
            error_msg = "The message couldn't be " \
                        "signed\n{}".format(e)
            logger.error(error_msg)
            result.set_error(error_msg)
            return result
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        verify = gpg.verify(signed_message.data)
        logger.info('')
        logger.info('## Signature results ##')
        logger.info('valid: {}'.format(verify.valid))
        logger.info('status: {}'.format(verify.status))
        logger.debug('stderr: {}'.format(verify.stderr))
        logger.info('')
        if verify.valid:
            logger.info('Signing message successful!\n')
            result.set_success()
        else:
            error_msg = "The message couldn't be " \
                        "signed\n{}".format(verify.stderr)
            logger.error(error_msg)
            result.set_error(error_msg)
        return result


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


class Tester:
    def __init__(self):
        self.report = {}
        self.n_tests = 0
        self.n_fails = 0
        self.n_success = 0
        self.success_rate = 0

    def update_tests(self, test_type):
        self.n_tests += 1
        self.n_fails += 1 if self.report[test_type][-1].exit_code == 1 else 0
        self.n_success = self.n_tests - self.n_fails
        self.success_rate = self.n_success / self.n_tests

    def update_report(self, test_type, result):
        self.report.setdefault(test_type, [])
        self.report[test_type].append(result)
        self.update_tests(test_type)


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


def process_returned_values(returned_values):
    def log_opts_overridden(opts_overridden, msg, log_level='debug'):
        nb_items = len(opts_overridden)
        for i, (cfg_name, old_v, new_v) in enumerate(opts_overridden):
            msg += f'\t {cfg_name}: {old_v} --> {new_v}'
            if i + 1 < nb_items:
                msg += "\n"
        getattr(logger, log_level)(msg)

    # Process config options overridden by command-line args
    if returned_values.config_opts_overridden:
        msg = returned_values.msg
        log_opts_overridden(returned_values.config_opts_overridden, msg)
    # Process arguments not found in config file
    if returned_values.args_not_found_in_config and True:
        msg = 'Command-line arguments not found in config file:\n'
        log_opts_overridden(returned_values.args_not_found_in_config, msg)


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
    width = os.get_terminal_size().columns - 5
    parser = argparse.ArgumentParser(
        # usage="%(prog)s [OPTIONS]",
        # prog=os.path.basename(__file__),
        description='Command-line program for sending and reading encrypted '
                    'emails.',
        usage=usage(__file__),
        add_help=False,
        # ArgumentDefaultsHelpFormatter
        # HelpFormatter
        # RawDescriptionHelpFormatter
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    # ===============
    # General options
    # ===============
    general_group = parser.add_argument_group(f"{yellow('General options')}")
    general_group.add_argument('-h', '--help', action='help',
                               help='Show this help message and exit.')
    general_group.add_argument(
        '-v', '--version', action='version',
        version=f'%(prog)s v{cryptlib.__version__}',
        help="Show program's version number and exit.")
    general_group.add_argument(
        '-q', '--quiet', action='store_true',
        help='Enable quiet mode, i.e. nothing will be printed.')
    general_group.add_argument(
        '--verbose', action='store_true',
        help='Print various debugging information, e.g. print traceback '
             'when there is an exception.')
    general_group.add_argument(
        '-l', '--log-level', dest='logging_level',
        choices=['debug', 'info', 'warning', 'error'],
        default=default_config.logging_level,
        help='Set logging level for all loggers.'
             + default(default_config.logging_level))
    # TODO: explain each format
    general_group.add_argument(
        '-f', '--log-format', dest='logging_formatter',
        choices=['console', 'simple', 'only_msg'],
        default=default_config.logging_formatter,
        help='Set logging formatter for all loggers.'
             + default(default_config.logging_formatter))
    """
    general_group.add_argument(
        '-i', '--inbox-address', metavar='ADDRESS',
        dest='inbox_address',
        help='Inbox address (e.g. my_email@address.com)')
    """
    # ===============
    # Testing options
    # ===============
    testing_group = parser.add_argument_group(f"{yellow('Testing options')}")
    testing_group.add_argument(
        '--rt', '--run-cfg-tests', dest='run_tests', action='store_true',
        help='Run a battery of tests as defined in the config file.')
    testing_group.add_argument(
        '--te', '--test-encryption', dest='test_encryption', action='store_true',
        help='Test encrypting and decrypting a message. The encryption program '
             'used (e.g. GPG) is the one defined in the config file.')
    testing_group.add_argument(
        '--ts', '--test-signature', dest='test_signature', action='store_true',
        help='Test signing a message.')
    testing_group.add_argument(
        '--tm', '--test-message', metavar='MESSAGE', dest='test_message',
        default=default_config.test_message,
        help='Message to be used for testing encryption or signing.'
             + default(default_config.test_message))
    testing_group.add_argument(
        '--tc', '--test-connection', metavar='CONNECTION',
        dest='test_connection', choices=['googleapi', 'smtp'],
        default='not_used',
        help='Test connecting to an email server either with tokens '
             '(`googleapi`) or an email password (`smtp`).')
    # =================
    # Uninstall options
    # =================
    # TODO: important, use subcommands
    uninstall_group = parser.add_argument_group(f"{yellow('Uninstall options')}")
    uninstall_group.add_argument(
        '--uninstall', choices=['package', 'everything'],
        help="Uninstall the `package` (including the program '{}') or "
             "`everything` (including config and log files).".format(
            prog_name(__file__)))
    # ============================
    # Edit cryptoemail config file
    # ============================
    edit_group = parser.add_argument_group(
        f"{yellow('Edit/reset the configuration file')}")
    edit_mutual_group = edit_group.add_mutually_exclusive_group()
    edit_mutual_group.add_argument(
        '-e', '--edit', action='store_true',
        help=f'Edit the {prog_name(__file__)} configuration file.')
    edit_group.add_argument(
        '-a', '--app', dest='app',
        help='Name of the application to use for editing the '
             f'{prog_name(__file__)} configuration file. If no name is given, '
             'then the default application for opening this type of file (.py) '
             'will be used.')
    edit_mutual_group.add_argument(
        '--reset', action='store_true',
        help=f'Reset the {prog_name(__file__)} configuration file to factory values.')
    # ===================
    # Send emails options
    # ===================
    send_group = parser.add_argument_group(f"{yellow('Send options')}")
    send_group.add_argument(
        '-s', '--send', dest='send', action='store_true',
        help="Send an encrypted email. The encryption applied is the one "
             "defined in the config file.")
    send_group.add_argument(
        '-u', '--unencrypt', action='store_true',
        help="Don't encrypt the email.")
    send_group.add_argument(
        '--recipient', metavar='USER-ID',
        dest='asymmetric.recipient_fingerprint',
        help="Recipient to be used for encrypting the message.")
    send_group.add_argument(
        '--sign', metavar='USER-ID', dest='asymmetric.signature_fingerprint',
        help="Sign the email. The signature applied is the one defined in the "
             "config file.")
    send_group.add_argument('-m', '--email-message', metavar='STRING', nargs=2,
                            help='The email subject and text.')
    send_group.add_argument(
        '-p', '--email-path', metavar='PATH',
        help='Path to a text file containing the email to be sent.')
    send_group.add_argument(
        '--sc', '--send-connection', metavar='CONNECTION',
        dest='send_emails.connection_method', choices=['googleapi', 'smtp'],
        help='Connecting to an email server for sending either with tokens '
             '(`googleapi`) or an email password (`smtp`).')
    send_group.add_argument(
        '--sa', '--sender-address', metavar='ADDRESS',
        dest='send_emails.sender_email_address',
        help='Sender email address (e.g. sender@address.com)')
    send_group.add_argument(
        '--ra', '--receiver-address', metavar='ADDRESS',
        dest='send_emails.receiver_email_address',
        help='Receiver email address (e.g. receiver@address.com)')
    # ===================
    # Read emails options
    # ===================
    read_group = parser.add_argument_group(f"{yellow('Read options')}")
    read_group.add_argument(
        '-r', '--read', dest='read',
        action='store_true',
        help='Read emails from your inbox which might contain '
             'unencrypted and encrypted emails.')
    read_group.add_argument(
        '--rc', '--read-connection', metavar='CONNECTION',
        dest='send_emails.connection_method', choices=['googleapi', 'smtp'],
        help='Connecting to an email server for reading either with tokens '
             '(`googleapi`) or an email password (`smtp`).')
    read_group.add_argument(
        '--reader-address', metavar='ADDRESS',
        dest='read_emails.reader_email_address',
        help='Reader email address (e.g. reader@address.com)')
    return parser


def main():
    try:
        exit_code = 0
        # Parse command-line arguments
        parser = setup_argparser()
        args = parser.parse_args()
        main_cfg = argparse.Namespace(**get_config_dict('main', PROJECT_DIR))
        # Override configuration dict with command-line arguments
        returned_values = override_config_with_args(main_cfg, args)
        setup_log(package='cryptlib',
                  script_name=prog_name(__file__),
                  log_filepath=LOGGING_PATH,
                  quiet=main_cfg.quiet,
                  verbose=main_cfg.verbose,
                  logging_level=main_cfg.logging_level,
                  logging_formatter=main_cfg.logging_formatter)
        process_returned_values(returned_values)
        if main_cfg.uninstall:
            logger.info('Uninstalling program ...')
        else:
            exit_code = CryptoEmail(main_cfg).run()
    except KeyboardInterrupt:
        logger.debug('Ctrl+c detected!')
        exit_code = 2
    return exit_code


if __name__ == '__main__':
    exit_code = main()
    logger.info('Exiting with code {}'.format(exit_code))
    sys.exit(exit_code)
