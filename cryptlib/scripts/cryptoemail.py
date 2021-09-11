#!/usr/bin/env python
import base64
import getpass
import re
import readline
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

CONNECTIONS = {'tokens': 'googleapi', 'password': 'smtp_imap'}


class CryptoEmail:
    def __init__(self, config):
        self.config = config
        self._check_args()
        self._check_config(self.config.__dict__)
        self._check_gnupghome(self.config.homedir)
        self.subject = ''
        self.original_message_text = ''
        self.tester = Tester()
        self._missing_data = False

    def run(self):
        if self.config.interactive:
            self._interact()
        # ===========
        # Subcommands
        # ===========
        try:
            if self.config.subcommand == 'send':
                self._get_message()
                return self._send_email().exit_code
            if self.config.subcommand == 'read':
                return self._read_emails()
        except Exception as e:
            self._log_error(e)
            return 1
        if self.config.subcommand == 'test':
            if self.config.run_tests:
                self._run_tests()
            else:
                if self.config.args_test_encryption:
                    self._test_encryption(self.config.test_message)
                if self.config.args_test_signature:
                    self._test_signature(self.config.test_message)
                if self.config.args_test_connection:
                    self._test_connection(self.config.args_test_connection)
            if self.tester.n_tests:
                logger.info(blue('### Test results ###'))
                logger.info('Success rate: {}/{} = {}%'.format(
                    self.tester.n_success, self.tester.n_tests,
                    int(self.tester.success_rate * 100)))
                logger.info('')
                success_msg = ''
                fail_msg = ''
                for test_name, result in self.tester.report.items():
                    if result.exit_code == 0:
                        success_msg += f'- {test_name}\n'
                    elif result.exit_code > 0:
                        fail_msg += f'- {test_name}: {result.error_msg.splitlines()[0]}\n'
                if fail_msg:
                    success_msg = success_msg.strip()
                if success_msg:
                    logger.info(f"{green('Successful tests:')}\n{success_msg}")
                if fail_msg:
                    logger.info(f"{red('Failed tests:')}\n{fail_msg}")
            else:
                logger.info('No tests!')
        return 0

    def _check_args(self):
        logger.debug('Checking args ...')
        if getattr(self.config, 'unencrypt', None):
            logger.debug('enable_encryption = False')
            self.config.send_emails['encrypt']['enable_encryption'] = False
        else:
            logger.debug('enable_encryption = True')
            self.config.send_emails['encrypt']['enable_encryption'] = True
        if getattr(self.config, 'sign', None):
            logger.debug('enable_signature = True')
            self.config.send_emails['sign']['enable_signature'] = True
            self.config.send_emails['sign']['signature'] = self.config.sign
        if self.config.verbose:
            logger.debug('logging_level = True')
            self.config.logging_level = 'debug'
        opts = ['run_tests', 'args_test_encryption', 'args_test_connection',
                'args_test_signature']
        for opt in opts:
            if getattr(self.config, opt, None) is None:
                logger.debug(f'{opt} = None')
                setattr(self.config, opt, None)

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
        recipient = self.config.send_emails['encrypt']['recipient_userid']
        # TODO: remove following line
        # gpg --full-generate-key --expert --homedir

        def encrypt_using_gpg(msg):
            start = 'Signing and encrypting' if sign else 'Encrypting'
            logger.info("{} the message (recipient='{}') "
                        "...".format(start, recipient))
            passphrase = None
            if sign:
                passphrase = get_gpg_passphrase(
                    prompt=self.config.prompt_passwords,
                    gpg=gpg,
                    recipient=recipient,
                    message='Enter your GPG passphrase for signing')
            return gpg.encrypt(msg, recipient, sign=sign, passphrase=passphrase)

        encryption_program = config['encrypt'].get('program')
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
            if self._fingerprint_exists(recipient, gpg):
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

    @staticmethod
    def _fingerprint_exists(fingerprint, gpg):
        logger.debug("Checking fingerprint='{}' ...".format(fingerprint))
        if fingerprint not in gpg.list_keys().fingerprints:
            logger.debug("The fingerprint='{}' was not found in the "
                         "keyring".format(fingerprint))
            return 0
        return 1

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
        if self.config.connection_method == 'googleapi':
            if self.subject.startswith('Subject:'):
                logger.debug(f"Removing 'Subject:' from '{self.subject}'")
                self.subject = self.subject[len('Subject:'):].strip()

    def _input(self, prompt, values=None, lower=False, is_path=False,
               is_userid=False, is_address=False, is_server=False):
        if not self._missing_data:
            print('\nEnter the following data')
            self._missing_data = True
        while True:
            ans = input(prompt)
            ans = ans.lower() if lower else ans
            if values:
                if ans in values:
                    return ans
                else:
                    print('Invalid value!')
            elif is_path:
                ans = os.path.expanduser(ans)
                if os.path.exists(ans):
                    return ans
                else:
                    print("Path doesn't exist!")
            elif is_userid:
                if os.path.exists(self.config.homedir):
                    gpg = gnupg.GPG(gnupghome=self.config.homedir)
                    if self._fingerprint_exists(ans, gpg):
                        return ans
                    else:
                        print("userid not found!")
                else:
                    return ans
            elif is_address:
                if self._is_valid_email(ans):
                    return ans
                else:
                    print("Invalid address!")
            elif is_server:
                if self._is_valid_servername(ans):
                    return ans
                else:
                    print("Invalid server name!")

    def _interact(self):
        if (self.config.run_tests and (self.config.test_encryption or self.config.test_signature)) or \
                self.config.args_test_encryption or self.config.args_test_signature \
                or self.config.subcommand in ['send', 'read']:
            if self.config.subcommand == 'send' and \
                    (not self.config.send_emails['encrypt']['enable_encryption']
                     or not self.config.send_emails['sign']['enable_signature']):
                logger.debug('homedir not necessary')
            elif self.config.homedir == default_config.homedir:
                self.config.homedir = self._input('homedir: ', is_path=True)
        if (self.config.run_tests and self.config.test_encryption) or self.config.args_test_encryption or \
                (self.config.subcommand == 'send' and self.config.send_emails['encrypt']['enable_encryption']):
            if self.config.send_emails['encrypt']['recipient_userid'] == \
                    default_config.send_emails['encrypt']['recipient_userid']:
                self.config.send_emails['encrypt']['recipient_userid'] = self._input('recipient_userid: ', is_userid=True)
        if ((self.config.run_tests and self.config.test_signature) or self.config.args_test_signature or
                (self.config.subcommand == 'send' and self.config.send_emails['sign']['enable_signature'])):
            if self.config.send_emails['sign']['signature'] == default_config.send_emails['sign']['signature']:
                self.config.send_emails['sign']['signature'] = self._input('signature: ', is_userid=True)
        if (self.config.run_tests and self.config.test_connection) or \
                self.config.args_test_connection or self.config.subcommand in ['send', 'read']:
            if self.config.mailbox_address == default_config.mailbox_address:
                self.config.mailbox_address = self._input('mailbox_address: ', is_address=True)
            if ((self.config.subcommand in ['send', 'read']) and self.config.connection_method == 'googleapi') \
                    or (self.config.run_tests and
                        self.config.test_connection == 'googleapi') or \
                    self.config.args_test_connection == 'googleapi':
                if self.config.googleapi['credentials_path'] \
                        == default_config.googleapi['credentials_path']:
                    self.config.googleapi['credentials_path'] = \
                        self._input('credentials_path: ', is_path=True)
            if (self.config.subcommand == 'send' and self.config.connection_method == 'smtp_imap')  \
                    or (self.config.run_tests and
                        self.config.test_connection == 'smtp_imap') or \
                    self.config.args_test_connection == 'smtp_imap':
                if self.config.smtp_imap['smtp_server'] \
                        == default_config.smtp_imap['smtp_server']:
                    self.config.smtp_imap['smtp_server'] = \
                        self._input('smtp_server: ', is_server=True)
            if self.config.subcommand == 'read' and self.config.connection_method == 'smtp_imap':
                if self.config.smtp_imap['imap_server'] \
                        == default_config.smtp_imap['imap_server']:
                    self.config.smtp_imap['imap_server'] = \
                        self._input('imap_server: ', is_server=True)
            if self.config.subcommand == 'send':
                if self.config.send_emails['receiver_email_address'] \
                        == default_config.send_emails['receiver_email_address']:
                    self.config.send_emails['receiver_email_address'] = \
                        self._input('(Receiver) email_address: ', is_address=True)
        if self._missing_data:
            print('')
            self._missing_data = False

    @staticmethod
    def _is_valid_email(email):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.fullmatch(regex, email):
            return 1
        else:
            return 0

    @staticmethod
    def _is_valid_servername(servername):
        regex = r'\b(smtp|imap)\.[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.fullmatch(regex, servername):
            return 1
        else:
            return 0

    def _log_error(self, error, nl=False):
        if self.config.verbose:
            error_msg = f'{traceback.format_exc()}'.strip()
        else:
            error_msg = red(error.__str__())
        if nl:
            error_msg = error_msg + '\n'
        logger.error(red(f'{error_msg}'))

    def _login_stmp(self, server, password):
        result = Result()
        context = ssl.create_default_context()
        server.ehlo()  # Can be omitted
        server.starttls(context=context)
        server.ehlo()  # Can be omitted
        # Success: (235, b'2.7.0 Accepted')
        # Fail (printed): *** smtplib.SMTPAuthenticationError: (535, b'5.7.8 Username and Password not accepted.
        try:
            server.login(self.config.mailbox_address, password)
            del password
        except smtplib.SMTPAuthenticationError as e:
            error_msg = "Login to '{}' failed".format(
                self.config.mailbox_address)
            logger.warning(yellow(error_msg))
            self._log_error(e, nl=True)
            return result.set_error(error_msg)
        else:
            return 0

    def _read_emails(self):
        logger.info('Reading emails ...')
        return 0

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
        if config['encrypt']['recipient_userid'] \
                == config['sign']['signature'] \
                and config['encrypt']['enable_encryption'] \
                and config['sign']['enable_signature']:
            logger.warning('Signing with the same encryption key. Both '
                           'encryption and signature fingerprints are the same')
        if not config['sign']['enable_signature']:
            logger.info("No signature will be applied on the email")
        elif config['sign']['enable_signature'] and \
                (not config['use_single_pass']
                 or not config['encrypt']['enable_encryption']):
            try:
                signed_message = self._sign_message(message_text)
                message_text = str(signed_message)
            except ValueError as e:
                error_msg = "The email couldn't be signed with the program " \
                            "{}\n{}\n".format(config['sign']['program'], e)
                logger.error(error_msg)
                return result.set_error(error_msg)
        elif config['sign']['enable_signature'] and \
                config['encrypt']['enable_encryption'] \
                and config['use_single_pass']:
            sign = config['sign']['signature']
        if config['encrypt']['enable_encryption']:
            try:
                encrypted_message = self._encrypt_message(message_text, sign)
                message_text = str(encrypted_message)
            except ValueError as e:
                error_msg = "The email couldn't be encrypted with the " \
                            "program {}\n{}\n".format(
                                config['encrypt']['program'], e)
                logger.error(error_msg)
                return result.set_error(error_msg)
        else:
            logger.info('No encryption will be applied on the email')
        # Connect to the email provider server and send the encrypted email
        logger.info(f"sender email address: "
                    f"{self.config.mailbox_address}")
        logger.info(f"receiver email address: "
                    f"{self.config.send_emails['receiver_email_address']}")
        if self.config.connection_method == 'googleapi':
            return self._send_email_with_tokens(message_text)
        else:
            return self._send_email_with_password(message_text)

    def _send_email_with_password(self, message_text):
        config = self.config.send_emails
        connection_type = self.config.connection_method
        smtp_config = getattr(self.config, connection_type)
        logger.info(f"Connecting to the email server with 'smtp'")
        logger.debug('Logging to the smtp server using a PASSWORD (less '
                     'secure than with TOKENS)')
        result = Result()
        message = """\
{}

{}""".format(self.subject, message_text)
        password = self._get_email_password(self.config.mailbox_address,
                                            self.config.prompt_passwords)
        if password is None:
            error_msg = "No email password could be retrieved. Thus, the " \
                        "email can't be sent."
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)
        logger.info('Connecting to the smtp server...')
        with smtplib.SMTP(smtp_config['smtp_server'],
                          smtp_config['smtp_port']) as server:
            retval = self._login_stmp(server, password)
            if retval:
                return retval
            # Success: {}
            # Fail (printed): *** smtplib.SMTPServerDisconnected: please run connect() first
            logger.debug('Message to be sent to {}:\n{}'.format(
                config['receiver_email_address'], message))
            logger.info('Sending email...')
            server.sendmail(self.config.mailbox_address,
                            config['receiver_email_address'], message)
            logger.info('Message sent!\n')
        return result.set_success()

    def _send_email_with_tokens(self, message_text):
        result = Result()
        connection_type = self.config.connection_method
        auth_config = getattr(self.config, connection_type)
        service = self._connect_with_tokens(
            email_account=self.config.mailbox_address,
            connection_type=connection_type,
            credentials_path=auth_config['credentials_path'],
            scopes=auth_config['scopes_for_sending'])
        # Call the Gmail API
        msg = create_message(self.config.mailbox_address,
                             self.config.send_emails['receiver_email_address'],
                             self.subject, message_text)
        logger.debug("Message to be sent to "
                     f"{self.config.send_emails['receiver_email_address']}:\n"
                     f"Subject: {self.subject}\n\n{message_text}")
        logger.info('Sending email...')
        result_send = send_message(
            service, self.config.mailbox_address, msg)
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
        if config['sign']['program'] == 'GPG':
            logger.info("Signing message (signature='{}') ...".format(
                config['sign']['signature']))
        else:
            error_msg = "Signature program not supported: " \
                        "{}\n".format(config['sign']['program'])
            raise ValueError(error_msg)
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        passphrase = get_gpg_passphrase(
            prompt=self.config.prompt_passwords,
            gpg=gpg,
            recipient=config['sign']['signature'],
            message="Enter your GPG passphrase for signing with fingerprint="
                    f"'{config['sign']['signature']}'")
        message = gpg.sign(message_text,
                           keyid=config['sign']['signature'],
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
                    self._log_error(e, nl=True)
                    result.set_error(e.__str__())
                self.tester.update_report(test_type=test_type, result=result)
                return result
            return wrapped_function
        return update_decorator

    @_update_report('testing connection')
    def _test_connection(self, connection):
        logger.info(blue(f"### Test connection with '{connection}' ###"))
        result = Result()
        if connection == CONNECTIONS['tokens']:
            self.config.connection_method = connection
            connection_type = self.config.connection_method
            auth_config = getattr(self.config, connection_type)
            service = self._connect_with_tokens(
                email_account=self.config.mailbox_address,
                connection_type=connection_type,
                credentials_path=auth_config['credentials_path'],
                scopes=auth_config['scopes_for_sending'])
            logger.debug("Scopes: "
                         f"{service._rootDesc['auth']['oauth2']['scopes']['https://mail.google.com/']['description']}")
        elif connection == CONNECTIONS['password']:
            self.config.connection_method = self.config.smtp_imap
            smtp_config = self.config.connection_method
            password = self._get_email_password(
                self.config.mailbox_address,
                self.config.prompt_passwords)
            logger.info(f"Connecting to the smtp server '{smtp_config['smtp_server']}'...")
            with smtplib.SMTP(smtp_config['smtp_server'],
                              smtp_config['smtp_port']) as server:
                retval = self._login_stmp(server, password)
                result = retval if retval else result
        else:
            error_msg = f'Connection method not supported: {connection}\n'
            result.set_error(error_msg)
            logger.error(red(error_msg))
        if not result.exit_code:
            logger.info(green('Connection successful!\n'))
            result.set_success()
        return result

    @_update_report('testing encryption/decryption')
    def _test_encryption(self, plaintext_message):
        logger.info(blue('### Test encryption/decryption ###'))
        result = Result()
        logger.info('Plaintext message: {}'.format(plaintext_message))
        try:
            encrypted_message = self._encrypt_message(plaintext_message)
        except ValueError as e:
            error_msg = "The message couldn't be encrypted with the " \
                        "program '{}'\n{}\n".format(
                            self.config.send_emails['encrypt']['program'], e)
            logger.error(red(error_msg))
            return result.set_error(error_msg)
        logger.info('')
        logger.info('## Encryption results ##')
        logger.info('ok: {}'.format(encrypted_message.ok))
        logger.info('status: {}'.format(encrypted_message.status))
        logger.debug('stderr:\n{}'.format(encrypted_message.stderr))
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        decrypted_message = gpg.decrypt(str(encrypted_message))
        logger.info('')
        logger.info('## Decryption results ##')
        logger.info('ok: {}'.format(decrypted_message.ok))
        logger.info('status: {}'.format(decrypted_message.status))
        logger.debug('stderr:\n{}'.format(decrypted_message.stderr))
        logger.info('')
        logger.debug('Encrypted message:\n{}'.format(str(encrypted_message)))
        logger.info('Decrypted message: {}'.format(decrypted_message.data.decode()))
        if plaintext_message == decrypted_message.data.decode():
            logger.info(green('Encryption/decryption successful!\n'))
            result.set_success()
        else:
            error_msg = "The message couldn't be decrypted " \
                        "correctly\n{}".format(decrypted_message.stderr)
            logger.error(red(error_msg))
            result.set_error(error_msg)
        return result

    @_update_report('testing signing')
    def _test_signature(self, message):
        logger.info(blue('### Test message signing ###'))
        result = Result()
        logger.info('Message to be signed: {}'.format(message))
        try:
            signed_message = self._sign_message(message)
        except ValueError as e:
            error_msg = "The message couldn't be " \
                        "signed\n{}\n".format(e.__str__().strip())
            logger.error(error_msg)
            result.set_error(error_msg)
            return result
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        verify = gpg.verify(signed_message.data)
        logger.info('')
        logger.info('## Signature results ##')
        logger.info('valid: {}'.format(verify.valid))
        logger.info('status: {}'.format(verify.status))
        logger.debug('stderr:\n{}'.format(verify.stderr))
        logger.info('')
        if verify.fingerprint != self.config.send_emails['sign']['signature']:
            error_msg = 'The fingerprint used for signing ' \
                        f'({verify.fingerprint}) is different from the one in ' \
                        'the config ' \
                        f"({self.config.send_emails['sign']['signature']})\n"
            logger.error(red(error_msg))
            result.set_error(error_msg)
        elif verify.valid:
            logger.info(green('Signing message successful!\n'))
            result.set_success()
        else:
            error_msg = "The message couldn't be " \
                        "signed\n{}\n".format(verify.stderr)
            logger.error(red(error_msg))
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
        # TODO: exit_code >= 1
        self.n_fails += 1 if self.report[test_type].exit_code >= 1 else 0
        self.n_success = self.n_tests - self.n_fails
        self.success_rate = self.n_success / self.n_tests

    def update_report(self, test_type, result):
        self.report.setdefault(test_type, result)
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
        msg = 'Config options overridden by command-line arguments:\n'
        log_opts_overridden(returned_values.config_opts_overridden, msg)
    # Process arguments not found in config file
    if returned_values.args_not_found_in_config:
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


def init_list(list_):
    return [] if list_ is None else list_


class OptionsChecker:
    def __init__(self, add_opts, remove_opts):
        self.add_opts = init_list(add_opts)
        self.remove_opts = init_list(remove_opts)

    def check(self, opt_name):
        return not self.remove_opts.count(opt_name) or \
               self.add_opts.count(opt_name)


def add_connection_options(parser, add_opts=None, remove_opts=None,
                           title='Connection options'):
    checker = OptionsChecker(add_opts, remove_opts)
    connection_group = parser.add_argument_group(title=f"{yellow(title)}")
    connection_group.add_argument(
        '--mailbox', metavar='ADDRESS', dest='mailbox_address',
        help='Mailbox address (e.g. my_email@address.com)')
    if checker.check('conn'):
        connection_group.add_argument(
            '-c', '--connection', metavar='METHOD',
            dest='connection_method', choices=CONNECTIONS.values(),
            help='Connecting to an email server either with tokens '
                 '(`googleapi`) or an email password (`smtp`).')


def add_encryption_options(parser, add_opts=None, remove_opts=None,
                           title='Encryption options'):
    checker = OptionsChecker(add_opts, remove_opts)
    encrypt_group = parser.add_argument_group(f"{yellow('Encryption options')}")
    encrypt_group.add_argument(
        '--recipient', metavar='USER-ID',
        dest='send_emails.encrypt.recipient_userid',
        help="Recipient to be used for encrypting the message.")
    encrypt_group.add_argument(
        '--sign', metavar='USER-ID',
        help="The signature to be applied to the message.")
    if checker.check('unencrypt'):
        encrypt_group.add_argument(
            '-u', '--unencrypt', action='store_true',
            help="Don't encrypt the message.")
    if checker.check('use-single-pass'):
        encrypt_group.add_argument(
            '--usp', '--use-single-pass', action='store_true',
            dest='send_emails.use_single_pass',
            help="Sign and encrypt in a single pass. Otherwise, sign first "
                 "and then encrypt as separate processes.")


# General options
def add_general_options(parser, add_opts=None, remove_opts=None,
                        program_version=cryptlib.__version__,
                        title='General options'):
    checker = OptionsChecker(add_opts, remove_opts)
    parser_general_group = parser.add_argument_group(title=f"{yellow(title)}")
    if checker.check('help'):
        parser_general_group.add_argument('-h', '--help', action='help',
                                          help='Show this help message and exit.')
    if checker.check('version') and False:
        parser_general_group.add_argument(
            '-v', '--version', action='version',
            version=f'{prog_name(__file__)} {program_version}',
            help="Show program's version number and exit.")
    if checker.check('quiet'):
        parser_general_group.add_argument(
            '-q', '--quiet', action='store_true',
            help='Enable quiet mode, i.e. nothing will be printed.')
    if checker.check('verbose'):
        parser_general_group.add_argument(
            '--verbose', action='store_true',
            help='Print various debugging information, e.g. print traceback '
                 'when there is an exception.')
    if checker.check('log-level'):
        parser_general_group.add_argument(
            '-l', '--log-level', dest='logging_level',
            choices=['debug', 'info', 'warning', 'error'],
            help='Set logging level for all loggers. '
                 + default(default_config.logging_level))
    if checker.check('log-format'):
        # TODO: explain each format
        parser_general_group.add_argument(
            '-f', '--log-format', dest='logging_formatter',
            choices=['console', 'simple', 'only_msg'],
            help='Set logging formatter for all loggers. '
                 + default(default_config.logging_formatter))
    if checker.check('homedir'):
        parser_general_group.add_argument(
            '--homedir', metavar='PATH', dest='homedir',
            help='Home directory where encryption keys are saved by the '
                 'encryption program (e.g. GnuPG)')
    if checker.check('interactive'):
        parser_general_group.add_argument(
            '-i', '--interactive', action='store_true',
            help='Prompt the user to enter missing data from the configuration '
                 'file (e.g. mailbox address)')
    if checker.check('prompt_passwords'):
        parser_general_group.add_argument(
            '--pp', '--prompt-passwords', dest='prompt_passwords',
            action='store_true',
            help='Prompt users to enter their email passwords or passphrases.')
    return parser_general_group


def add_googleapi_options(parser, title='googleapi options'):
    googleapi_group = parser.add_argument_group(title=f'{yellow(title)}')
    googleapi_group.add_argument(
        '--creds', '--credentials', metavar='PATH',
        dest='googleapi.credentials_path',
        help="Path to the credentials file (JSON).")
    googleapi_group.add_argument(
        '--ss', '--scopes-sending', metavar='PATH', nargs='*',
        dest='googleapi.scopes_for_sending',
        help="Scopes applied when sending emails from gmail.com "
             + default(default_config.googleapi['scopes_for_sending']))
    googleapi_group.add_argument(
        '--sr', '--scopes-reading', metavar='SCOPE', nargs='*',
        dest='googleapi.scopes_for_reading',
        help="Scopes applied when reading emails from gmail.com "
             + default(default_config.googleapi['scopes_for_reading']))


def add_smtp_imap_options(parser, title='smtp-imap options'):
    smtp_imap_group = parser.add_argument_group(title=f'{yellow(title)}')
    smtp_imap_group.add_argument(
        '--smtp-port', metavar='PORT', type=int,
        dest='smtp_imap.smtp_port',
        help="SMTP port number. " + default(default_config.smtp_imap['smtp_port']))
    smtp_imap_group.add_argument(
        '--imap-port', metavar='PORT', type=int,
        dest='smtp_imap.imap_port',
        help="IMAP port number. " + default(default_config.smtp_imap['imap_port']))
    smtp_imap_group.add_argument(
        '--smtp-server', metavar='NAME',
        dest='smtp_imap.smtp_server',
        help="SMTP server name.")
    smtp_imap_group.add_argument(
        '--imap-server', metavar='NAME',
        dest='smtp_imap.imap_server',
        help="IMAP server name.")


def setup_argparser():
    # Setup the parser
    width = os.get_terminal_size().columns - 5
    parser = argparse.ArgumentParser(
        usage=main_usage(__file__),
        description="Command-line program for sending and reading "
                    "encrypted emails.",
        add_help=False,
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    general_group = parser.add_argument_group(f"{yellow('General options')}")
    general_group.add_argument('-h', '--help', action='help',
                               help='Show this help message and exit.')
    general_group.add_argument(
        '-v', '--version', action='version',
        version=f'{prog_name(__file__)} v{cryptlib.__version__}',
        help="Show program's version number and exit.")
    # ===========
    # Subcommands
    # ===========
    title = f"{yellow('Subcommands')}"
    if sys.version_info >= (3, 7):
        subparsers = parser.add_subparsers(
            title=title, description=None, dest='subcommand', required=True,
            help=None)
    else:
        # No arg 'required' supported for <= 3.6
        # TODO: important, test without subcommand
        subparsers = parser.add_subparsers(
            title=title, description=None, dest='subcommand', help=None)
    # =================
    # Uninstall options
    # =================
    # create the parser for the "uninstall" command
    subcommand = 'uninstall'
    desc = "Uninstall the `package` (including the program " \
           f"'{prog_name(__file__)}') or `everything` (including config and " \
           "log files)."
    parser_test = subparsers.add_parser(
        subcommand,
        usage=subcomand_usage(__file__, subcommand),
        description=desc,
        add_help=False,
        help='Uninstall the program.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_test, remove_opts=['interactive', 'homedir'])
    parser_uninstall_group = parser_test.add_argument_group(
        title=f"{yellow('Uninstall options')}")
    parser_uninstall_group.add_argument(
        '--uninstall', choices=['package', 'everything'],
        help=desc)
    # ============================
    # Edit cryptoemail config file
    # ============================
    # create the parser for the "edit" command
    subcommand = 'edit'
    parser_test = subparsers.add_parser(
        subcommand,
        usage=subcomand_usage(__file__, subcommand),
        description='Edit or reset the configuration file.',
        add_help=False,
        help='Edit/reset the configuration file.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_test, remove_opts=['interactive', 'homedir'])
    parser_edit_group = parser_test.add_argument_group(
        title=f"{yellow('Edit/reset options')}")
    edit_mutual_group = parser_edit_group.add_mutually_exclusive_group()
    edit_mutual_group.add_argument(
        '-e', '--edit', action='store_true',
        help=f'Edit the {prog_name(__file__)} configuration file.')
    edit_mutual_group.add_argument(
        '-a', '--app', dest='app',
        help='Name of the application to use for editing the '
             f'{prog_name(__file__)} configuration file. If no name is given, '
             'then the default application for opening this type of file (.py) '
             'will be used.')
    edit_mutual_group.add_argument(
        '--reset', action='store_true',
        help=f'Reset the {prog_name(__file__)} configuration file to factory values.')
    # ===============
    # Testing options
    # ===============
    # create the parser for the "test" command
    subcommand = 'test'
    parser_test = subparsers.add_parser(
        subcommand,
        usage=subcomand_usage(__file__, subcommand),
        description='Run tests as defined in the config file.',
        add_help=False,
        help='Run tests.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_test)
    add_connection_options(parser_test, remove_opts=['conn'])
    add_googleapi_options(parser_test)
    add_smtp_imap_options(parser_test)
    add_encryption_options(parser_test, remove_opts=['unencrypt'])
    parser_test_group = parser_test.add_argument_group(title=f"{yellow('Test options')}")
    parser_test_group.add_argument(
        '-r', '--run-tests', dest='run_tests', action='store_true',
        help='Run a set of tests as defined in the config file.')
    parser_test_group.add_argument(
        '-e', '--encryption', dest='args_test_encryption',
        action='store_true',
        help='Test encrypting and decrypting a message. The encryption program '
             'used (e.g. GPG) is the one defined in the config file.')
    parser_test_group.add_argument(
        '-s', '--signature', dest='args_test_signature',
        action='store_true', help='Test signing a message.')
    parser_test_group.add_argument(
        '-m', '--message', metavar='MESSAGE', dest='test_message',
        default=default_config.test_message,
        help='Message to be used for testing encryption or signing. '
             + default(default_config.test_message))
    parser_test_group.add_argument(
        '-c', '--connection', metavar='METHOD',
        dest='args_test_connection', choices=CONNECTIONS.values(),
        help="Test connecting to an email server either with tokens "
             f"(`{CONNECTIONS['tokens']}`) or an email password "
             f"(`{CONNECTIONS['password']}`).")
    # ===================
    # Send emails options
    # ===================
    # create the parser for the "send" command
    subcommand = 'send'
    parser_send = subparsers.add_parser(
        subcommand,
        usage=subcomand_usage(__file__, subcommand),
        description='Send a signed and/or encrypted email.',
        add_help=False,
        help='Send an encrypted email.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_send)
    add_connection_options(parser_send)
    add_googleapi_options(parser_send)
    add_smtp_imap_options(parser_send)
    add_encryption_options(parser_send)
    parser_send_group = parser_send.add_argument_group(title=f"{yellow('Send options')}")
    parser_send_group.add_argument('-m', '--email-message', metavar='STRING', nargs=2,
                                   help='The email subject and text.')
    parser_send_group.add_argument(
        '-p', '--email-path', metavar='PATH',
        help='Path to a text file containing the email to be sent.')
    parser_send_group.add_argument(
        '-r', '--receiver-email', metavar='ADDRESS',
        dest='send_emails.receiver_email_address',
        help="Receiver's email address (e.g. receiver@address.com)")
    # ===================
    # Read emails options
    # ===================
    # create the parser for the "read" command
    subcommand = 'read'
    parser_read = subparsers.add_parser(
        subcommand,
        usage=subcomand_usage(__file__, subcommand),
        description='Read emails from your inbox which might contain '
                    'unencrypted and encrypted emails.',
        add_help=False,
        help='Read your emails.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_read)
    add_connection_options(parser_read)
    add_googleapi_options(parser_read)
    add_smtp_imap_options(parser_read)
    parser_read_group = parser_send.add_argument_group(title=f"{yellow('Read options')}")
    return parser


def main():
    try:
        exit_code = 0
        # Check project directory
        mkdir(cryptlib.PROJECT_DIR)
        mkdir(cryptlib.LOGS_DIR)
        # Parse command-line arguments
        parser = setup_argparser()
        args = parser.parse_args()
        main_cfg = argparse.Namespace(**get_config_dict('main', cryptlib.PROJECT_DIR))
        # Override configuration dict with command-line arguments
        returned_values = override_config_with_args(main_cfg, get_config_dict('main'), args)
        setup_log(package='cryptlib',
                  script_name=prog_name(__file__),
                  log_filepath=cryptlib.LOGGING_PATH,
                  quiet=main_cfg.quiet,
                  verbose=main_cfg.verbose,
                  logging_level=main_cfg.logging_level,
                  logging_formatter=main_cfg.logging_formatter,
                  handler_names=['console'])
        process_returned_values(returned_values)
        if main_cfg.subcommand == 'uninstall':
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
