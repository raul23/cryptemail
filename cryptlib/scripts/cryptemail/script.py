#!/usr/bin/env python
import readline
import smtplib
import ssl
import time
from functools import wraps
from urllib import parse

import gnupg

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from args import CONNECTIONS, setup_argparser
from cryptlib.configs import default_config, default_logging
from cryptlib.edit import edit_file, reset_file
from cryptlib.utils.genutils import *
from cryptlib.utils.logutils import log_error
from lib import *

# Change logging level for googleapiclient and gnupg loggers
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger('gnupg').setLevel(logging.ERROR)

logger = Logger(__name__, __file__)

# Configuration files within project directory
CONFIG_PATH = os.path.join(cryptlib.__project_dir__, CFG_TYPES['main']['user'])
LOGGING_PATH = os.path.join(cryptlib.__project_dir__, CFG_TYPES['log']['user'])

# The file token.json stores the user's access and refresh tokens, and is
# created automatically when the authorization flow completes for the first
# time.
TOKENS_FILENAME = 'tokens.json'


class InvalidDataError(Exception):
    """Raised if TODO..."""


class CryptEmail:
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
        try:
            self._interact()
            # ==============================
            # Subcommands (excluding 'test')
            # ==============================
            if self.config.subcommand == 'send':
                return self._send_email().exit_code
            if self.config.subcommand == 'read':
                return self._read_emails().exit_code
            if self.config.subcommand == 'update' and self.config.tokens:
                return self._update_token().exit_code
            if self.config.subcommand in ['delete', 'update']:
                return self._delete_or_update_keyring().exit_code
            if self.config.subcommand == 'init':
                return self._initialize().exit_code
        except EOFError:
            raise
        except Exception as e:
            self._log_error(e)
            return 1
        # ================
        # Subcommand: test
        # ================
        if self.config.subcommand == 'test':
            if self.config.run_tests:
                self._run_tests()
            else:
                if self.config.args_test_encryption or \
                    self.config.args_test_signature or \
                        self.config.args_test_connection:
                    logger.info(violet('Starting tests ...\n'))
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
                success_msg = []
                fail_msg = []
                for test_name, result in self.tester.report.items():
                    if result.exit_code == 0:
                        success_msg.append(f'- {test_name}')
                    elif result.exit_code > 0:
                        fail_msg.append(f'- {test_name}: {result.error_msg.splitlines()[0]}')
                if fail_msg:
                    msg = fail_msg[-1]
                    fail_msg[-1] = msg + '\n'
                elif success_msg:
                    msg = success_msg[-1]
                    success_msg[-1] = msg + '\n'
                if success_msg:
                    logger.info(green('Successful tests:'))
                    for m in success_msg:
                        logger.info(m)
                if fail_msg:
                    logger.info(red('Failed tests:'))
                    for m in fail_msg:
                        logger.info(m)
            else:
                logger.warning(yellow('No tests!'))
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
        if getattr(self.config, 'args_test_encryption', None) is not None or \
                not getattr(self.config, 'test_encryption', None):
            if not self.config.run_tests:
                self.config.send_emails['encrypt']['recipient_userid'] = \
                    self.config.args_test_encryption
            logger.debug(
                "recipient_userid = "
                f"{self.config.send_emails['encrypt']['recipient_userid']}")
        if getattr(self.config, 'args_test_signature', None) is not None or \
                not getattr(self.config, 'test_signature', None):
            if not self.config.run_tests:
                self.config.send_emails['sign']['signature'] = \
                    self.config.args_test_signature
            logger.debug(
                "signature = "
                f"{self.config.send_emails['sign']['signature']}")
        if getattr(self.config, 'args_test_connection', None) is not None or \
                getattr(self.config, 'test_connection', None) is not None:
            if getattr(self.config, 'run_tests', None) is True:
                self.config.connection_method = self.config.test_connection
            elif getattr(self.config, 'args_test_connection', None) is not None:
                self.config.connection_method = self.config.args_test_connection
            logger.debug(f'connection_method = {self.config.connection_method}')
        attrs = ['args_test_encryption', 'args_test_connection',
                 'args_test_signature']
        if getattr(self.config, 'run_tests', None) is True and \
                (getattr(self.config, 'args_test_encryption', None) is not None or
                 getattr(self.config, 'args_test_connection', None) is not None or
                 getattr(self.config, 'args_test_signature', None) is not None):
            logger.warning(yellow('Only tests from the config file will be '
                                  'executed!'))
            # Set all attributes in `attrs` to None
            self._setattrs(attrs, None)
        attrs.extend(['run_tests', 'tokens_dirpath'])
        self._create_attrs(attrs)

    def _create_attrs(self, attrs):
        for attr in attrs:
            # If attr doesn't exist, create it and set it to None
            if getattr(self.config, attr, 'not_found') == 'not_found':
                logger.debug(f'{attr} = None')
                setattr(self.config, attr, None)

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
            logger.warning(yellow('gnupghome is None and will thus take '
                                  'whatever gpg defaults to (e.g. ~/.gnupg)'))

    @staticmethod
    def _check_subject_and_text(subject, text):
        if (subject.startswith('Subject:') and not subject.strip('Subject:')) \
                or not subject:
            logger.warning(yellow('Message subject is empty'))
        if not text:
            error_msg = 'No message text given'
            raise ValueError(error_msg)

    @staticmethod
    def _connect_with_tokens(email_account, connection_type, credentials_path,
                             scopes, check_domain=True):
        logger.info(f"Connecting to the email server with '{connection_type}'")
        logger.debug('Logging to the email server using TOKENS (more secure than '
                     'with PASSWORD)')
        domain = parse.splituser(email_account)[1]
        if check_domain and domain != 'gmail.com':
            error_msg = f"The email domain is invalid: '{domain}'. " \
                        "Only 'gmail.com' addresses are supported when using " \
                        "TOKEN-based authentication"
            raise ValueError(error_msg)
        if not os.path.exists(credentials_path):
            error_msg = "The directory path containing the credentials " \
                        f"doesn't exist: {credentials_path}"
            raise ValueError(error_msg)
        creds = None
        dirname = os.path.dirname(credentials_path)
        tokens_path = os.path.join(dirname, TOKENS_FILENAME)
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

    def _delete_account_from_keyring(self):
        result = Result()
        if self.config.email_account:
            service = KEYRING_SERVICE_EMAIL_PASS
            account = 'email'
            enter_pass_msg = 'Enter the email password'
            prompt = 'Email password (will not be echoed): '
            prompt_verify = 'Verify password (will not be echoed): '
        else:
            service = KEYRING_SERVICE_GPG_PASS
            enter_pass_msg = 'Enter the GPG passphrase'
            account = 'GPG'
            prompt = 'GPG passphrase (will not be echoed): '
            prompt_verify = 'Verify GPG passphrase (will not be echoed): '
        success_msg = 'Account deleted!'
        password1 = keyring.get_password(service, self.config.username)
        if not password1:
            error_msg = f"Couldn't find the {account} account with username " \
                        f"{bold(self.config.username)} in the keyring"
            self._log_error(error_msg)
            return result.set_error(error_msg)
        print(blue(enter_pass_msg))
        password2 = prompt_password(prompt, prompt_verify, newline=True)
        if password1 != password2:
            error_msg = "Password isn't valid!"
            print()
            self._log_error(error_msg)
            return result.set_error(error_msg)
        print()
        keyring.delete_password(service, self.config.username)
        logger.info(green(success_msg))
        time.sleep(0.5)
        result.set_success()
        return result

    def _delete_or_update_keyring(self):
        if not self.config.username:
            error_msg = 'The following arguments are required: -u/--username'
            logger.error(red(error_msg))
            return Result().set_error(error_msg)
        if self.config.subcommand == 'delete':
            email_arg = self.config.email_account
            gpg_arg = self.config.gpg_account
            op_func = self._delete_account_from_keyring
        else:
            email_arg = self.config.email_password
            gpg_arg = self.config.gpg_passphrase
            op_func = self._update_keyring
        ans = None
        if not email_arg and not gpg_arg:
            if self.config.subcommand == 'delete':
                print(blue('What kind of account do you want to delete in the keyring?'))
                print(blue('(1) Email account\n(2) GPG account'))
            else:
                print(blue('What do you want to update in the keyring?'))
                print(blue('(1) Email password\n(2) GPG passphrase'))
            ans = self._input('Choice', values=['1', '2'])
            print()
            if ans == '1':
                email_arg = True
                if self.config.subcommand == 'delete':
                    self.config.email_account = True
                else:
                    self.config.email_password = True
            else:
                gpg_arg = True
                if self.config.subcommand == 'delete':
                    self.config.gpg_account = True
                else:
                    self.config.gpg_passphrase = True
        account = violet(self.config.username)
        if email_arg:
            if self.config.subcommand == 'delete':
                logger.info(f'Delete the email account {account}')
            else:
                logger.info(f'Update the email password for the username {account}')
        else:
            if self.config.subcommand == 'delete':
                logger.info(f'Delete the GPG account {account}')
            else:
                logger.info(f'Update the GPG passphrase for the account {account}')
        if ans:
            time.sleep(0.5)
        print()
        return op_func()

    def _encrypt_message(self, unencrypted_msg, sign=None):
        config = self.config.send_emails
        recipient = self.config.send_emails['encrypt']['recipient_userid']
        # TODO: remove following line
        # gpg --full-generate-key --expert --homedir

        def encrypt_using_gpg(msg):
            start = 'Signing and encrypting' if sign else 'Encrypting'
            logger.info(f"{start} the message (recipient='{bold(recipient)}') "
                        "...")
            passphrase = None
            cred = None
            if sign:
                passphrase, cred = get_gpg_passphrase(
                    prompt=self.config.prompt_passwords,
                    gpg=gpg,
                    fingerprint=config['sign']['signature'],
                    message=blue("Enter your GPG passphrase for signing with "
                                 f"fingerprint {bold(config['sign']['signature'])}"))
            enc = gpg.encrypt(msg, recipient, sign=sign, passphrase=passphrase)
            return enc, cred

        encryption_program = config['encrypt'].get('program')
        if encryption_program in ['GPG']:
            logger.debug("Encrypting the message with the encryption program "
                         f"'{encryption_program}'")
        elif encryption_program is None:
            raise ValueError("Encryption program missing")
        else:
            error_msg = f"'{encryption_program}' is not supported as an " \
                        "encryption program"
            raise ValueError(error_msg)
        if encryption_program == 'GPG':
            gpg = gnupg.GPG(gnupghome=self.config.homedir)
            credential = None
            if self._fingerprint_exists(recipient, gpg):
                encrypted_msg, credential = encrypt_using_gpg(unencrypted_msg)
                status = encrypted_msg.status
                stderr = encrypted_msg.stderr.strip()
            else:
                encrypted_msg = ''
                status = 'invalid recipient'
                stderr = f"The recipient '{recipient}' was not found in the " \
                         "keyring"
            if status == 'encryption ok':
                logger.info('Message encrypted')
                update_gpg_pass(credential, success=True)
            else:
                # case: invalid password entered twice
                update_gpg_pass(credential, success=False)
                error_msg = f"Status from encrypt(): {status}\n" \
                            f"{stderr}"
                # TODO: important, another exception type?
                raise ValueError(error_msg)
            # gpg.list_keys()
            # gpg.delete_keys()
        else:
            raise NotImplementedError('Only GPG supported!')
        return encrypted_msg

    @staticmethod
    def _fingerprint_exists(fingerprint, gpg):
        logger.debug(f"Checking fingerprint {bold(fingerprint)} ...")
        if fingerprint not in gpg.list_keys().fingerprints:
            logger.debug(f"The fingerprint {bold(fingerprint)} was not found in "
                         "the keyring")
            return 0
        return 1

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
                logger.info(f'Subject line:\n{self.subject}')
                error_msg = "The subject line should start with 'Subject:'"
                raise ValueError(error_msg)
            self.original_message_text = '\n'.join(lines[2:])
            # Check email message text
            if not lines[1] == '':
                logger.info(f'Email message content:\n{email_message}')
                error_msg = "Empty line missing after the 'Subject:' line"
                raise ValueError(error_msg)
        # Remove "Subject:" if connecting to email server with googlapi
        if self.config.connection_method == 'googleapi':
            if self.subject.startswith('Subject:'):
                logger.debug(f"Removing 'Subject:' from '{self.subject}'")
                self.subject = self.subject[len('Subject:'):].strip()

    def _initialize(self):
        logger.info('Initialize the config file ...')
        result = Result()
        default_cfg_fp = get_main_config_filepath(default_config=True)
        user_cfg_fp = get_main_config_filepath(configs_dirpath=cryptlib.__project_dir__)
        default_content = read(default_cfg_fp)
        user_content = read(user_cfg_fp)
        regex_template = r"(FIELD_NAME[\s]*[=|:]{1})[\s]*(FIELD_VALUE)"
        regex = '([# ]*)' + regex_template
        regex = regex.replace('FIELD_NAME', "[A-Za-z0-9_']+").replace('FIELD_VALUE', "'WRITEME:[\s]*[A-Za-z0-9_@.\/']+")
        matches = re.finditer(regex, default_content, re.MULTILINE)
        # ipdb.set_trace()
        print(blue("\nEnter the following data. To skip a field, just press "
                   f"{bold('<Enter>')}\n"))
        for matchNum, match in enumerate(matches, start=1):
            if match.group().startswith('#'):
                # Skip comment line
                continue
            elif match.group().find('emails_dirpath') != -1:
                continue
            pos = match.start() - 2
            comment_line = ''
            while True:
                if pos == -1:
                    error_msg = 'pos=-1: No comment found associated with ' \
                                f'he field data {bold(match.group().strip())}'
                    self._log_error(error_msg)
                    return result.set_error(error_msg)
                char = default_content[pos]
                if char == '\n':
                    comment_line = default_content[pos:match.start()]
                    if '# ' in comment_line:
                        comment_line = comment_line.strip().split('# ')[1]
                        break
                    else:
                        error_msg = 'No comment found associated with the ' \
                                    f'field data {bold(match.group().strip())}'
                        self._log_error(error_msg)
                        return result.set_error(error_msg)
                        # TODO: raise (gives you a traceback) or self._log_error()? and other places
                        # raise ValueError(error_msg)
                else:
                    pos -= 1
                    continue
            for groupNum in range(0, len(match.groups())):
                groupNum = groupNum + 1
                group = match.group(groupNum)
                if not group:
                    continue
                if groupNum == 2:
                    print(yellow(comment_line))
                    field_name = group.replace("'", '').replace(':', '').replace('=', '').strip()
                    field_value = self._input(field_name,
                                              auto_check=True, skip=True)
                    if field_value:
                        # TODO: assume only strings as values
                        field_value = f"'{field_value}'"
                        if match.group().split(field_name)[1].strip().startswith('='):
                            sep = ' ='
                        else:
                            sep = ':'
                            field_name = f"'{field_name}'"
                            field_value += ','
                        regex = regex_template.replace('FIELD_NAME', field_name).replace('FIELD_VALUE', '.+')
                        new_field = f"{field_name}{sep} {field_value}"
                        user_content = re.sub(regex, new_field, user_content)
                    else:
                        print(violet('Skipped field!'))
                    print()
        write(user_cfg_fp, user_content)
        return result.set_success()

    def _input(self, opt_name, values=None, lower=False, is_path=False,
               is_userid=False, is_address=False, is_server=False,
               auto_check=True, skip=False):
        def invalid(msg):
            return red(msg)

        if auto_check:
            if 'path' in opt_name or 'homedir' in opt_name:
                is_path = True
            elif opt_name in ['signature']:
                is_userid = True
            elif 'address' in opt_name:
                is_address = True
            elif 'server' in opt_name:
                is_server = True
        while True:
            ans = input(f'{opt_name}: ')
            ans = ans.lower() if lower else ans
            ans = ans.strip()
            if skip and not ans:
                return ans
            elif values:
                if ans in values:
                    return ans
                else:
                    print(invalid('Invalid value!'))
            elif is_path:
                ans = os.path.expanduser(ans)
                if os.path.exists(ans):
                    return ans
                else:
                    print(invalid("Path doesn't exist!"))
            elif is_userid:
                if os.path.exists(self.config.homedir):
                    gpg = gnupg.GPG(gnupghome=self.config.homedir)
                    if self._fingerprint_exists(ans, gpg):
                        return ans
                    else:
                        print(invalid("userid not found!"))
                else:
                    return ans
            elif is_address:
                if self._is_valid_email(ans):
                    return ans
                else:
                    print(invalid("Invalid address!"))
            elif is_server:
                if self._is_valid_servername(ans):
                    return ans
                else:
                    print(invalid("Invalid server name!"))
            else:
                return ans

    def _input_missing_data(self, opt_name, opt_value=None, values=None,
                            lower=False, is_path=False, is_userid=False,
                            is_address=False, is_server=False):
        if not self.config.interactive:
            if opt_value is None:
                raise ValueError('opt_value is None')
            error_msg = f'invalid data => {opt_name}={opt_value}'
            raise InvalidDataError(error_msg)
        if not self._missing_data:
            print(blue('\nEnter the following data'))
            self._missing_data = True
        return self._input(opt_name, values, lower, is_path, is_userid,
                           is_address, is_server)

    def _interact(self):
        if (self.config.run_tests and (self.config.test_encryption or self.config.test_signature)) or \
                self.config.args_test_encryption or self.config.args_test_signature \
                or self.config.subcommand in ['send', 'read']:
            if self.config.subcommand == 'send' and \
                    (not self.config.send_emails['encrypt']['enable_encryption']
                     or not self.config.send_emails['sign']['enable_signature']):
                logger.debug('homedir not necessary')
            elif self.config.homedir == default_config.homedir:
                self.config.homedir = self._input_missing_data('homedir', self.config.homedir, is_path=True)
        if (self.config.run_tests and self.config.test_encryption) or self.config.args_test_encryption or \
                (self.config.subcommand == 'send' and self.config.send_emails['encrypt']['enable_encryption']):
            if self.config.send_emails['encrypt']['recipient_userid'] == \
                    default_config.send_emails['encrypt']['recipient_userid']:
                self.config.send_emails['encrypt']['recipient_userid'] = self._input_missing_data(
                    'recipient_userid',
                    self.config.send_emails['encrypt']['recipient_userid'],
                    is_userid=True)
        if ((self.config.run_tests and self.config.test_signature) or self.config.args_test_signature or
                (self.config.subcommand == 'send' and self.config.send_emails['sign']['enable_signature'])):
            if self.config.send_emails['sign']['signature'] == default_config.send_emails['sign']['signature']:
                self.config.send_emails['sign']['signature'] = self._input_missing_data(
                    'signature',
                    self.config.send_emails['sign']['signature'],
                    is_userid=True)
        test_cond = (self.config.run_tests and self.config.test_connection) or self.config.args_test_connection
        if test_cond or self.config.subcommand in ['send', 'read', 'update']:
            if test_cond and self.config.connection_method == 'googleapi':
                logger.debug("mailbox_address not necessary since just testing "
                             "connection and 'connection_method=googleapi'")
            elif self.config.subcommand != 'update' and \
                    self.config.mailbox_address == default_config.mailbox_address:
                self.config.mailbox_address = self._input_missing_data(
                    'mailbox_address',
                    self.config.mailbox_address,
                    is_address=True)
            if ((self.config.subcommand in ['send', 'read']) and self.config.connection_method == 'googleapi') \
                    or (self.config.run_tests and
                        self.config.test_connection == 'googleapi') or \
                    self.config.args_test_connection == 'googleapi':
                if self.config.googleapi['credentials_path'] \
                        == default_config.googleapi['credentials_path']:
                    self.config.googleapi['credentials_path'] = \
                        self._input_missing_data('credentials_path',
                                                 self.config.googleapi['credentials_path'],
                                                 is_path=True)
            if (self.config.subcommand == 'send' and self.config.connection_method == 'smtp_imap')  \
                    or (self.config.run_tests and
                        self.config.test_connection == 'smtp_imap') or \
                    self.config.args_test_connection == 'smtp_imap':
                if self.config.smtp_imap['smtp_server'] \
                        == default_config.smtp_imap['smtp_server']:
                    self.config.smtp_imap['smtp_server'] = \
                        self._input_missing_data('smtp_server',
                                                 self.config.smtp_imap['smtp_server'],
                                                 is_server=True)
            if self.config.subcommand == 'read' and self.config.connection_method == 'smtp_imap':
                if self.config.smtp_imap['imap_server'] \
                        == default_config.smtp_imap['imap_server']:
                    self.config.smtp_imap['imap_server'] = \
                        self._input_missing_data('imap_server',
                                    self.config.smtp_imap['imap_server'],
                                    is_server=True)
            if self.config.subcommand == 'send':
                if self.config.send_emails['receiver_email_address'] \
                        == default_config.send_emails['receiver_email_address']:
                    self.config.send_emails['receiver_email_address'] = \
                        self._input_missing_data(
                            'receiver_email_address',
                            self.config.send_emails['receiver_email_address'],
                            is_address=True)
        if self._missing_data and self.config.interactive:
            print()
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

    # TODO: change param name from nl to newline?
    def _log_error(self, error, nl=False):
        log_error(logger, error, self.config.verbose, nl)

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
            error_msg = f"Login to '{self.config.mailbox_address}' failed"
            logger.warning(yellow(error_msg))
            self._log_error(e, nl=True)
            return result.set_error(error_msg)
        else:
            return 0

    def _read_emails(self):
        logger.info(blue('### Reading emails ###'))
        result = Result()
        result.set_success()
        return result

    def _run_tests(self):
        logger.info('Running tests from config file ...\n')
        if self.config.test_encryption:
            self._test_encryption(self.config.test_message)
        if self.config.test_signature:
            self._test_signature(self.config.test_message)
        if self.config.test_connection:
            self._test_connection(self.config.test_connection)
        # logger.info('End tests from config file\n')

    def _send_email(self):
        self._get_message()
        self._check_subject_and_text(self.subject, self.original_message_text)
        message_text = self.original_message_text
        config = self.config.send_emails
        result = Result()
        sign = None
        if config['encrypt']['recipient_userid'] \
                == config['sign']['signature'] \
                and config['encrypt']['enable_encryption'] \
                and config['sign']['enable_signature']:
            logger.warning(yellow('Signing with the same encryption key. Both '
                                  'encryption and signature fingerprints are '
                                  'the same'))
        if not config['sign']['enable_signature']:
            logger.warning(yellow('No signature will be applied on the email'))
        elif config['sign']['enable_signature'] and \
                (not config['use_single_pass']
                 or not config['encrypt']['enable_encryption']):
            try:
                signed_message = self._sign_message(message_text)
                message_text = str(signed_message)
            except ValueError as e:
                error_msg = "The email couldn't be signed with the program " \
                            "{}\n{}".format(config['sign']['program'], e)
                logger.error(red(error_msg))
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
                            "program {}\n{}".format(
                                config['encrypt']['program'], e)
                self._log_error(error_msg)
                return result.set_error(error_msg)
        else:
            logger.warning(yellow('No encryption will be applied on the email ...'))
            time.sleep(2)
        # Connect to the email provider server and send the encrypted email
        logger.info("sender email address: "
                    f"{self.config.mailbox_address}")
        logger.info("receiver email address: "
                    f"{self.config.send_emails['receiver_email_address']}")
        if self.config.connection_method == 'googleapi':
            return self._send_email_with_tokens(message_text)
        else:
            return self._send_email_with_password(message_text)

    def _send_email_with_password(self, message_text):
        config = self.config.send_emails
        connection_type = self.config.connection_method
        smtp_config = getattr(self.config, connection_type)
        logger.debug("Connecting to the email server with 'smtp'")
        logger.debug('Logging to the smtp server using a PASSWORD (less '
                     'secure than with TOKENS)')
        result = Result()
        message = """\
{}

{}""".format(self.subject, message_text)
        password, credential = get_email_password(
            self.config.mailbox_address, self.config.prompt_passwords)
        # TODO: remove following, already taken care in get_email_password()
        # i.e., raise ValueError if no password
        """
        if password is None:
            error_msg = "No email password could be retrieved. Thus, the " \
                        "email can't be sent."
            logger.error(error_msg + '\n')
            return result.set_error(error_msg)
        """
        logger.info("Connecting to the smtp server "
                    f"'{smtp_config['smtp_server']}' ...")
        with smtplib.SMTP(smtp_config['smtp_server'],
                          smtp_config['smtp_port']) as server:
            retval = self._login_stmp(server, password)
            if retval:
                if credential:
                    warning_msg = "The email password could not be added in " \
                                  "the keyring for the " \
                                  f"username {bold(credential[1])}\n"
                    logger.warning(yellow(warning_msg))
                return retval
            if credential:
                logger.info(violet('Adding email password in the keyring for '
                                   'the username {bold(credential[1])}'))
                keyring.set_password(*credential)
            # Success: {}
            # Fail (printed): *** smtplib.SMTPServerDisconnected: please run connect() first
            logger.debug("Message to be sent to "
                         f"{config['receiver_email_address']}:\n{message}")
            logger.info('Sending email ...')
            server.sendmail(self.config.mailbox_address,
                            config['receiver_email_address'], message)
            logger.info(green('Message sent!'))
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
        logger.info('Sending email ...')
        result_send = send_message(
            service, self.config.mailbox_address, msg)
        if result_send is None:
            error_msg = "send_message() returned None. Thus, email couldn't " \
                        "be sent"
            self._log_error(error_msg)
            return result.set_error(error_msg)
        elif result_send.get('id') and 'SENT' in result_send.get('labelIds', []):
            logger.info(green('Message sent!'))
            return result.set_success()
        else:
            error_msg = "Couldn't find SENT in labelIds. Thus, message " \
                        f"(ID='{result_send.get('id', 'None')}') couldn't be " \
                        "sent"
            self._log_error(error_msg)
            return result.set_error(error_msg)

    # Set all attributes in `attrs` to value
    def _setattrs(self, attrs, value):
        for attr in attrs:
            logger.debug(f'{attr} = {value}')
            setattr(self.config, attr, value)

    # TODO: provide signature fingerprint as param?
    def _sign_message(self, message_text):
        config = self.config.send_emails
        if config['sign']['program'] == 'GPG':
            logger.info("Signing message (signature="
                        f"'{bold(config['sign']['signature'])}') ...")
        else:
            error_msg = "Signature program not supported: " \
                        f"{config['sign']['program']}\n"
            raise ValueError(error_msg)
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        passphrase, credential = get_gpg_passphrase(
            prompt=self.config.prompt_passwords,
            gpg=gpg,
            fingerprint=config['sign']['signature'],
            message=blue("Enter your GPG passphrase for signing with "
                         f"fingerprint {bold(config['sign']['signature'])}"))
        message = gpg.sign(message_text,
                           keyid=config['sign']['signature'],
                           passphrase=passphrase)
        del passphrase
        if message.status == 'signature created' and \
                message.fingerprint == self.config.send_emails['sign']['signature']:
            logger.info('Message signed')
            update_gpg_pass(credential, success=True)
            return message
        else:
            update_gpg_pass(credential, success=False)
            if message.status == 'signature created' and \
                    message.fingerprint == self.config.send_emails['sign']['signature']:
                error_msg = 'The fingerprint used for signing ' \
                            f'({message.fingerprint}) is different from the ' \
                            'one in the config ' \
                            f"({self.config.send_emails['sign']['signature']})\n"
                raise ValueError(error_msg)
            else:
                error_msg = f"{message.stderr.strip()}\n"
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
        credential = None
        if connection == CONNECTIONS['tokens']:
            self.config.connection_method = connection
            connection_type = self.config.connection_method
            auth_config = getattr(self.config, connection_type)
            service = self._connect_with_tokens(
                email_account=self.config.mailbox_address,
                connection_type=connection_type,
                credentials_path=auth_config['credentials_path'],
                scopes=auth_config['scopes_for_sending'],
                check_domain=False)
            logger.debug("Scopes: "
                         f"{service._rootDesc['auth']['oauth2']['scopes']['https://mail.google.com/']['description']}")
            result.set_success()
        elif connection == CONNECTIONS['password']:
            self.config.connection_method = self.config.smtp_imap
            smtp_config = self.config.connection_method
            password, credential = get_email_password(
                self.config.mailbox_address,
                self.config.prompt_passwords)
            logger.info(f"Connecting to the smtp server '{smtp_config['smtp_server']}' ...")
            with smtplib.SMTP(smtp_config['smtp_server'],
                              smtp_config['smtp_port']) as server:
                retval = self._login_stmp(server, password)
                if retval:
                    result = retval
                else:
                    result.set_success()
        else:
            error_msg = f'Connection method not supported: {connection}\n'
            result.set_error(error_msg)
            logger.error(red(error_msg))
        if result.exit_code == 0:
            if credential:
                logger.info(violet('Adding email password in the keyring for '
                                   f'the username {bold(credential[1])}'))
                keyring.set_password(*credential)
            logger.info(green('Connection successful!\n'))
        elif credential:
            warning_msg = "The email password could not be added in the " \
                          f"keyring for the username {bold(credential[1])}\n"
            logger.warning(yellow(warning_msg))
        return result

    @_update_report('testing encryption/decryption')
    def _test_encryption(self, plaintext_message):
        logger.info(blue('### Test encryption/decryption ###'))
        result = Result()
        logger.info(f'Plaintext message: {plaintext_message}')
        try:
            encrypted_message = self._encrypt_message(plaintext_message)
        except ValueError as e:
            error_msg = f'{e}\n'
            logger.error(red(error_msg))
            return result.set_error(error_msg)
        logger.info('')
        logger.info('## Encryption results ##')
        logger.info(f'ok: {encrypted_message.ok}')
        logger.info(f'status: {encrypted_message.status}')
        logger.debug(f'stderr:\n{encrypted_message.stderr}')
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        passphrase, credential = get_gpg_passphrase(
            prompt=self.config.prompt_passwords,
            gpg=gpg,
            fingerprint=self.config.send_emails['encrypt']['recipient_userid'],
            message=blue("Enter your GPG passphrase for decrypting with "
                         "fingerprint "
                         f"{bold(self.config.send_emails['encrypt']['recipient_userid'])}"))
        decrypted_message = gpg.decrypt(str(encrypted_message), passphrase=passphrase)
        del passphrase
        logger.info('')
        logger.info('## Decryption results ##')
        logger.info(f'ok: {decrypted_message.ok}')
        logger.info(f'status: {decrypted_message.status}')
        logger.debug(f'stderr:\n{decrypted_message.stderr}')
        logger.info('')
        logger.debug(f'Encrypted message:\n{str(encrypted_message)}')
        logger.info(f'Decrypted message: {decrypted_message.data.decode()}')
        if plaintext_message == decrypted_message.data.decode():
            logger.info(green('Encryption/decryption successful!\n'))
            result.set_success()
            update_gpg_pass(credential, success=True)
        else:
            error_msg = "The message couldn't be decrypted " \
                        f"correctly\n{decrypted_message.stderr}"
            logger.error(red(error_msg))
            result.set_error(error_msg)
            update_gpg_pass(credential, success=False)
        return result

    @_update_report('testing signing')
    def _test_signature(self, message):
        logger.info(blue('### Test signing message ###'))
        result = Result()
        logger.info(f'Message to be signed: {message}')
        try:
            signed_message = self._sign_message(message)
        except ValueError as e:
            error_msg = "The message couldn't be " \
                        f"signed\n{e.__str__().strip()}\n"
            logger.error(red(error_msg))
            result.set_error(error_msg)
            return result
        gpg = gnupg.GPG(gnupghome=self.config.homedir)
        verify = gpg.verify(signed_message.data)
        logger.info('')
        logger.info('## Signature results ##')
        logger.info(f'valid: {verify.valid}')
        logger.info(f'status: {verify.status}')
        logger.debug(f'stderr:\n{verify.stderr}')
        logger.info('')
        if verify.valid:
            logger.info(green('Signing message successful!\n'))
            result.set_success()
        else:
            error_msg = "The message couldn't be " \
                        f"signed\n{verify.stderr}\n"
            logger.error(red(error_msg))
            result.set_error(error_msg)
        return result

    def _update_keyring(self):
        result = Result()
        if self.config.email_password:
            service = KEYRING_SERVICE_EMAIL_PASS
            account = 'email'
            enter_old_pass_msg = 'Enter the old email password'
            enter_new_pass_msg = 'Enter the NEW email password'
            prompt_old = 'Old email password (will not be echoed): '
            prompt_new = 'New email password (will not be echoed): '
            prompt_verify = 'Confirm new password (will not be echoed): '
            success_msg = 'Successful password update!'
        else:
            service = KEYRING_SERVICE_GPG_PASS
            enter_old_pass_msg = 'Enter the old GPG passphrase'
            enter_new_pass_msg = 'Enter the NEW GPG passphrase'
            account = 'GPG'
            prompt_old = 'Old GPG passphrase (will not be echoed): '
            prompt_new = 'New GPG passphrase (will not be echoed): '
            prompt_verify = 'Confirm new GPG passphrase (will not be echoed): '
            success_msg = 'Successful passphrase update!'
        old_password1 = keyring.get_password(service, self.config.username)
        if not old_password1:
            error_msg = f"Couldn't find the {account} account with username " \
                        f"{bold(self.config.username)} in the keyring"
            self._log_error(error_msg)
            return result.set_error(error_msg)
        print(blue(enter_old_pass_msg))
        old_password2 = prompt_password(prompt_old, prompt_verify, verify=False)
        if old_password1 != old_password2:
            error_msg = "Old password isn't valid!"
            print()
            self._log_error(error_msg)
            return result.set_error(error_msg)
        print()
        print(blue(enter_new_pass_msg))
        password = prompt_password(prompt_new, prompt_verify, newline=True)
        keyring.set_password(service, self.config.username, password)
        print()
        logger.info(green(success_msg))
        time.sleep(0.5)
        result.set_success()
        return result

    def _update_token(self):
        logger.info('Update the googleapi tokens')
        result = Result()
        if self.config.tokens_dirpath:
            if os.path.isdir(self.config.tokens_dirpath):
                tokens_dirpath = self.config.tokens_dirpath
            else:
                error_msg = f'{bold(self.config.tokens_dirpath)} is not a directory'
                self._log_error(error_msg)
                return result.set_error(error_msg)
        else:
            if os.path.exists(self.config.googleapi['credentials_path']):
                tokens_dirpath = os.path.dirname(self.config.googleapi['credentials_path'])
            else:
                print(blue('\nEnter the directory path containing the tokens and '
                           'credentials files (JSON)'))
                while True:
                    tokens_dirpath = os.path.expanduser(input('Directory path: ').strip())
                    if os.path.isdir(tokens_dirpath):
                        break
                    else:
                        print(red(f'{bold(tokens_dirpath)} is not a directory!'))
                print()
        tokens_filepath = os.path.join(tokens_dirpath, TOKENS_FILENAME)
        if os.path.exists(tokens_filepath):
            logger.debug(f'Removing the token file {bold(tokens_filepath)}')
            os.remove(tokens_filepath)
            logger.info(green('googleapi tokens successfully updated!'))
            result.set_success()
            return result
        else:
            error_msg = f"The directory {bold(tokens_dirpath)} doesn't " \
                        f"contain the tokens file {bold(TOKENS_FILENAME)}"
            self._log_error(error_msg)
            return result.set_error(error_msg)


def main():
    try:
        exit_code = 0
        # Check project directory
        mkdir(cryptlib.__project_dir__)
        mkdir(default_logging.LOGS_DIR)
        # Parse command-line arguments
        parser = setup_argparser()
        args = parser.parse_args()
        main_config = argparse.Namespace(**get_config_dict('main', cryptlib.__project_dir__))
        # Override configuration dict with command-line arguments
        returned_values = override_config_with_args(
            main_config=main_config,
            default_main_config=get_config_dict('main', default_config=True),
            args=args)
        setup_log(package=cryptlib.__package_name__,
                  script_name=cryptlib.__project_name__,
                  log_filepath=LOGGING_PATH,
                  quiet=main_config.quiet,
                  verbose=main_config.verbose,
                  logging_level=main_config.logging_level,
                  logging_formatter=main_config.logging_formatter,
                  level_handler_names=['console', 'file'],
                  formater_handler_names=['console'])
        process_returned_values(returned_values)
        if main_config.subcommand == 'edit':
            if main_config.reset:
                exit_code = reset_file(configs_dirpath=cryptlib.__project_dir__,
                                       verbose=main_config.verbose)
            else:
                exit_code = edit_file(app=main_config.app,
                                      configs_dirpath=cryptlib.__project_dir__,
                                      verbose=main_config.verbose)
        elif main_config.subcommand == 'uninstall':
            logger.info('Uninstalling the program '
                        f'{bold(cryptlib.__project_name__)} ...')
        else:
            exit_code = CryptEmail(main_config).run()
    except KeyboardInterrupt:
        logger.debug('Ctrl+c detected!')
        exit_code = 2
    except EOFError:
        logger.debug('Ctrl+d detected!')
        exit_code = 3
    return exit_code


if __name__ == '__main__':
    exit_code = main()
    logger.info(f'Exiting with code {exit_code}')
    sys.exit(exit_code)
