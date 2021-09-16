import base64
import getpass
import os
import re
import string
from email.mime.text import MIMEText
from secrets import choice

from googleapiclient import errors
import keyring

from cryptlib.utils.genutils import yellow
from cryptlib.utils.logutils import Logger
from script import KEYRING_SERVICE_GPG_PASS

logger = Logger(__name__, __file__)


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


def get_gpg_passphrase(prompt=False, gpg=None, fingerprint=None, message=None):
    if gpg and fingerprint:
        logger.debug('Checking if the passphrase is already cached '
                     '(by gpg-agent)')
        msg = 'test'
        encrypted_data = gpg.encrypt(msg, fingerprint)
        decrypted_data = gpg.decrypt(str(encrypted_data),
                                     passphrase=generate_random_string())
        if msg == decrypted_data.data.decode():
            logger.info("The GPG passphrase is already cached")
            return None
    conf_path = os.path.join(gpg.gnupghome, 'gpg-agent.conf')
    if os.path.exists(conf_path):
        with open(conf_path, 'r') as f:
            conf_data = f.read()
        found = re.search('^(pinentry-program)', conf_data, re.MULTILINE)
        if found:
            logger.debug('pinentry might be used for entering the passphrase')
            # if not saved in keyring
            return None
    keyring_username = f'{fingerprint}'
    passphrase = keyring.get_password(KEYRING_SERVICE_GPG_PASS, keyring_username)
    if passphrase:
        logger.debug('GPG passphrase retrieved from keyring')
    else:
        logger.debug("A GPG passphrase couldn't be found saved locally")
        if prompt:
            if message:
                print(message)
            passphrase = prompt_password(
                prompt='GPG passphrase (will not be echoed): ',
                prompt_verify='Verify passphrase (will not be echoed): ')
            keyring.set_password(KEYRING_SERVICE_GPG_PASS, keyring_username,
                                 passphrase)
        if not passphrase:
            if not prompt:
                logger.warning(yellow('prompt_passwords = False'))
            raise ValueError('No GPG passphrase could be retrieved for '
                             f'fingerprint={fingerprint}')
    return passphrase


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


def prompt_password(prompt='Enter password (will not be echoed): ',
                     prompt_verify='Verify password (will not be echoed: '):
    password1 = getpass.getpass(prompt=prompt)
    password2 = getpass.getpass(prompt=prompt_verify)
    if password1 == password2:
        return password1
    else:
        raise ValueError('password verification failed!')


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
        print(f"Message Id: {message['id']}")
        return message
    except errors.HttpError as e:
        print(f'An error occurred: {e}')
