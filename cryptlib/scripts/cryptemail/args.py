import cryptlib
from cryptlib.configs import default_config
from cryptlib.utils.genutils import *

CONNECTIONS = {'tokens': 'googleapi', 'password': 'smtp_imap'}


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
    encrypt_group = parser.add_argument_group(f"{yellow(title)}")
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
                 "and then encrypt as separate steps.")


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
            help='Prompt users to enter their email password or passphrase '
                 '(decryption and signing).')
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


def init_list(list_):
    return [] if list_ is None else list_


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # self.print_help(sys.stderr)
        # self.usage
        self.exit(2, '\n%s: error: %s\n' % (self.prog, red(message)))


def setup_argparser():
    # Setup the parser
    width = os.get_terminal_size().columns - 5
    # parser = argparse.ArgumentParser(
    parser = ArgumentParser(
        usage=main_usage(cryptlib.__project_name__),
        description="Command-line program for sending and reading "
                    "encrypted emails.",
        add_help=False,
        prog=cryptlib.__project_name__,
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
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
        description=desc,
        add_help=False,
        help=f'Uninstall the {bold(cryptlib.__project_name__)} program.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_test, remove_opts=['interactive', 'homedir'])
    parser_uninstall_group = parser_test.add_argument_group(
        title=f"{yellow('Uninstall options')}")
    parser_uninstall_group.add_argument(
        '--uninstall', choices=['package', 'everything'],
        help=desc)
    # ===========================
    # Edit cryptemail config file
    # ===========================
    # create the parser for the "edit" command
    subcommand = 'edit'
    parser_test = subparsers.add_parser(
        subcommand,
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
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
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
        description='Run tests as defined in the config file such as TODO.',
        add_help=False,
        help='Run tests (e.g. test the connection to an email server).',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_test)
    add_connection_options(parser_test, remove_opts=['conn'])
    add_googleapi_options(parser_test)
    add_smtp_imap_options(parser_test)
    parser_test_group = parser_test.add_argument_group(title=f"{yellow('Test options')}")
    parser_test_group.add_argument(
        '-r', '--run-tests', dest='run_tests', action='store_true',
        help='Run a set of tests as defined in the config file.')
    parser_test_group.add_argument(
        '-e', '--encryption', dest='args_test_encryption', metavar='USERID',
        help='Test encrypting and decrypting a message. The encryption program '
             'used (e.g. GPG) is the one defined in the config file.')
    parser_test_group.add_argument(
        '-s', '--signature', dest='args_test_signature', metavar='USERID',
        help='Test signing a message.')
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
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
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
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
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
    # ==============
    # Update options
    # ==============
    # create the parser for the "update" command
    subcommand = 'update'
    parser_update = subparsers.add_parser(
        subcommand,
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand),
        description='Update the googleapi tokens or the keyring (i.e. email password or GPG passphrase).',
        add_help=False,
        help='Update the keyring or googleapi tokens.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_update,
                        remove_opts=['homedir', 'interactive', 'prompt_passwords', 'quiet'])
    parser_update_key_group = parser_update.add_argument_group(
        title=f"{yellow('Update keyring options')}")
    update_mutual_group = parser_update_key_group.add_mutually_exclusive_group()
    update_mutual_group.add_argument('-e', '--email-password', dest='email_password',
                                     action='store_true',
                                     help='Update an email password for a given username found in the keyring.')
    update_mutual_group.add_argument('-g', '--gpg-passphrase', dest='gpg_passphrase',
                                     action='store_true',
                                     help='Update a GPG passphrase for a given username found in the keyring.')
    parser_update_key_group.add_argument('-u', '--username', dest='username',
                                         help='Username.')
    parser_update_token_group = parser_update.add_argument_group(
        title=f"{yellow('Update the googleapi tokens options')}")
    parser_update_token_group.add_argument('-t', '--tokens', dest='tokens', action='store_true',
                                           help='Update the googleapi tokens if they have been expired or revoked.')
    parser_update_token_group.add_argument(
        '-d', '--directory', metavar='PATH', dest='tokens_dirpath',
        help="Directory path containing the tokens and credentials files (JSON).")
    # ==============
    # Delete options
    # ==============
    # create the parser for the "delete" command
    subcommand = 'delete'
    parser_delete = subparsers.add_parser(
        subcommand,
        prog=cryptlib.__project_name__,
        usage=subcommand_usage(cryptlib.__project_name__, subcommand,
                               required_args='-u USERNAME'),
        description='Delete an account in the keyring (i.e. email or GPG account).',
        add_help=False,
        help='Delete an account in the keyring.',
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    add_general_options(parser_delete,
                        remove_opts=['homedir', 'interactive', 'prompt_passwords', 'quiet'])
    parser_delete_group = parser_delete.add_argument_group(
        title=f"{yellow('Delete options')}")
    delete_mutual_group = parser_delete_group.add_mutually_exclusive_group()
    delete_mutual_group.add_argument('-e', '--email-account', dest='email_account',
                                     action='store_true',
                                     help='Delete an email account for a given username in the keyring.')
    delete_mutual_group.add_argument('-g', '--gpg-account', dest='gpg_account',
                                     action='store_true',
                                     help='Delete a GPG account for a given username in the keyring.')
    parser_delete_group.add_argument('-u', '--username', dest='username',
                                     help='Username.')
    return parser
