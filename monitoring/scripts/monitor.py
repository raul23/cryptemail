import tempfile

from monitoring import __name__ as PACKAGE_NAME, __version__ as VERSION
from monitoring.configs import default_config as default_cfg, plist
from monitoring.edit import edit_file, reset_file
from monitoring import scripts
from monitoring.utils.genutils import *
from monitoring.utils.logutils import init_log

logger = init_log(__name__, __file__)

LOG_CFG = 'log'
MAIN_CFG = 'main'
PROJECT_NAME = 'mac-monitoring'
PROG_DIR = os.path.expanduser(f'~/{PROJECT_NAME}')
PROG_NAME = prog_name(__file__)
CONFIGS_PATH = PROG_DIR
SERVICE_SCRIPT_NAME = 'service.py'
SERVICE_SCRIPT_PATH = os.path.join(PROG_DIR, SERVICE_SCRIPT_NAME)

# =====================
# Default config values
# =====================
ACTION = default_cfg.action
APP = default_cfg.app
DELAY_ACTION = default_cfg.delay_action
EDIT = default_cfg.edit
END = default_cfg.end
LOGGING_FORMATTER = default_cfg.logging_formatter
LOGGING_LEVEL = default_cfg.logging_level
PREDICATE = default_cfg.predicate
RESET = default_cfg.reset
SERVICE_TYPE = default_cfg.service_type
SHOW = default_cfg.show
START = default_cfg.start


class Service:
    def __init__(self, service_type='agent', logging_formatter='simple'):
        self.service_type = service_type
        if service_type == 'agent':
            self.service_name = f'com.{PROJECT_NAME}.agent'
        else:
            raise NotImplementedError(
                f"Service type '{service_type}' not supported. Only 'agent' "
                "is supported as a service")
        self.logging_formatter = logging_formatter
        self.plist_path = os.path.expanduser(
            f'~/Library/LaunchAgents/{self.service_name}.plist')
        self.script_path = SERVICE_SCRIPT_PATH

    def abort(self):
        raise NotImplementedError('abort() is not implemented!')

    def pause(self):
        logger.debug(f"Pausing {self.service_type} '{self.service_name}'...")
        cmd = f'launchctl unload {self.plist_path}'
        result = subprocess.run(shlex.split(cmd), capture_output=True)
        return check_result(
            result,
            error_msg=f"The {self.service_type} couldn't be disabled",
            valid_msg=f'{self.service_type} disabled',
            err_key='not find', logging_formatter=self.logging_formatter)

    def start(self):
        logger.debug(f"Starting {self.service_type} '{self.service_name}'...")
        src = os.path.join(os.path.dirname(scripts.__file__), SERVICE_SCRIPT_NAME)
        copy(src, self.script_path)
        # TODO: remove following lines
        """
        if not os.path.exists(self.script_path):
            raise FileNotFoundError(f'The service script is not found: {self.script_path}')
        """
        plist_content = plist.plist_content.format(service_name=self.service_name,
                                                   script_path=self.script_path,
                                                   configs_path=CONFIGS_PATH)
        tmp_file_plist = tempfile.mkstemp(suffix='.plist')[1]
        with open(tmp_file_plist, 'w') as f:
            f.write(plist_content)
        copy(tmp_file_plist, self.plist_path)
        remove_file(tmp_file_plist)
        # TODO: important, check first if service is already loaded before overwriting service.py and plist
        # launchctl list
        cmd = f'launchctl load {self.plist_path}'
        result = subprocess.run(shlex.split(cmd), capture_output=True)
        return check_result(
            result,
            error_msg=f"The {self.service_type} couldn't be started",
            valid_msg=f'{self.service_type} started',
            skip_key='already loaded', logging_formatter=self.logging_formatter)


def check_result(result, error_msg, valid_msg, err_key=None, skip_key=None,
                 logging_formatter='simple'):
    # TODO: raise error to get traceback?
    stderr = result.stderr.decode().strip()
    stderr = stderr.replace('WARNING:', '').replace('ERROR:', '').strip()
    if skip_key and stderr and stderr.find(skip_key) != -1:
        logger.warning(f'{warning()} {stderr}')
    elif result.returncode or (err_key and stderr.find(err_key) != -1):
        log_error(f'{error_msg}: {stderr}', logging_formatter)
        return 1
    else:
        logger.info(green(valid_msg))
        return 0


def log_error(msg, logging_formatter='simple'):
    if logging_formatter == 'only_msg':
        logger.error(f'{error(msg)}')
    else:
        logger.error(f'{red(msg)}')


def setup_argparser():
    width = os.get_terminal_size().columns - 5
    parser = ArgumentParser(
        description=f'''
Script for monitoring your Mac.

{important()}''',
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
        version=f'%(prog)s v{VERSION}',
        help="Show program's version number and exit.")
    general_group.add_argument(
        '-q', '--quiet', action='store_true',
        help='Enable quiet mode, i.e. nothing will be printed.')
    general_group.add_argument(
        '--verbose', action='store_true',
        help='Print various debugging information, e.g. print traceback '
             'when there is an exception.')
    # TODO: important, remove the following option
    """
    general_group.add_argument(
        '-u', '--use-config', dest='use_config', action='store_true',
        help='If this is enabled, the parameters found in the main '
             'config file will be used instead of the command-line '
             'arguments. NOTE: any other command-line argument that '
             'you use in the terminal with the `--use-config` flag is '
             'ignored, i.e. only the parameters defined in the main '
             'config file config.py will be used.')
    """
    general_group.add_argument(
        '-l', '--log-level', dest='logging_level',
        choices=['debug', 'info', 'warning', 'error'],  # default=LOGGING_LEVEL,
        help='Set logging level for all loggers.'
             + default(LOGGING_LEVEL))
    # TODO: explain each format
    general_group.add_argument(
        '-f', '--log-format', dest='logging_formatter',
        choices=['console', 'simple', 'only_msg'],  # default=LOGGING_FORMATTER,
        help='Set logging formatter for all loggers.'
             + default(LOGGING_FORMATTER))
    # =================
    # Uninstall options
    # =================
    uninstall_group = parser.add_argument_group(f"{yellow('Uninstall options')}")
    uninstall_group.add_argument(
        '-u', '--uninstall', action='store_true', help='Uninstall the program.')
    uninstall_group.add_argument(
        '--all', action='store_true', dest='clear_all',
        help='Remove everything including config files and logs.')
    # ================
    # Edit/reset files
    # ================
    edit_group = parser.add_argument_group(
        f"{yellow('Edit/reset a configuration file')}")
    parser_edit_mutual_group = edit_group.add_mutually_exclusive_group()
    parser_edit_mutual_group.add_argument(
        "-e", "--edit", choices=[LOG_CFG, MAIN_CFG],
        help='Edit a configuration file, either the main configuration file '
             f'(`{MAIN_CFG}`) or the logging configuration file (`{LOG_CFG}`).'
             + default(EDIT))
    edit_group.add_argument(
        "--app", dest="app",  # default=None,
        help='''Name of the application to use for editing the file. If no 
            name is given, then the default application for opening this type of
            file will be used.''' + default(APP))
    parser_edit_mutual_group.add_argument(
        '--reset', choices=[LOG_CFG, MAIN_CFG],
        help='Reset a configuration file to factory values. It can either be '
             f'the main configuration file (`{MAIN_CFG}`) or the logging '
             f'configuration file (`{LOG_CFG}`).' + default(RESET))
    # ==================
    # Monitoring options
    # ==================
    monitor_group = parser.add_argument_group(f"{yellow('Monitoring options')}")
    parser_mutual_group = monitor_group.add_mutually_exclusive_group()
    parser_mutual_group.add_argument(
        '-a', '--abort-monitoring', action="store_true",
        help='Abort system monitoring.')
    parser_mutual_group.add_argument(
        '-p', '--pause-monitoring', action="store_true",
        help='Pause system monitoring.')
    parser_mutual_group.add_argument(
        '-s', '--start-monitoring', action="store_true",
        help='Start system monitoring.')
    parser_mutual_group.add_argument(
        '-r', '--restart-monitoring', action="store_true",
        help='Restart system monitoring.')
    monitor_group.add_argument(
        '-t', '--service-type', choices=['agent', 'daemon'],
        help='Type of service to install.' + default(SERVICE_TYPE))
    # ==============
    # Report options
    # ==============
    report_group = parser.add_argument_group(f"{yellow('Report options')}")
    report_group.add_argument(
        '--show', metavar='NUM', help=f'Show last {SHOW} logs.' + default(SHOW))
    report_group.add_argument(
        '--start', metavar='YYYY-MM-DD HH:MM:SS', help='TODO.' + default(START))
    report_group.add_argument(
        '--end', metavar='YYYY-MM-DD HH:MM:SS', help='TODO.' + default(END))
    report_group.add_argument(
        '--email', action="store_true", help='Send the alerts as emails.')
    report_group.add_argument(
        '--encrypt', action="store_true",
        help='Encrypt sensitive data generated by the program, e.g. emails '
             'before being sent or pictures taken of suspects.')
    # ====================
    # Failed login options
    # ====================
    failed_group = parser.add_argument_group(f"{yellow('Failed login options')}")
    failed_group.add_argument(
        '--not-failed', action="store_true",
        help="Don't detect failed login attempts.")
    failed_group.add_argument(
        '--predicate', metavar='FILTER',
        help='Filter messages based on the provided predicate, based on '
             'NSPredicate.' + default(PREDICATE))
    failed_group.add_argument(
        '--action',
        help='Action to be performed right after a failed login attempt is '
             'detected. Supported action can be one of the following: '
             'take-picture, shutdown or a path to a script.' + default(ACTION))
    # TODO: use the following important message
    """
        help='Action to be performed right after a failed login attempt is '
             'detected. Supported action can either be: take-picture, '
             f'shutdown or a path to a script. {red("IMPORTANT:")} This option '
             f'only works if the service is a daemon since an agent can\'t '
             f'perform an action (e.g. shutdown) while the user is not login.')
    """
    failed_group.add_argument(
        '-d', '--delay-action', metavar='SECONDS',
        help='Delay in seconds to wait before starting the action.'
             + default(DELAY_ACTION))
    # ===========
    # Set options
    # ===========
    set_group = parser.add_argument_group(f"{yellow('Set options')}")
    set_group.add_argument(
        '--set', metavar='option1=value1;option2=value2', dest='set_options',
        help='The option names are the long versions, e.g. \'last\' instead of '
             f'\'l\'. Example: {PROG_NAME} --set email:True;delay-action=30')
    return parser


def uninstall(logging_formatter, clear_all=False):
    logger.debug(f"Uninstalling {PROJECT_NAME}...")
    if clear_all:
        """
        logger.debug('Removing user config files')
        remove_file(os.path.join(PROG_DIR, 'config.py'))
        remove_file(os.path.join(PROG_DIR, 'logging.py'))
        """
        logger.debug(f'Remove program directory: {PROG_DIR}')
        shutil.rmtree(PROG_DIR)
        logger.debug('Removed!')
    cmd = f'pip uninstall -y {PROJECT_NAME}'
    result = subprocess.run(shlex.split(cmd), capture_output=True)
    return check_result(
        result,
        error_msg=f"{PROJECT_NAME} couldn't be uninstalled",
        valid_msg=f'{PROJECT_NAME} was uninstalled',
        skip_key='Skipping',
        logging_formatter=logging_formatter)


def main():
    main_cfg = None
    # =====================
    # Default logging setup
    # =====================
    # Setup the default logger (whose name is __main__ since this file is run
    # as a script) which will be used for printing to the console before all
    # loggers defined in the JSON file will be configured. The printing with
    # this default logger will only be done in the cases that the user allows
    # it, e.g. the verbose option is enabled.
    # IMPORTANT: the config options need to be read before using any logger
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter("%(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logging_setup = False
    try:
        # TODO: testing code
        # test = {}
        # print(test['a'])
        exit_code = 0
        parser = setup_argparser()
        args = parser.parse_args()
        # TODO: can you do it in setup_argparser()
        if args.app and not args.edit:
            msg = red('error: argument -a/--app: required with argument -e/--edit')
            print(f"\n{msg}")
            return 1
        # Get main cfg dict
        # TODO: important, check if an option is defined more than once
        if not os.path.exists(PROG_DIR):
            logger.debug(f"Creating program directory: {PROG_DIR}")
            mkdir(PROG_DIR)
            logger.info(f"Program directory created: {PROG_DIR}")
        configs_dirpath = CONFIGS_PATH
        main_cfg = argparse.Namespace(**get_config_dict('main', configs_dirpath))
        # TODO: testing code
        # test = args
        # import ipdb
        # ipdb.set_trace()
        # Override main configuration from file with command-line arguments
        returned_values = override_config_with_args(
            main_cfg, args, default_cfg.__dict__)  # use_config=args.use_config)
        setup_log(package=PACKAGE_NAME, configs_dirpath=configs_dirpath,
                  quiet=main_cfg.quiet,
                  verbose=main_cfg.verbose,
                  logging_level=main_cfg.logging_level,
                  logging_formatter=main_cfg.logging_formatter)
        logging_setup = True
        process_returned_values(returned_values)
        service = Service(logging_formatter=main_cfg.logging_formatter)
        if main_cfg.uninstall:
            exit_code = uninstall(main_cfg.logging_formatter, main_cfg.clear_all)
        elif main_cfg.edit:
            exit_code = edit_file(main_cfg.edit, main_cfg.app, configs_dirpath)
        elif main_cfg.reset:
            exit_code = reset_file(main_cfg.reset, configs_dirpath)
        elif main_cfg.start_monitoring:
            exit_code = service.start()
        elif main_cfg.pause_monitoring:
            exit_code = service.pause()
        elif main_cfg.abort_monitoring:
            exit_code = service.abort()
        else:
            logger.warning(yellow('No action chosen!'))
    except Exception as e:
        if logging_setup:
            logging_formatter = main_cfg.logging_formatter
            verbose = main_cfg.verbose
            if verbose:
                value = e.args
                value = (red(f'{value[0]}'),)
                e.__setattr__('args', value)
                logger.exception(e)
            else:
                log_error(e, logging_formatter)
        else:
            msg = "{}: {}".format(str(e.__class__).split("'")[1], e)
            logger.exception(f'{error(msg)}')
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    main()
