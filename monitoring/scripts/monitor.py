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
SERVICE_NAME = f'com.{PROJECT_NAME}.service'
SERVICE_SCRIPT_NAME = 'service.py'
SERVICE_SCRIPT_PATH = os.path.join(PROG_DIR, SERVICE_SCRIPT_NAME)


class CheckResult:
    def __init__(self, log_format):
        self.log_format = log_format

    def _log_msg(self, msg, log_level, use_debug):
        if not use_debug:
            if log_level == 'warning':
                logger.warning(msg)
            elif log_level == 'error':
                log_error(msg, self.log_format)
            else:
                logger.info(msg)
        else:
            logger.debug(msg)

    def check_result(self, result, error_msg, valid_msg, error_keys=None,
                     skip_keys=None, use_debug=False):
        def find_key(msg, keys):
            for key in keys:
                if msg.find(key) != -1:
                    return True
            return False
        # TODO: raise error to get traceback?
        stderr = result.stderr.decode().strip()
        stderr = stderr.replace('WARNING:', '').replace('ERROR:', '').strip()
        if skip_keys and stderr and find_key(stderr, skip_keys):
            self._log_msg(f'{warning()} {stderr}', 'warning', use_debug)
        elif result.returncode or (error_keys and find_key(stderr, error_keys)):
            self._log_msg(f'{error_msg}: {stderr}', 'error', use_debug)
            return 1
        else:
            self._log_msg(green(valid_msg), 'info', use_debug)
        return 0


class Monitor:
    def __init__(self, config, configs_path):
        self.config = config
        self.configs_path = configs_path
        self.service = Service(log_format=self.config.log_format)
        self.checker = CheckResult(self.config.log_format)

    def _uninstall(self):
        logger.debug(f"Uninstalling {PROJECT_NAME}...")
        if self.config.clear_all:
            logger.debug(f'Remove program directory: {PROG_DIR}')
            shutil.rmtree(PROG_DIR)
            logger.debug('Removed!')
        cmd = f'pip uninstall -y {PROJECT_NAME}'
        result = subprocess.run(shlex.split(cmd), capture_output=True)
        return self.checker.check_result(
            result,
            error_msg=f"{PROJECT_NAME} couldn't be uninstalled",
            valid_msg=f'{PROJECT_NAME} was uninstalled',
            skip_keys=['Skipping'])

    def run(self):
        exit_code = 0
        if self.config.uninstall:
            exit_code = self._uninstall()
        elif self.config.edit:
            exit_code = edit_file(self.config.edit, self.config.app, self.configs_path)
        elif self.config.reset:
            exit_code = reset_file(self.config.reset, self.configs_path)
        elif self.config.start_monitoring:
            exit_code = self.service.start()
        elif self.config.cancel_monitoring:
            exit_code = self.service.cancel()
        elif self.config.restart_monitoring:
            exit_code = self.service.restart()
        else:
            logger.debug(yellow('No action chosen'))
        return exit_code


class Service:
    def __init__(self, service_type='agent', log_format='simple'):
        self.service_type = service_type
        if service_type == 'agent':
            self.service_name = f'{SERVICE_NAME}.agent'
            self.plist_path = os.path.expanduser(
                f'~/Library/LaunchAgents/{self.service_name}.plist')
        else:
            self.service_name = f'{SERVICE_NAME}.daemon'
            self.plist_path = os.path.expanduser(
                f'/Library/LaunchDaemons/{self.service_name}.plist')
            raise NotImplementedError(
                f"Service type '{service_type}' not supported. Only 'agent' "
                "is supported as a service")
        self.log_format = log_format
        self.script_path = SERVICE_SCRIPT_PATH
        self.checker = CheckResult(log_format)

    def cancel(self, use_debug=False):
        logger.debug(f"Stopping {self.service_type} '{self.service_name}'...")
        cmd = f'launchctl unload {self.plist_path}'
        result = subprocess.run(shlex.split(cmd), capture_output=True)
        return self.checker.check_result(
            result,
            error_msg=f"The {self.service_type} couldn't be stopped",
            valid_msg=f'{self.service_type} stopped',
            error_keys=['not find', 'No such file or directory'],
            use_debug=use_debug)

    def restart(self):
        logger.debug(f"Restarting {self.service_type} '{self.service_name}'...")
        self.cancel(use_debug=True)
        if self.start(use_debug=True):
            log_error(f"The {self.service_type} couldn't be restarted", self.log_format)
            return 1
        logger.info(green(f'{self.service_type} restarted'))
        return 0

    def start(self, use_debug=False):
        logger.debug(f"Starting {self.service_type} '{self.service_name}'...")
        src = os.path.join(os.path.dirname(scripts.__file__), SERVICE_SCRIPT_NAME)
        copy(src, self.script_path)
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
        return self.checker.check_result(
            result,
            error_msg=f"The {self.service_type} couldn't be started",
            valid_msg=f'{self.service_type} started',
            skip_keys=['already loaded'],
            use_debug=use_debug)


def log_error(msg, log_format='simple'):
    msg = f'{error(msg)}' if log_format == 'only_msg' else f'{red(msg)}'
    logger.error(msg)


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
    general_group.add_argument(
        '-l', '--log-level', dest='log_level',
        choices=['debug', 'info', 'warning', 'error'],  # default=LOGGING_LEVEL,
        help='Set logging level for all loggers.'
             + default(default_cfg.log_level))
    # TODO: explain each format
    general_group.add_argument(
        '-f', '--log-format', dest='log_format',
        choices=['console', 'simple', 'only_msg'],  # default=LOGGING_FORMATTER,
        help='Set logging formatter for all loggers.'
             + default(default_cfg.log_format))
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
        '-e', '--edit', choices=[LOG_CFG, MAIN_CFG],
        help='Edit a configuration file, either the main configuration file '
             f'(`{MAIN_CFG}`) or the logging configuration file (`{LOG_CFG}`).'
             + default(default_cfg.edit))
    edit_group.add_argument(
        '-a', '--app', dest='app',
        help='''Name of the application to use for editing the file. If no 
            name is given, then the default application for opening this type of
            file will be used.''' + default(default_cfg.app))
    parser_edit_mutual_group.add_argument(
        '--reset', choices=[LOG_CFG, MAIN_CFG],
        help='Reset a configuration file to factory values. It can either be '
             f'the main configuration file (`{MAIN_CFG}`) or the logging '
             f'configuration file (`{LOG_CFG}`).' + default(default_cfg.reset))
    # ==================
    # Monitoring options
    # ==================
    monitor_group = parser.add_argument_group(f"{yellow('Monitoring options')}")
    parser_mutual_group = monitor_group.add_mutually_exclusive_group()
    parser_mutual_group.add_argument(
        '-s', '--start-monitoring', action="store_true",
        help='Start system monitoring.')
    parser_mutual_group.add_argument(
        '-r', '--restart-monitoring', action="store_true",
        help='Restart system monitoring.')
    parser_mutual_group.add_argument(
        '-c', '--cancel-monitoring', action="store_true",
        help='Cancel system monitoring.')
    monitor_group.add_argument(
        '-t', '--service-type', choices=['agent', 'daemon'],
        help='Type of service to install.' + default(default_cfg.service_type))
    # ==============
    # Report options
    # ==============
    report_group = parser.add_argument_group(f"{yellow('Report options')}")
    report_group.add_argument(
        '--show', metavar='NUM',
        help=f'Show last {default_cfg.show} logs.' + default(default_cfg.show))
    report_group.add_argument(
        '--start-date', metavar='YYYY-MM-DD HH:MM:SS',
        help='TODO.' + default(default_cfg.start_date))
    report_group.add_argument(
        '--end-date', metavar='YYYY-MM-DD HH:MM:SS',
        help='TODO.' + default(default_cfg.end_date))
    report_group.add_argument(
        '--email', action="store_true", help='Send the alerts as emails.')
    report_group.add_argument(
        '--encrypt', action="store_true", help='Encrypt emails before being sent.')
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
             'NSPredicate.' + default(default_cfg.predicate))
    failed_group.add_argument(
        '--action',
        help='Action to be performed right after a failed login attempt is '
             'detected. Supported action can be one of the following: '
             'take-picture, shutdown or a path to a script.' + default(default_cfg.action))
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
             + default(default_cfg.delay_action))
    # ===========
    # Set options
    # ===========
    set_group = parser.add_argument_group(f"{yellow('Set options')}")
    set_group.add_argument(
        '--set', metavar='option1=value1;option2=value2', dest='set_options',
        help='The option names are the long versions, e.g. \'last\' instead of '
             f'\'l\'. Example: {PROG_NAME} --set email:True;delay-action=30')
    return parser


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
                  log_level=main_cfg.log_level,
                  log_format=main_cfg.log_format)
        logging_setup = True
        process_returned_values(returned_values)
        monitor = Monitor(main_cfg, configs_dirpath)
        exit_code = monitor.run()
    except Exception as e:
        if logging_setup:
            verbose = main_cfg.verbose
            if verbose:
                value = e.args
                value = (red(f'{value[0]}'),)
                e.__setattr__('args', value)
                logger.exception(e)
            else:
                log_error(e, main_cfg.log_format)
        else:
            msg = "{}: {}".format(str(e.__class__).split("'")[1], e)
            logger.exception(f'{error(msg)}')
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    main()
