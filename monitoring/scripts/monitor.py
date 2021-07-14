import tempfile

from monitoring import __name__ as PACKAGE_NAME, __version__ as VERSION
from monitoring.configs import __path__, default_config as default_cfg
from monitoring.edit import edit_file, reset_file
from monitoring import scripts
from monitoring.utils.genutils import *
from monitoring.utils.logutils import init_log

logger = init_log(__name__, __file__)
LOG_CFG = 'log'
MAIN_CFG = 'main'
SERVICE_SCRIPT = 'service.py'

# =====================
# Default config values
# =====================
APP = default_cfg.app
EDIT = default_cfg.edit
LOGGING_FORMATTER = default_cfg.logging_formatter
LOGGING_LEVEL = default_cfg.logging_level
RESET = default_cfg.reset


class Service:
    def __init__(self, service_type='agent', logging_formatter='simple'):
        self.service_type = service_type
        if service_type == 'agent':
            self.service_name = 'com.mac-monitoring.agent'
        else:
            raise NotImplementedError(
                f"Service type '{service_type}' not supported. Only 'agent' "
                "is supported as a service")
        self.logging_formatter = logging_formatter
        self.plist_path = os.path.expanduser(
            f'~/Library/LaunchAgents/{self.service_name}.plist')

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
        script_path = os.path.join(os.path.dirname(scripts.__file__), SERVICE_SCRIPT)
        if not os.path.exists(script_path):
            raise FileNotFoundError(f'The service script is not foud: {script_path}')
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd >
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{self.service_name}</string>
    <key>Program</key>
    <string>{script_path}</string>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
'''
        tmp_file_plist = tempfile.mkstemp(suffix='.plist')[1]
        with open(tmp_file_plist, 'w') as f:
            f.write(plist_content)
        copy(tmp_file_plist, self.plist_path)
        remove_file(tmp_file_plist)
        # TODO: important, check first if service is already loaded before overwriting plist
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
    if skip_key and stderr and stderr.find(skip_key):
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
    general_group.add_argument(
        '-u', '--use-config', dest='use_config', action='store_true',
        help='If this is enabled, the parameters found in the main '
             'config file will be used instead of the command-line '
             'arguments. NOTE: any other command-line argument that '
             'you use in the terminal with the `--use-config` flag is '
             'ignored, i.e. only the parameters defined in the main '
             'config file config.py will be used.')
    general_group.add_argument(
        '--log-level', dest='logging_level',
        choices=['debug', 'info', 'warning', 'error'],
        help='Set logging level for all loggers.'
             + default(LOGGING_LEVEL))
    # TODO: explain each format
    general_group.add_argument(
        '--log-format', dest='logging_formatter',
        choices=['console', 'simple', 'only_msg'],
        help='Set logging formatter for all loggers.'
             + default(LOGGING_FORMATTER))
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
        "--app", dest="app", default=None,
        help='''Name of the application to use for editing the file. If no 
            name is given, then the default application for opening this type of
            file will be used.''' + default(APP))
    parser_edit_mutual_group.add_argument(
        '-r', '--reset', choices=[LOG_CFG, MAIN_CFG],
        help='Reset a configuration file to factory values. It can either be '
             'the main configuration file (`{MAIN_CFG}`) or the logging '
             'configuration file (`{LOG_CFG}`).' + default(RESET))
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
        # test = {}
        # print(test['a'])
        exit_code = 0
        parser = setup_argparser()
        args = parser.parse_args()
        # TODO: find if you can do it in setup_argparser()
        if args.app and not args.edit:
            msg = red('error: argument -a/--app: required with argument -e/--edit')
            print(f"\n{msg}")
            return 1
        # Get main cfg dict
        # TODO: important, check if an option is defined more than once
        configs_dirpath = __path__[0]
        main_cfg = argparse.Namespace(**get_config_dict('main', configs_dirpath))
        # Override main configuration from file with command-line arguments
        returned_values = override_config_with_args(
            main_cfg, args, default_cfg.__dict__, use_config=args.use_config)
        setup_log(package=PACKAGE_NAME, configs_dirpath=configs_dirpath,
                  quiet=main_cfg.quiet,
                  verbose=main_cfg.verbose,
                  logging_level=main_cfg.logging_level,
                  logging_formatter=main_cfg.logging_formatter)
        logging_setup = True
        process_returned_values(returned_values)
        service = Service(logging_formatter=main_cfg.logging_formatter)
        if main_cfg.edit:
            exit_code = edit_file(main_cfg.edit, main_cfg.app, get_configs_dirpath())
        elif main_cfg.reset:
            exit_code = reset_file(main_cfg.reset, get_configs_dirpath())
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
