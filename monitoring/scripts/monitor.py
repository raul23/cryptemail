import tempfile

from monitoring import __name__ as PACKAGE_NAME, __version__ as VERSION
from monitoring.configs import __path__, default_config as default_cfg
from monitoring.edit_config import edit_file, reset_file
from monitoring import scripts
from monitoring.utils.genutils import *
from monitoring.utils.logutils import init_log

logger = init_log(__name__, __file__)
LOG_CFG = 'log'
MAIN_CFG = 'main'
AGENT_SCRIPT = 'agent.py'

# =====================
# Default config values
# =====================
EDIT = default_cfg.edit
LOGGING_FORMATTER = default_cfg.logging_formatter
LOGGING_LEVEL = default_cfg.logging_level
RESET = default_cfg.reset


class Agent:
    def __init__(self, stealth=False):
        self.stealth = stealth
        if stealth:
            logger.info('Stealth mode enabled')
            self.agent_name = 'com.mac.load.agent'
        else:
            self.agent_name = 'com.mac-monitoring.agent'

    def load(self):
        pass

    def unload(self):
        pass


def check_result(result, error_msg, valid_msg, err_key=None, skip_key=None):
    stderr = result.stderr.decode().strip()
    if skip_key and stderr and stderr.find(skip_key):
        logger.warning(f'{warning()} {stderr}')
    elif result.returncode or (err_key and stderr.find(err_key) != -1):
        logger.error(f"{error()} {error_msg}: {stderr}")
        return 1
    else:
        logger.info(valid_msg)
        return 0


def get_plist_path(agent_name):
    return os.path.expanduser(f'~/Library/LaunchAgents/{agent_name}.plist')


def load_agent(main_cfg):
    agent_name = main_cfg.agent_name
    logger.debug(f"Loading agent '{agent_name}'...")
    plist_path = get_plist_path(agent_name)
    script_path = os.path.join(os.path.dirname(scripts.__file__), AGENT_SCRIPT)
    plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd >
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{agent_name}</string>
    <key>Program</key>
    <string>{script_path}</string>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
    '''
    """
    with open(plist_path, 'w') as f:
        f.write(plist_config)
    """
    tmp_file_plist = tempfile.mkstemp(suffix='.plist')[1]
    with open(tmp_file_plist, 'w') as f:
        f.write(plist_content)
    copy(tmp_file_plist, plist_path)
    remove_file(tmp_file_plist)
    cmd = f'launchctl load {plist_path}'
    # subprocess.run(shlex.split(cmd), shell=False)
    # os.system(cmd)
    result = subprocess.run(shlex.split(cmd), capture_output=True)
    return check_result(result, "The agent couldn't be loaded", 'Agent loaded', skip_key='already loaded')


def setup_argparser():
    width = os.get_terminal_size().columns - 5
    parser = ArgumentParser(
        description=f'''
Script for monitoring your Mac.

{get_important_msg()}''',
        usage=get_usage(__file__),
        add_help=False,
        # ArgumentDefaultsHelpFormatter
        # HelpFormatter
        # RawDescriptionHelpFormatter
        formatter_class=lambda prog: MyFormatter(
            prog, max_help_position=50, width=width))
    # ===============
    # General options
    # ===============
    general_group = parser.add_argument_group(
        f"{COLORS['YELLOW']}General options{COLORS['NC']}")
    general_group.add_argument('-h', '--help', action='help',
                               help='Show this help message and exit.')
    general_group.add_argument(
        '-v', '--version', action='version',
        version=f'%(prog)s v{VERSION}',
        help="Show program's version number and exit.")
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
             + get_default_message(LOGGING_LEVEL))
    # TODO: explain each format
    general_group.add_argument(
        '--log-format', dest='logging_formatter',
        choices=['console', 'simple', 'only_msg'],
        help='Set logging formatter for all loggers.'
             + get_default_message(LOGGING_FORMATTER))
    # ================
    # Edit/reset files
    # ================
    edit_group = parser.add_argument_group(
        f"{COLORS['YELLOW']}Edit/reset a configuration file{COLORS['NC']}")
    parser_edit_mutual_group = edit_group.add_mutually_exclusive_group()
    parser_edit_mutual_group.add_argument(
        "-e", "--edit", choices=[LOG_CFG, MAIN_CFG],
        help='Edit a configuration file, either the main configuration file '
             f'(`{MAIN_CFG}`) or the logging configuration file (`{LOG_CFG}`).'
             + get_default_message(EDIT))
    edit_group.add_argument(
        "--app", dest="app", default=None,
        help='''Name of the application to use for editing the file. If no 
            name is given, then the default application for opening this type of
            file will be used.''')
    parser_edit_mutual_group.add_argument(
        '-r', '--reset', choices=[LOG_CFG, MAIN_CFG],
        help='Reset a configuration file to factory values. It can either be '
             'the main configuration file (`{MAIN_CFG}`) or the logging '
             'configuration file (`{LOG_CFG}`).' + get_default_message(RESET))
    # ==================
    # Monitoring options
    # ==================
    monitor_group = parser.add_argument_group(
        f"{COLORS['YELLOW']}Monitoring options{COLORS['NC']}")
    monitor_group.add_argument(
        '-a', '--abort-monitoring', action="store_true",
        help='Abort system monitoring.')
    monitor_group.add_argument(
        '-p', '--pause-monitoring', action="store_true",
        help='Pause system monitoring.')
    monitor_group.add_argument(
        '-s', '--start-monitoring', action="store_true",
        help='Start system monitoring.')
    monitor_group.add_argument(
        '-f', '--force', action="store_true",
        help='Forcibly execute the given operation (e.g. pause) on all '
             'loaded monitoring agents no matter their type (stealth or not).')
    monitor_group.add_argument(
        '--stealth', action="store_true",
        help='Enable stealth system monitoring, i.e. make the monitoring as '
             'transparent as possible.')
    return parser


def unload_agent(main_cfg):
    logger.debug(f"Unloading agent '{main_cfg.agent_name}'...")
    plist_path = get_plist_path(main_cfg.agent_name)
    cmd = f'launchctl unload {plist_path}'
    result = subprocess.run(shlex.split(cmd), capture_output=True)
    return check_result(result, "The agent couldn't be unloaded",
                        'Agent unloaded', 'not find')


def main():
    try:
        exit_code = 0
        parser = setup_argparser()
        args = parser.parse_args()
        # TODO: find if you can do it in setup_argparser()
        if args.app and not args.edit:
            print(f"\n{COLORS['RED']}error: argument -a/--app: required with "
                  f"argument -e/--edit{COLORS['NC']}")
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
        process_returned_values(returned_values)
        if main_cfg.stealth:
            logger.info('Stealth mode enabled')
            main_cfg.agent_name = 'com.mac.load.agent'
        else:
            main_cfg.agent_name = 'com.mac-monitoring.agent'
        if main_cfg.edit:
            exit_code = edit_file(main_cfg.edit, main_cfg.app, get_configs_dirpath())
        elif main_cfg.reset:
            exit_code = reset_file(main_cfg.reset, get_configs_dirpath())
        elif main_cfg.start_monitoring:
            exit_code = load_agent(main_cfg)
        elif main_cfg.pause_monitoring:
            exit_code = unload_agent(main_cfg)
    except AssertionError as e:
        # TODO (IMPORTANT): use same logic as in other project
        # TODO: add KeyboardInterruptError
        logger.error(e)
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    main()
