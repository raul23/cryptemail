import argparse
import os

from monitoring import __name__ as PACKAGE_NAME, __version__ as VERSION
from monitoring.configs import __path__, default_config as default_cfg
from monitoring.edit_config import edit_file, reset_file
from monitoring.utils.genutils import (COLORS, ArgumentParser, MyFormatter,
                                       get_config_dict, get_configs_dirpath,
                                       get_default_message, get_important_msg,
                                       get_usage, override_config_with_args,
                                       process_returned_values, setup_log)
from monitoring.utils.logutils import init_log


logger = init_log(__name__, __file__)
LOG_CFG = 'log'
MAIN_CFG = 'main'

# =====================
# Default config values
# =====================
EDIT = default_cfg.edit
LOGGING_FORMATTER = default_cfg.logging_formatter
LOGGING_LEVEL = default_cfg.logging_level
RESET = default_cfg.reset


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
        "-a", "--app", dest="app", default=None,
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
        '-s', '--start-monitoring', action="store_true",
        help='Start system monitoring.')
    return parser


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
        if main_cfg.edit:
            exit_code = edit_file(main_cfg.edit, main_cfg.app, get_configs_dirpath())
        elif main_cfg.reset:
            exit_code = reset_file(main_cfg.reset, get_configs_dirpath())
        elif args.start_monitoring:
            pass
    except AssertionError as e:
        # TODO (IMPORTANT): use same logic as in other project
        # TODO: add KeyboardInterruptError
        logger.error(e)
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    main()
