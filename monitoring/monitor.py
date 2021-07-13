import os

from monitoring import __version__
from monitoring.utils import (COLORS, ArgumentParser, MyFormatter,
                              get_important_msg, get_usage)


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
        version=f'%(prog)s v{__version__}',
        help="Show program's version number and exit.")
    # ==================
    # Monitoring options
    # ==================
    monitor_group = parser.add_argument_group(
        f"{COLORS['YELLOW']}Monitoring options{COLORS['NC']}")
    monitor_group.add_argument(
        '-s', '--start-monitor', action="store_true",
        help='Start system monitoring.')
    return parser


def main():
    parser = setup_argparser()
    args = parser.parse_args()


if __name__ == '__main__':
    main()
