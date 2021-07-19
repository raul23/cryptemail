"""General utilities
"""
import argparse
import codecs
import importlib
import json
import logging.config
import os
import shlex
import shutil
import subprocess
import sys
from argparse import Namespace
from collections import namedtuple, OrderedDict
from logging import NullHandler
from pathlib import Path
from runpy import run_path
from types import SimpleNamespace

from monitoring.utils.logutils import (init_log, set_logging_field_width,
                                       set_logging_formatter, set_logging_level)

logger = init_log(__name__, __file__)
# TODO: is next necessary? already done in init_log
logger.addHandler(NullHandler())

CFG_TYPES = ['main', 'log']

COLORS = {
    'GREEN': '\033[0;36m',  # 32
    'RED': '\033[0;31m',
    'YELLOW': '\033[0;33m',  # 32
    'BLUE': '\033[0;34m',  #
    'VIOLET': '\033[0;35m',  #
    'BOLD': '\033[1m',
    'NC': '\033[0m',
}
_COLOR_TO_CODE = {
    'g': COLORS['GREEN'],
    'r': COLORS['RED'],
    'y': COLORS['YELLOW'],
    'b': COLORS['BLUE'],
    'v': COLORS['VIOLET'],
    'bold': COLORS['BOLD']
}


class ArgumentParser(argparse.ArgumentParser):

    def error(self, message):
        # self.print_help(sys.stderr)
        # self.print_usage(sys.stderr)
        print(self.format_usage().splitlines()[0])
        self.exit(2, color(f'\nerror: {message}\n', 'r'))


# Ref.: https://stackoverflow.com/a/32891625/14664104
class MyFormatter(argparse.RawDescriptionHelpFormatter):
    """
    Corrected _max_action_length for the indenting of subactions
    """

    def add_argument(self, action):
        if action.help is not argparse.SUPPRESS:

            # find all invocations
            get_invocation = self._format_action_invocation
            invocations = [get_invocation(action)]
            current_indent = self._current_indent
            for subaction in self._iter_indented_subactions(action):
                # compensate for the indent that will be added
                indent_chg = self._current_indent - current_indent
                added_indent = 'x' * indent_chg
                invocations.append(added_indent + get_invocation(subaction))
            # print('inv', invocations)

            # update the maximum item length
            invocation_length = max([len(s) for s in invocations])
            action_length = invocation_length + self._current_indent
            self._action_max_length = max(self._action_max_length,
                                          action_length)

            # add the item to the list
            self._add_item(self._format_action, [action])

    # Ref.: https://stackoverflow.com/a/23941599/14664104
    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            # if the Optional doesn't take a value, format is:
            #    -s, --long
            if action.nargs == 0:
                parts.extend(action.option_strings)

            # if the Optional takes a value, format is:
            #    -s ARGS, --long ARGS
            # change to
            #    -s, --long ARGS
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    # parts.append('%s %s' % (option_string, args_string))
                    parts.append('%s' % option_string)
                parts[-1] += ' %s'%args_string
            return ', '.join(parts)


def copy(src, dst, clobber=True):
    dst = Path(dst)
    if dst.exists():
        logger.debug(f'{dst}: file already exists')
        if clobber:
            logger.debug(f'{dst}: overwriting the file')
            shutil.copy(src, dst)
        else:
            logger.debug(f'{dst}: cannot overwrite existing file')
    else:
        logger.debug(f'Copying the file')
        shutil.copy(src, dst)


def get_config_dict(cfg_type='main', configs_dirpath=None):
    return load_cfg_dict(get_config_filepath(cfg_type, configs_dirpath), cfg_type)


def get_config_filepath(cfg_type='main', configs_dirpath=None):
    if cfg_type == 'main':
        cfg_filepath = get_main_config_filepath(configs_dirpath)
    elif cfg_type == 'log':
        cfg_filepath = get_logging_filepath(configs_dirpath)
    else:
        raise ValueError(f"Invalid cfg_type: {cfg_type}")
    return cfg_filepath


def get_settings(conf, cfg_type):
    if cfg_type == 'log':
        # set_logging_field_width(conf['logging'])
        return conf['logging']
    elif cfg_type == 'main':
        _settings = {}
        for opt_name, opt_value in conf.items():
            if opt_name.startswith('__') and opt_name.endswith('__'):
                continue
            elif isinstance(opt_value, type(os)):
                # e.g. import config
                continue
            else:
                _settings.setdefault(opt_name, opt_value)
        return _settings
    else:
        raise ValueError(f"Invalid cfg_type: {cfg_type}")


def load_cfg_dict(cfg_filepath, cfg_type):

    def _load_cfg_dict(cfg_filepath, cfg_type):
        if file_ext == '.py':
            cfg_dict = run_path(cfg_filepath)
            cfg_dict = get_settings(cfg_dict, cfg_type)
        elif file_ext == '.json':
            cfg_dict = load_json(cfg_filepath)
        else:
            raise TypeError("Config file extension not supported: "
                            f"{cfg_filepath}")
        return cfg_dict

    configs_dirpath = Path(cfg_filepath).parent
    assert cfg_type in CFG_TYPES, f"Invalid cfg_type: {cfg_type}"
    _, file_ext = os.path.splitext(cfg_filepath)
    try:
        cfg_dict = _load_cfg_dict(cfg_filepath, cfg_type)
    except FileNotFoundError as e:
        # Copy it from the default one
        # TODO: IMPORTANT destination with default?
        if cfg_type == 'main':
            src = get_main_config_filepath(configs_dirpath, default_config=True)
        else:
            src = get_logging_filepath(configs_dirpath, default_config=True)
        shutil.copy(src, cfg_filepath)
        print(f"Config file created: {cfg_filepath}")
        cfg_dict = _load_cfg_dict(cfg_filepath, cfg_type)
    return cfg_dict


def load_json(filepath, encoding='utf8'):
    """Load JSON data from a file on disk.

    If using Python version betwee 3.0 and 3.6 (inclusive), the data is
    returned as :obj:`collections.OrderedDict`. Otherwise, the data is
    returned as :obj:`dict`.

    Parameters
    ----------
    filepath : str
        Path to the JSON file which will be read.
    encoding : str, optional
        Encoding to be used for opening the JSON file in read mode (the default
        value is '*utf8*').

    Returns
    -------
    data : dict or collections.OrderedDict
        Data loaded from the JSON file.

    Raises
    ------
    OSError
        Raised if any I/O related error occurs while reading the file, e.g. the
        file doesn't exist.

    References
    ----------
    `Are dictionaries ordered in Python 3.6+? (stackoverflow)`_

    """
    try:
        with codecs.open(filepath, 'r', encoding) as f:
            if sys.version_info.major == 3 and sys.version_info.minor <= 6:
                data = json.load(f, object_pairs_hook=OrderedDict)
            else:
                data = json.load(f)
    except OSError:
        raise
    else:
        return data


def mkdir(path):
    # Since path can be relative to the cwd
    path = os.path.abspath(path)
    dirname = os.path.basename(path)
    if os.path.exists(path):
        logger.debug(f"Folder already exits: {path}")
        logger.debug(f"Skipping it!")
    else:
        logger.debug(f"Creating folder '{dirname}': {path}")
        os.mkdir(path)
        logger.debug("Folder created!")


def namespace_to_dict(ns):
    namspace_classes = [Namespace, SimpleNamespace]
    # TODO: check why not working anymore
    # if isinstance(ns, SimpleNamespace):
    if type(ns) in namspace_classes:
        adict = vars(ns)
    else:
        adict = ns
    for k, v in adict.items():
        # if isinstance(v, SimpleNamespace):
        if type(v) in namspace_classes:
            v = vars(v)
            adict[k] = v
        if isinstance(v, dict):
            namespace_to_dict(v)
    return adict


def override_config_with_args(main_config, args, default_config, use_config=False):

    def process_user_args(user_args):

        def get_opt_val(opt_name, cfg_dict, default=False):
            default_val = 'not_found' if default else None
            opt_val = cfg_dict.get(opt_name, 'not_found')
            if opt_val == 'not_found' and args.get('subcommand'):
                    opt_val = cfg_dict.get(args['subcommand'], {}).get(
                        opt_name, default_val)
            return opt_val

        for arg_name, arg_val in list(user_args.items()):
            """
            if arg_name in ignored_args:
                continue
            """
            if isinstance(arg_val, dict):
                if args['subcommand'] == arg_name:
                    process_user_args(arg_val)
                    del config[args['subcommand']]
                else:
                    del config[arg_name]
                continue
            arg_val = get_opt_val(arg_name, user_args)
            default_val = get_opt_val(arg_name, default_config, default=True)
            if arg_val is not None:
                if arg_val != default_val:
                    # User specified a value in the command-line/config file
                    config[arg_name] = arg_val
                    if default_val == 'not_found':
                        results.args_not_found_in_config.append((arg_name, default_val, arg_val))
                    else:
                        results.default_args_overridden.append((arg_name, default_val, arg_val))
                else:
                    # User didn't change the config value (same as default one)
                    # TODO: factorize
                    if config.get(arg_name, 'not_found') != 'not_found':
                        config[arg_name] = arg_val
                    else:
                        config.setdefault(arg_name, arg_val)
            else:
                if default_val != 'not_found':
                    if config.get(arg_name, 'not_found') != 'not_found':
                        config[arg_name] = default_val
                    else:
                        config.setdefault(arg_name, default_val)
                else:
                    raise AttributeError("No value could be found for the "
                                         f"argument '{arg_name}'")

    # ignored_args = ['func', 'subparser_name']
    # If config is Namespace
    main_config = vars(main_config)
    args = args.__dict__
    results = namedtuple("results", "args_not_found_in_config default_args_overridden msg")
    results.args_not_found_in_config = []
    results.default_args_overridden = []
    if use_config:
        results.msg = 'Default arguments overridden by config options:\n'
        config_keys = set()
        for k, v in main_config.items():
            if isinstance(v, dict):
                config_keys.update(list(v.keys()))
        for k, v in args.items():
            if k not in config_keys:
                main_config.setdefault(k, v)
        config = main_config
        user_args = main_config
    else:
        results.msg = 'Default arguments overridden by command-line arguments:\n'
        config = args.copy()
        user_args = config
        # Remove subdicts (e.g. fix or organize)
        for k, v in list(main_config.items()):
            if isinstance(v, dict):
                del main_config[k]
    process_user_args(user_args)
    main_config.update(config)
    return results


def process_returned_values(returned_values):
    def log_opts_overridden(opts_overridden, msg, log_level='debug'):
        nb_items = len(opts_overridden)
        for i, (cfg_name, old_v, new_v) in enumerate(opts_overridden):
            msg += f'\t {cfg_name}: {old_v} --> {new_v}'
            if i + 1 < nb_items:
                msg += "\n"
        getattr(logger, log_level)(msg)

    # Process default args overridden by command-line args/config options
    if returned_values.default_args_overridden:
        msg = returned_values.msg
        log_opts_overridden(returned_values.default_args_overridden, msg)
    # Process arguments not found in config file
    if returned_values.args_not_found_in_config and True:
        msg = 'Command-line arguments not found in config file:\n'
        log_opts_overridden(returned_values.args_not_found_in_config, msg)


def prog_name(filename):
    return filename.split('.py')[0]


def remove_file(file_path):
    # TODO add reference: https://stackoverflow.com/a/42641792
    try:
        os.remove(file_path)
        return 0
    except OSError as e:
        logger.error(f'Error: {e.filename} - {e.strerror}.')
        return 1


def run_cmd(cmd):
    """Run a shell command with arguments.

    The shell command is given as a string but the function will split it in
    order to get a list having the name of the command and its arguments as
    items.

    Parameters
    ----------
    cmd : str
        Command to be executed, e.g. ::

            open -a TextEdit text.txt

    Returns
    -------
    retcode: int
        Returns code which is 0 if the command was successfully completed.
        Otherwise, the return code is non-zero.

    Raises
    ------
    FileNotFoundError
        Raised if the command ``cmd`` is not recognized, e.g.
        ``$ TextEdit {filepath}`` since `TextEdit` is not an executable.

    """
    try:
        if sys.version_info.major == 3 and sys.version_info.minor <= 6:
            # TODO: PIPE not working as arguments and capture_output new in
            # Python 3.7
            # Ref.: https://stackoverflow.com/a/53209196
            #       https://bit.ly/3lvdGlG
            result = subprocess.run(shlex.split(cmd))
        else:
            result = subprocess.run(shlex.split(cmd), capture_output=True)
    except FileNotFoundError:
        raise
    else:
        return result


def setup_log(package=None, configs_dirpath=None, quiet=False, verbose=False,
              log_level=None, log_format=None, subcommand=None):
    package_path = os.getcwd()
    log_filepath = get_logging_filepath(configs_dirpath)
    main_cfg_msg = f"Main config path: {get_main_config_filepath(configs_dirpath)}"
    main_log_msg = f'Logging path: {log_filepath}'
    # Get logging cfg dict
    log_dict = load_cfg_dict(log_filepath, cfg_type='log')
    # NOTE: if quiet and verbose are both activated, only quiet will have an effect
    # TODO: get first cfg_dict to setup log (same in train_models.py)
    if not quiet:
        if verbose:
            # verbose supercedes log_level
            set_logging_level(log_dict, level='DEBUG')
        else:
            if log_level:
                log_level = log_level.upper()
                # TODO: add console_for_users at the top
                set_logging_level(log_dict, level=log_level)
        if log_format:
            set_logging_formatter(log_dict, formatter=log_format)
        if subcommand:
            # TODO: scripts.monitor and monitoring (package name) at the top?
            size_longest_name = len('scripts.monitor')
            for log_name, _ in log_dict['loggers'].items():
                if log_name.startswith(f'monitoring') and subcommand in log_name:
                    size_longest_name = max(size_longest_name, len(log_name))
        else:
            size_longest_name = None
        set_logging_field_width(log_dict, size_longest_name)
        # Load logging config dict
        logging.config.dictConfig(log_dict)
    # =============
    # Start logging
    # =============
    if package:
        if type(package) == str:
            package = importlib.import_module(package)
        logger.info("Running {} v{}".format(package.__name__,
                                            package.__version__))
    logger.info("Verbose option {}".format(
        "enabled" if verbose else "disabled"))
    logger.debug("Working directory: {}".format(package_path))
    logger.debug(main_cfg_msg)
    logger.debug(main_log_msg)


# ------
# Colors
# ------
def color(msg, msg_color='y', bold=False):
    msg_color = msg_color.lower()
    colors = list(_COLOR_TO_CODE.keys())
    assert msg_color in colors, f'Wrong color: {msg_color}. Only these colors are ' \
                                f'supported: {msg_color}'
    if bold:
        msg = f"{COLORS['BOLD']}{msg}{COLORS['NC']}"
    return f"{_COLOR_TO_CODE[msg_color]}{msg}{COLORS['NC']}"


def error(msg):
    return f"ERROR {red(msg)}"


def warning(msg):
    return f"WARNING {yellow(msg)}"


def default(default_value):
    msg = f"default: {default_value}"
    return f" ({color(msg, 'g')})"


def important():
    return f'''
{color("IMPORTANT:", "r")} this code is for educational and informational purposes only. The
author, raul23, assumes no responsibility for the use of this code or any information 
contained therein. The user is solely responsible for any action he/she takes with this 
code and information contained in it.'''


def usage(script_filename):
    msg = f"{prog_name(script_filename)} [OPTIONS]"
    return f"{color(msg, 'b')}"


def blue(msg):
    return f"{color(msg, 'b')}"


def green(msg):
    return f"{color(msg, 'g')}"


def red(msg):
    return f"{color(msg, 'r')}"


def yellow(msg):
    return f"{color(msg)}"


# -------------------------------
# Configs: dirpaths and filepaths
# -------------------------------
def get_configs_dirpath():
    from monitoring.configs import __path__
    return __path__[0]


def get_logging_filepath(configs_dirpath=None, default_config=False):
    configs_dirpath = get_configs_dirpath() if configs_dirpath is None else configs_dirpath
    if default_config and not os.path.exists(os.path.join(configs_dirpath, 'default_logging.py')):
        default_config = True
        configs_dirpath = get_configs_dirpath()
    if default_config:
        return os.path.join(configs_dirpath, 'default_logging.py')
    else:
        return os.path.join(configs_dirpath, 'logging.py')


def get_main_config_filepath(configs_dirpath=None, default_config=False):
    configs_dirpath = get_configs_dirpath() if configs_dirpath is None else configs_dirpath
    if default_config and not os.path.exists(os.path.join(configs_dirpath, 'default_config.py')):
        default_config = True
        configs_dirpath = get_configs_dirpath()
    if default_config:
        return os.path.join(configs_dirpath, 'default_config.py')
    else:
        return os.path.join(configs_dirpath, 'config.py')
