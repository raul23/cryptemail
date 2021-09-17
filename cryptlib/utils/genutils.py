"""General utilities
"""
import argparse
import codecs
import importlib
import json
import logging.config
import os
import shutil
import sys
from collections import namedtuple, OrderedDict
from logging import NullHandler
from pathlib import Path
from runpy import run_path

from cryptlib.utils.logutils import (init_log, set_logging_field_width,
                                     set_logging_formatter, set_logging_level)

logger = init_log(__name__, __file__)
# TODO: is next necessary? already done in init_log
logger.addHandler(NullHandler())

CFG_TYPES = {'main': {'default': 'default_config.py', 'user': 'config.py'},
             'log': {'default': 'default_logging.py', 'user': 'logging.py'}}

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
    except FileNotFoundError:
        # Copy it from the default one
        if cfg_type == 'main':
            src = get_main_config_filepath(configs_dirpath, default_config=True)
        else:
            src = get_logging_filepath(configs_dirpath, default_config=True)
        shutil.copy(src, cfg_filepath)
        # print(f"Config file created: {cfg_filepath}")
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
    if os.path.exists(path):
        logger.debug(f"Directory already exits: {path}")
    else:
        logger.debug(f"Creating directory '{path}'")
        os.mkdir(path)
        logger.info(f"Directory created: '{path}'")


def override_config_with_args(main_config, default_main_config, args):

    def process_user_args():

        def get_opt_val(opt_name, cfg_dict, use_config=False):
            if opt_name.find('.') != -1:
                if use_config:
                    keys = opt_name.split('.')
                    opt_val = cfg_dict
                    try:
                        for k in keys:
                            opt_val = opt_val[k]
                    except KeyError:
                        logger.debug(f"The option '{opt_name}' couldn't be "
                                     "found in the configuration file")
                    else:
                        return opt_val
                else:
                    return cfg_dict[opt_name]
            return cfg_dict.get(opt_name, 'not_found')

        def set_opt_val(opt_name, opt_val, cfg_dict):
            if opt_name.find('.') != -1:
                keys = opt_name.split('.')
                tmp_dict = cfg_dict
                for i, k in enumerate(keys):
                    if i == len(keys) - 1:
                        break
                    tmp_dict = tmp_dict[k]
                tmp_dict[keys[-1]] = opt_val
            else:
                cfg_dict[opt_name] = opt_val
            return opt_val

        for arg_name, arg_val in list(user_args.items()):
            arg_val = get_opt_val(arg_name, user_args)
            config_val = get_opt_val(arg_name, main_config, use_config=True)
            if arg_val is False and config_val is True:
                continue
            elif arg_val is not None:
                if arg_val != config_val:
                    # User specified a value in the command-line/config file
                    set_opt_val(arg_name, arg_val, main_config)
                    if config_val == 'not_found':
                        results.args_not_found_in_config.append((arg_name, config_val, arg_val))
                    else:
                        results.config_opts_overridden.append((arg_name, config_val, arg_val))
                # else: user didn't change the config value (same as default one)
            else:
                if config_val == 'not_found':
                    logger.debug("No value could be found for the "
                                 f"argument '{arg_name}'")
                    default_config_val = get_opt_val(arg_name, default_main_config, use_config=True)
                    if default_config_val == 'not_found':
                        set_opt_val(arg_name, arg_val, main_config)
                        results.args_not_found_in_config.append((arg_name, config_val, arg_val))
                    else:
                        set_opt_val(arg_name, default_config_val, main_config)
                        results.args_not_found_in_config.append((arg_name, config_val, default_config_val))

    def _get_dict(cfg):
        if isinstance(cfg, argparse.Namespace):
            # cfg = cfg.__dict__
            cfg = vars(cfg)
        return cfg

    main_config = _get_dict(main_config)
    default_main_config = _get_dict(default_main_config)
    args = _get_dict(args)
    results = namedtuple("results", "args_not_found_in_config config_opts_overridden")
    results.args_not_found_in_config = []
    results.config_opts_overridden = []
    user_args = args.copy()
    process_user_args()
    return results


def prog_name(filename):
    filename = Path(filename).name
    return filename.split('.py')[0]


def setup_log(package=None, script_name=None, log_filepath=None,
              configs_dirpath=None, quiet=False, verbose=False,
              logging_level=None, logging_formatter=None, subcommand=None,
              level_handler_names=None, formater_handler_names=None):
    if type(package) == str:
        package = importlib.import_module(package)
    package_path = os.getcwd()
    log_filepath = log_filepath if log_filepath else get_logging_filepath(configs_dirpath)
    main_log_msg = f'Logging path: {log_filepath}'
    # Get logging cfg dict
    log_dict = load_cfg_dict(log_filepath, cfg_type='log')
    # NOTE: if quiet and verbose are both activated, only quiet will have an effect
    if not quiet:
        if verbose:
            # verbose supercedes logging_level
            set_logging_level(log_dict, handler_names=level_handler_names, level='DEBUG')
        else:
            if logging_level:
                logging_level = logging_level.upper()
                set_logging_level(log_dict, handler_names=level_handler_names,
                                  level=logging_level)
        if logging_formatter:
            set_logging_formatter(log_dict, handler_names=formater_handler_names,
                                  formatter=logging_formatter)
        if subcommand:
            size_longest_name = max([len(key) for key in log_dict['loggers'].keys()])
            for log_name, _ in log_dict['loggers'].items():
                if log_name.startswith(package.__name__) and subcommand in log_name:
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
        script_name = script_name if script_name else package.__name__
        logger.debug("Running {} v{}".format(script_name,
                                             package.__version__))
    logger.debug("Verbose option {}".format(
        "enabled" if verbose else "disabled"))
    logger.debug("Working directory: {}".format(package_path))
    logger.debug(main_log_msg)


# ------
# Colors
# ------
def color(msg, msg_color='y', bold=False):
    msg_color = msg_color.lower()
    colors = list(_COLOR_TO_CODE.keys())
    assert msg_color in colors, f'Wrong color: {msg_color}. Only these ' \
                                f'colors are supported: {msg_color}'
    if bold:
        msg = f"{COLORS['BOLD']}{msg}{COLORS['NC']}"
    return f"{_COLOR_TO_CODE[msg_color]}{msg}{COLORS['NC']}"


def default(default_value):
    return green(f'(default: {default_value})')


def main_usage(script_filename):
    return blue(f'{prog_name(script_filename)} [-h] [-v] subcommand ...')


def subcommand_usage(script_filename, subcommand, required_args=''):
    return blue(f'{prog_name(script_filename)} {subcommand} [OPTIONS] {required_args}')


def blue(msg):
    return color(msg, 'b')


def bold(msg):
    return color(msg, 'bold')


def green(msg):
    return color(msg, 'g')


def red(msg):
    return color(msg, 'r')


def violet(msg):
    return color(msg, 'v')


def yellow(msg):
    return color(msg)


# -------------------------------
# Configs: dirpaths and filepaths
# -------------------------------
def get_configs_dirpath():
    from cryptlib.configs import __path__
    return __path__._path[0]


def get_logging_filepath(configs_dirpath=None, default_config=False):
    configs_dirpath = get_configs_dirpath() if configs_dirpath is None else configs_dirpath
    if default_config and not os.path.exists(os.path.join(configs_dirpath, CFG_TYPES['log']['default'])):
        default_config = True
        configs_dirpath = get_configs_dirpath()
    if default_config:
        return os.path.join(configs_dirpath, CFG_TYPES['log']['default'])
    else:
        return os.path.join(configs_dirpath, CFG_TYPES['log']['user'])


def get_main_config_filepath(configs_dirpath=None, default_config=False):
    configs_dirpath = get_configs_dirpath() if configs_dirpath is None else configs_dirpath
    if default_config and not os.path.exists(os.path.join(configs_dirpath, CFG_TYPES['main']['default'])):
        default_config = True
        configs_dirpath = get_configs_dirpath()
    if default_config:
        return os.path.join(configs_dirpath, CFG_TYPES['main']['default'])
    else:
        return os.path.join(configs_dirpath, CFG_TYPES['main']['user'])
