import copy
import logging
import os
import traceback
from logging import NullHandler, StreamHandler

# TODO: check why ImportError: cannot import name 'COLORS' from 'cryptlib.utils.genutils'
from cryptlib.utils import genutils
from genutils import COLORS, red


class Logger:
    def __init__(self, name, file_):
        self.logger = init_log(name, file_)
        self._removed_handlers = []

    def _add_handlers_back(self):
        """Add the removed handlers back to the logger.
        """
        for h in self._removed_handlers:
            self.logger.addHandler(h)
        self._removed_handlers.clear()

    def _keep_everything_but(self, handlers_to_remove):
        """TODO

        Parameters
        ----------
        handlers_to_remove : list of Handlers

        """
        if not isinstance(handlers_to_remove, list):
            raise TypeError("handlers_to_remove must be a list")
        # self._removed_handlers = []
        # IMPORTANT: TODO you are iterating throughout handlers which you are also
        # removing items from. Thus it is better to work on a copy of handlers
        # If you don't, there will items you won't process.
        # TODO: check also logutils.setup_basic_logger where I don't use 'type(h) in' but just 'h in'
        handlers = copy.copy(self.logger.handlers)
        for i, h in enumerate(handlers):
            if type(h) in handlers_to_remove:
                self._remove_handler(h)

    def _log(self, logging_fnc, msg, *args, **kwargs):
        raw_msg = self._remove_colors(msg)
        self._remove_everything_but(handlers_to_keep=[StreamHandler])
        if self.logger.handlers:
            # Call the message-logging function, e.g. logger.info()
            logging_fnc(msg, *args, **kwargs)
        # Add the removed non-console handlers back to the logger
        self._add_handlers_back()
        self._keep_everything_but(
            handlers_to_remove=[NullHandler, StreamHandler])
        # Log the non-colored message with the non-console handlers
        if self.logger.handlers:
            logging_fnc(raw_msg, *args, **kwargs)
        # Add the handlers back to the logger
        self._add_handlers_back()

    @staticmethod
    def _remove_colors(msg):
        for c in COLORS.values():
            msg = msg.replace(c, "")
        return msg

    def _remove_everything_but(self, handlers_to_keep):
        """TODO

        Parameters
        ----------
        handlers_to_keep : list of Handlers

        """
        if not isinstance(handlers_to_keep, list):
            raise TypeError("handlers_to_keep must be a list")
        # self._removed_handlers = []
        handlers = copy.copy(self.logger.handlers)
        for h in handlers:
            if not type(h) in handlers_to_keep:
                self._remove_handler(h)

    def _remove_handler(self, h):
        """Remove a handler from the logger.

        Parameters
        ----------
        h : logging.Handler
            The handler to be removed from the logger.

        """
        self._removed_handlers.append(h)
        self.logger.removeHandler(h)

    def debug(self, msg, *args, **kwargs):
        self._log(self.logger.debug, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log(self.logger.error, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._log(self.logger.info, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log(self.logger.warning, msg, *args, **kwargs)


# TODO: explain cases
def get_logger_name(module__name__, module___file__, package_name=None):
    if os.path.isabs(module___file__):
        # e.g. initcwd or editcfg
        module_name = os.path.splitext(os.path.basename(module___file__))[0]
        package_path = os.path.dirname(module___file__)
        package_name = os.path.basename(package_path)
        logger_name = "{}.{}".format(
            package_name,
            module_name)
    elif module__name__ == '__main__' or not module__name__.count('.'):
        # e.g. train_models.py or explore_data.py
        if package_name is None:
            package_name = os.path.basename(os.getcwd())
        logger_name = "{}.{}".format(
            package_name,
            os.path.splitext(module___file__)[0])
    elif module__name__.count('.') > 1:
        logger_name = '.'.join(module__name__.split('.')[-2:])
    else:
        # e.g. importing mlutils from train_models.py
        logger_name = module__name__
    return logger_name


def init_log(module__name__, module___file__=None, package_name=None):
    if module___file__:
        logger_ = logging.getLogger(get_logger_name(module__name__,
                                                    module___file__,
                                                    package_name))
    elif module__name__.count('.') > 1:
        logger_name = '.'.join(module__name__.split('.')[-2:])
        logger_ = logging.getLogger(logger_name)
    else:
        logger_ = logging.getLogger(module__name__)
    logger_.addHandler(NullHandler())
    return logger_


# TODO: change param name from nl to newline?
def log_error(logger, error, verbose, nl=False):
    if verbose:
        error_msg = traceback.format_exc().strip()
        if error_msg == 'NoneType: None':
            error_msg = error
        elif error.__str__() not in error_msg:
            error_msg += f'\n{error}'
    else:
        error_msg = red(error.__str__())
    if nl:
        error_msg += '\n'
    logger.error(red(error_msg))


# TODO: specify log_dict change inline
def set_logging_field_width(log_dict, size_longest_name=None):
    if not size_longest_name:
        names = log_dict['loggers'].keys()
        size_longest_name = len(max(names, key=len))
    for k, v in log_dict['formatters'].items():
        try:
            v['format'] = v['format'].format(auto_field_width=size_longest_name)
        except KeyError:
            continue


def set_logging_formatter(log_dict, handler_names=None, formatter='simple'):
    # TODO: assert handler_names and formatter
    """
    for handler_name in handler_names:
        log_dict['handlers'][handler_name]['formatter'] = formatter
    """
    handler_names = handler_names if handler_names else []
    for handler_name, handler_val in log_dict['handlers'].items():
        if not handler_names or handler_name in handler_names:
            handler_val['formatter'] = formatter


def set_logging_level(log_dict, handler_names=None, logger_names=None,
                      level='DEBUG'):
    # TODO: assert handler_names, logger_names and level
    handler_names = handler_names if handler_names else []
    logger_names = logger_names if logger_names else []
    keys = ['handlers', 'loggers']
    for k in keys:
        for name, val in log_dict[k].items():
            if (not handler_names and not logger_names) or \
                    (k == 'handlers' and (not handler_names or name in handler_names)) or \
                    (k == 'loggers' and (not logger_names or name in logger_names)):
                val['level'] = level
