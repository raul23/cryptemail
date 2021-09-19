import os
import platform
import sys

from cryptlib import __project_name__, __project_dir__

# Logs directory
if platform.system() == 'Darwin':
    LOGS_DIR = os.path.expanduser(f'~/Library/Logs/{__project_name__}')
elif platform.system() == 'Linux':
    LOGS_DIR = os.path.expanduser(f'{__project_dir__/{__project_name__}}')
else:
    print(f'OS not supported: {platform.system()}')
    sys.exit(1)
# Logs file
LOGS_PATH = os.path.join(LOGS_DIR, 'logs.txt')

logging = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters':
    {
        'console':
        {
          'format': '%(name)-{auto_field_width}s | %(levelname)-8s | %(message)s'
        },
        'console_time':
        {
          'format': '%(asctime)s | %(levelname)-8s | %(message)s'
        },
        'only_msg':
        {
          'format': '%(message)s'
        },
        'simple':
        {
          'format': '%(levelname)-8s %(message)s'
        },
        'simple2':
        {
          'format': '%(levelname)-8s | %(message)s'
        },
        'verbose':
        {
          'format': '%(asctime)s | %(name)-{auto_field_width}s | %(levelname)-8s | %(message)s'
        }
    },

    'handlers':
    {
        'console':
        {
          'level': 'WARNING',
          'class': 'logging.StreamHandler',
          'formatter': 'only_msg'
        },
        'console_only_msg':
        {
          'level': 'INFO',
          'class': 'logging.StreamHandler',
          'formatter': 'only_msg'
        },
        'file':
        {
          'level': 'INFO',
          'class': 'logging.FileHandler',
          'filename': LOGS_PATH,
          'mode': 'a',
          'formatter': 'verbose',
          'delay': True
        }
    },

    'loggers':
    {
        # --------------------------------------
        # Loggers using console_only_msg handler
        # --------------------------------------
        'data':
        {
          'level': 'INFO',
          'handlers': ['console_only_msg'],
          'propagate': False
        },
        # -----------------------------
        # Loggers using console handler
        # -----------------------------
        'cryptlib.edit':
        {
          'level': 'INFO',
          'handlers': ['console', 'file'],
          'propagate': False
        },
        'cryptemail.script':
        {
          'level': 'INFO',
          'handlers': ['console', 'file'],
          'propagate': False
        },
        'cryptemail.lib':
        {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'utils.genutils':
        {
          'level': 'INFO',
          'handlers': ['console', 'file'],
          'propagate': False
        },
    },

    'root':
    {
        'level': 'INFO',
        'handlers': ['console'],
        'propagate': False
    }
}
