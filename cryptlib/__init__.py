import os
import platform
import sys

from cryptlib.utils.genutils import CFG_TYPES

__version__ = '0.1.0a1'
# For debugging purposes
__test_version__ = '0.1.0a1'
__project_name__ = 'cryptoemail'

# Project
# =======
# Project directory
PROJECT_DIR = os.path.expanduser(f'~/.{__project_name__}')
# Configuration files within project directory
CONFIG_PATH = os.path.join(PROJECT_DIR, CFG_TYPES['main']['user'])
LOGGING_PATH = os.path.join(PROJECT_DIR, CFG_TYPES['log']['user'])

# Logs
# ====
# Logs directory
if platform.system() == 'Darwin':
    LOGS_DIR = os.path.expanduser(f'~/Library/Logs/{__project_name__}')
elif platform.system() == 'Linux':
    LOGS_DIR = os.path.expanduser(f'{PROJECT_DIR/{__project_name__}}')
else:
    print(f'OS not supported: {platform.system()}')
    sys.exit(1)
# Logs file
LOGS_PATH = os.path.join(LOGS_DIR, 'logs.txt')
