#!/usr/bin/env python
import os
import shlex
import subprocess
import sys
import time


def send_alert():
    pass


if __name__ == '__main__':
    os.system('echo "Starting!" >> ' + os.path.expanduser('~/foostore.txt'))
    if len(sys.argv) == 2 or True:
        # configs_path = sys.argv[1]
        configs_path = os.path.expanduser('~/mac-monitoring')
        sys.path.append(configs_path)
        import config
        sleeping = 5
        while True:
            os.system('echo "Executing log command" >> ' + os.path.expanduser('~/foostore.txt'))
            last = '220m'
            cmd = "log show --last {} --style syslog --predicate \'{}\'".format(
                    last, config.predicate)
            try:
                result = subprocess.check_output(shlex.split(cmd),
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                os.system('echo "Error with log command!" >> ' + os.path.expanduser('~/foostore.txt'))
                sys.exit(1)
            result = result.decode()
            # Don't include first '\n' which is for the row "Timestamp (process)[PID]"
            failed_login_counts = result.count('\n') - 1
            if failed_login_counts:
                os.system('echo "ALERT!" >> ' + os.path.expanduser('~/foostore.txt'))
                os.system('echo "{}" failed login >> '.format(failed_login_counts) + os.path.expanduser('~/foostore.txt'))
            else:
                os.system('echo "Nothing to report!" >> ' + os.path.expanduser('~/foostore.txt'))
            os.system('echo "Sleeping for {}" >> '.format(sleeping) + os.path.expanduser('~/foostore.txt'))
            time.sleep(sleeping)
    os.system('echo "Ending! Very odd!" >> ' + os.path.expanduser('~/foostore.txt'))
    sys.exit(0)
