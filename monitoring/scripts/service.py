#!/usr/bin/env python
import shlex
import subprocess
import sys


def send_alert():
    pass


if __name__ == '__main__':
    if len(sys.argv) == 3:
        last = sys.argv[1]
        predicate = sys.argv[2]
        cmd = "log show --last {} --style syslog --predicate \'{}\'".format(
                last, predicate)
        try:
            result = subprocess.check_output(shlex.split(cmd),
                                             stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            sys.exit(1)
        import ipdb
        ipdb.set_trace()
        result = result.decode()
        if result.count('\n') > 1:
            pass
    sys.exit(0)
