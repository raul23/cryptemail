#!/usr/bin/env python
import os
import time
import sys


if __name__ == '__main__':
    if len(sys.argv) > 1:
        last = sys.argv[1]
        event_msg_contains = sys.argv[2]
        os.system('echo "{} {}" >> '.format(last, event_msg_contains) +
                  os.path.expanduser('~/foostore.txt'))
        time.sleep(1)
        """
        os.system(f"log show --last {last} --style syslog --predicate "
                  f"'eventMessage contains \"{event_msg_contains}\"'")
        """
