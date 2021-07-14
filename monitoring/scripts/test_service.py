#!/usr/bin/env python
import os
import time


if __name__ == '__main__':
    os.system('echo "Hello!" >> ' + os.path.expanduser('~/foostore.txt'))
    time.sleep(1)
