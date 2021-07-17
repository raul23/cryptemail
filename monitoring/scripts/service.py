#!/usr/bin/env python
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time

# TODO: important, add logger
ALERTS_PATH = os.path.expanduser('~/alerts.txt')
LOGS_PATH = os.path.expanduser('~/logs.txt')

# ========
# Database
# ========
DB_NAME = 'report.db'
TABLE_NAME = 'alerts'


def alert(msg):
    os.system('echo {} >> {}'.format(msg, ALERTS_PATH))


def connect_db(db_path, isolation_level=None):
    try:
        # By default isolation_level is None, i.e. it will leave the underlying
        # sqlite3 library operating in autocommit mode
        # Ref.: https://bit.ly/2mg5Hie
        conn = sqlite3.connect(db_path, isolation_level=isolation_level)
    except sqlite3.Error:
        raise
    else:
        return conn


def create_table(conn, create_table_sql):
    c = conn.cursor()
    c.execute(create_table_sql)


def log(msg):
    os.system('echo {} >> {}'.format(msg, LOGS_PATH))


def table_exists(conn, table_name):
    c = conn.cursor()
    sql = "SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?"
    c.execute(sql, (table_name,))
    result = c.fetchone()
    if result[0] == 1:
        return True
    else:
        return False


def main():
    exit_code = 0
    try:
        log('INFO : Starting!')
        last = '20m'
        number_of_args = 2
        regex = r"(?P<timestamp>^\d[\d\-\s:\.]+)  (?P<process>\w+ \w+)(?P<PID>\[\d+\]): " \
                r"(?P<message>.+) <(?P<user>.+)> (?P<error_number>.+)"
        sleeping = 2
        sql_create_table = """CREATE TABLE IF NOT EXISTS {} (
                                  long_timestamp text PRIMARY KEY NOT NULL,
                                  short_timestamp text NOT NULL,
                                  process text NOT NULL,
                                  PID integer NOT NULL,
                                  message text NOT NULL,
                                  user text NOT NULL,
                                  error_number integer NOT NULL
                              );""".format(TABLE_NAME)
        if len(sys.argv) == number_of_args or True:
            # configs_path = sys.argv[1]
            configs_path = os.path.expanduser('~/mac-monitoring')
            sys.path.append(configs_path)
            import config
            # Connect to database
            db_path = os.path.join(configs_path, DB_NAME)
            conn = connect_db(db_path)
            # Check if table exists
            if table_exists(conn, TABLE_NAME):
                log("DEBUG: Table '{}' already exists".format(TABLE_NAME))
            else:
                log("INFO : Creating the table '{}'".format(TABLE_NAME))
                create_table(conn, sql_create_table)
            while True:
                log('DEBUG: Executing log command')
                cmd = "log show --last {} --style syslog --predicate \'{}\'".format(
                        last, config.predicate)
                try:
                    result = subprocess.check_output(shlex.split(cmd),
                                                     stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    log('ERROR: Error with log command: {}'.format(e.__repr__()))
                    exit_code = 1
                    break
                result = result.decode()
                # Don't include first '\n' which is for the row "Timestamp (process)[PID]"
                failed_login_counts = result.count('\n') - 1
                if failed_login_counts:
                    alert('ALERT: {} failed login detected!'.format(failed_login_counts))
                    """
                    matches = re.finditer(regex, result, re.MULTILINE)
                    for matchNum, match in enumerate(matches, start=1):
                        groupdict = match.groupdict()
                    """
                else:
                    log('DEBUG: Nothing to report!')
                log('INFO : Sleeping for {} seconds'.format(sleeping))
                time.sleep(sleeping)
        else:
            log('ERROR: Wrong number ({}) of arguments. There should be {} '
                'arguments'.format(len(sys.argv), number_of_args))
        log('WARNING: Ending!')
    except sqlite3.Error as e:
        log(e)
        exit_code = 1
    except KeyboardInterrupt as e:
        log('INFO : Ctrl+c detected!')
    except Exception as e:
        if e.__repr__() == 'BdbQuit()':
            log('INFO : Quitting from ipdb')
        else:
            log('ERROR: {}'.format(e))
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
