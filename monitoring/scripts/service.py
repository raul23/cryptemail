#!/usr/bin/env python
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from datetime import datetime

# TODO: important, add logger
ALERTS_PATH = os.path.expanduser('~/alerts.txt')
LOGS_PATH = os.path.expanduser('~/logs.txt')

# ========
# Database
# ========
DB_NAME = 'report.db'
TABLE_NAME = 'alerts'


def actual_timestamp_exists(conn, table_name, actual_timestamp):
    c = conn.cursor()
    # TODO: check table_name exist
    sql = "SELECT count(actual_timestamp) FROM {} WHERE actual_timestamp=?".format(table_name)
    c.execute(sql, (actual_timestamp,))
    result = c.fetchone()
    if result[0] == 1:
        return True
    else:
        return False


def add_timestamp(msg):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return '{}  {}'.format(timestamp, msg)


def alert(msg, use_timestamp=True):
    msg = add_timestamp(msg) if use_timestamp else msg
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


def log(msg, level='info', use_timestamp=True):
    level = level.upper() + ' :' if level == 'info' else level.upper() + ':'
    msg = add_timestamp(msg) if use_timestamp else msg
    os.system('echo {} {} >> {}'.format(level, msg, LOGS_PATH))


def table_exists(conn, table_name):
    c = conn.cursor()
    sql = "SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?"
    c.execute(sql, (table_name,))
    result = c.fetchone()
    if result[0] == 1:
        return True
    else:
        return False


def insert_log(conn, table_name, values):
    c = conn.cursor()
    sql = '''INSERT INTO {} (actual_timestamp, detection_timestamp, process, 
    PID, message, user, error_number, alert_type) VALUES 
    (?, ?, ?, ?, ?, ?, ?, ?)'''.format(table_name)
    c.execute(sql, values)
    return c.lastrowid


def main():
    exit_code = 0
    try:
        log('Starting!')
        last = '1m'
        number_of_args = 2
        regex = r"(?P<timestamp>^\d[\d\-\s:\.]+)  (?P<process>\w+ \w+)(?P<PID>\[\d+\]): " \
                r"(?P<message>.+) <(?P<user>.+)> (?P<error_number>.+)"
        sleeping = 2
        sql_create_table = """CREATE TABLE IF NOT EXISTS {} (
                                  actual_timestamp text PRIMARY KEY NOT NULL,
                                  detection_timestamp text NOT NULL,
                                  process text NOT NULL,
                                  PID integer NOT NULL,
                                  message text NOT NULL,
                                  user text NOT NULL,
                                  error_number integer NOT NULL,
                                  alert_type text NOT NULL
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
                log("Table '{}' already exists".format(TABLE_NAME), 'debug')
            else:
                log("Creating the table '{}'".format(TABLE_NAME))
                create_table(conn, sql_create_table)
            while True:
                log('Executing log command', 'debug')
                cmd = "log show --last {} --style syslog --predicate \'{}\'".format(
                        last, config.predicate)
                try:
                    result = subprocess.check_output(shlex.split(cmd),
                                                     stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    log('Error with log command: {}'.format(e.__repr__()), 'error')
                    exit_code = 1
                    break
                detection_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                result = result.decode()
                # Don't include first '\n' which is for the row "Timestamp (process)[PID]"
                failed_login_counts = result.count('\n') - 1
                if failed_login_counts:
                    # alert('{} failed login detected!'.format(failed_login_counts))
                    matches = re.finditer(regex, result, re.MULTILINE)
                    for matchNum, match in enumerate(matches, start=1):
                        groupdict = match.groupdict()
                        # Check if the timestamp is already in the db
                        if actual_timestamp_exists(conn, TABLE_NAME, groupdict['timestamp']):
                            continue
                        values = (groupdict['timestamp'], detection_timestamp,
                                  groupdict['process'], groupdict['PID'],
                                  groupdict['message'], groupdict['user'],
                                  groupdict['error_number'], 'failed_login')
                        insert_log(conn, TABLE_NAME, values)
                        alert_msg1 = '{} \|\| {} {} {}'.format(detection_timestamp,
                                                               groupdict['timestamp'],
                                                               groupdict['message'],
                                                               groupdict['user'])
                        alert(alert_msg1, use_timestamp=False)
                        alert_msg2 = '{} {} {}'.format(groupdict['timestamp'], groupdict['message'], groupdict['user'])
                        os.system('osascript -e \'display notification "{}" with title "Alert"\''.format(alert_msg2))
                        # NOTE: groupdict.values() in 2.7 not in order (timestamp not first)
                else:
                    log('Nothing to report!', 'debug')
                log('Sleeping for {} seconds'.format(sleeping))
                time.sleep(sleeping)
        else:
            log('Wrong number ({}) of arguments. There should be {} '
                'arguments'.format(len(sys.argv), number_of_args), 'error')
        log('WARNING: Ending!')
    except sqlite3.Error as e:
        log(e, 'error')
        exit_code = 1
    except KeyboardInterrupt as e:
        log('Ctrl+c detected!')
    except Exception as e:
        if e.__repr__() == 'BdbQuit()':
            log('Quitting from ipdb')
        else:
            log('{}'.format(e), 'error')
        exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
