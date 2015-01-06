#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#           Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#

import time
import json
import datetime


class Message(object):
    def __init__(self, data, types=[]):
        self.body = data.get('body')
        self.raw = data.get('raw')
        self.types = types


CATEGORIES = \
    {
        'Message': Message,
    }


class Ignored(Exception):
    def __init__(self, error):
        self._error = error

    def __str__(self):
        return 'Ignored: ' + str(self._error)


class Log:
    def __init__(self, filename, data):
        self.data = data
        if not 'category' in data or data['category'] not in CATEGORIES:
            data['category'] = 'Message'
        self.raw = data['raw']
        self.date = (data['date'] if type(data['date']) == float else time.mktime(data['date'].timetuple())) \
            if 'date' in data else 0.0
        self.context = LogContext(filename, data)
        self.process = LogProcess(data)
        self.priority = LogPriority(data)
        self.message = CATEGORIES[data['category']](data)

        if not self.process.name:
            self.process.name = self.priority.get_facility()

    def verbose_date(self):
        try:
            return datetime.datetime.fromtimestamp(self.date).strftime('%Y-%m-%d %H:%M:%S')
        except TypeError:
            return None

    def to_JSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    def is_in_interval(self, required_interval):
        if self.date:
            return required_interval[0] < self.date < required_interval[1]


class LogError(Exception):
    def __init__(self, error):
        self._error = error

    def __str__(self):
        return 'LogError: ' + str(self._error)


class LogProcess:
    def __init__(self, data):
        self.filename = data.get('filename')
        self.fileline = data.get('fileline')
        self.name = data.get('process')
        self.user = data.get('user')
        self.pid = data.get('pid')


class LogContext:
    def __init__(self, filename, data):
        self.logfile = filename.path
        self.root_file = filename
        self.patterns = data.get('patterns')
        self.normalizers = data.get('normalizers')
        self.description = data.get('taxonomy')


class LogPriority:
    FACILITIES = \
        {
            0: 'kernel',
            1: 'user',
            2: 'mail',
            3: 'daemon',
            4: 'auth',
            5: 'syslog',
            6: 'print',
            7: 'news',
            8: 'uucp',
            9: 'ntp',
            10: 'secure',
            11: 'ftp',
            12: 'ntp',
            13: 'audit',
            14: 'alert',
            15: 'ntp',
            16: 'local0',
            17: 'local1',
            18: 'local2',
            19: 'local3',
            20: 'local4',
            21: 'local5',
            22: 'local6',
            23: 'local7',
        }

    SEVERITIES = \
        {
            0: 'emerg',
            1: 'alert',
            2: 'crit',
            3: 'error',
            4: 'warn',
            5: 'notice',
            6: 'info',
            7: 'debug'
        }

    def __init__(self, data):
        self.severity = int(data['severity_code']) % 8 if 'severity_code' in data else data.get('severity', -1)
        self.facility = int(data['facility_code']) / 8 if 'facility_code' in data else data.get('facility', -1)

        if (self.severity != -1 and self.severity not in self.SEVERITIES) or \
                (self.facility != -1 and self.facility not in self.FACILITIES):
            raise ValueError, 'LogError: facility(' + str(self.facility) + ') or severity(' + str(
                self.severity) + ') is out of range'

    def get_facility(self):
        return self.FACILITIES[self.facility] if self.facility != -1 else ''
