#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#           Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#

import zmq
import rfc
from logcontainer import *
from slave import Slave
import logging
logging.basicConfig(filename='/var/log/pyjeet.log',level=logging.DEBUG)


class User:
    def __init__(self, username):
        self.name = username


class Host(LogContainer):
    def __init__(self, info):
        LogContainer.__init__(self)
        if not info.has_key('name') or not info.has_key('ip'):
            raise AttributeError, 'Missing host name or host ip.'
        self.name = info.get('name')
        self.ip = info.get('ip')
        self.port = info.get('port')
        self.users = {}
        self.client = None
        self.files = []

    def is_connected(self):
        return self.client != None

    def connect(self, context):
        if not self.client:
            self.client = context.socket(zmq.REQ)
            self.client.connect('tcp://' + str(self.ip) + ':' + str(self.port))

    def set_files(self, selected_files, unzip, standalone):
        if not standalone:
            files_content = self._get_files_content(selected_files)
            if files_content:
                for filename in files_content:
                    if files_content[filename].has_key('error'):
                        logging.warn('[' + self.name + '] Error: ' + filename + ': ' + files_content[filename]['error'])
                    else:
                        self.files.append(File(filename, files_content[filename]['content'], False))
        else:
            for filename in selected_files:
                # some log files do not end with .log find another mechanism
                if '..' in filename: #or not filename.endswith('log'):
                    logging.warn('[' + self.name + '] Error: ' + filename + ': Non-authorized file.')
                else:
                    self.files.append(File(filename, None, unzip))

    def _get_files_content(self, info):
        self.client.send_json(rfc.create_request('get_files', info))
        res = self.client.recv_json()
        if res and res['success'] and res.has_key('result'):
            return res['result']
        return None

    def get_interfaces_files(self, standalone):
        files = []
        if not standalone:
            if self.client:
                self.client.send_json(rfc.create_request('get_interfaces_files', None))
                res = self.client.recv_json()
                if res and res['success']:
                    for key in res['result']:
                        if not res['result'][key].has_key('error'):
                            files.append({'name': key, 'content': res['result'][key]['content']})
            return files
        else:
            for if_file in Slave.interface_files():
                files.append({'name': if_file, 'content': open(if_file, 'r')})
            return files

    def get_bridges_files(self, standalone):
        content = []
        if not standalone:
            if self.client:
               self.client.send_json(rfc.create_request('get_bridges_files', None))
               res = self.client.recv_json()
               if res and res['success']:
                   for key in res['result']:
                       if not res['result'][key].has_key('error'):
                           content.extend(res['result'][key]['content'])
            return files
        else:
            # if standalone no Slave but make use of slave static functions
            return open(Slave.bridges_files(), 'r')

    def get_users(self):
        for u in ['root', ]:  # download users list
            self.users[u] = User(u)
