#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#           Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#

import os
import zmq
import rfc
import logging
logging.basicConfig(filename='/var/log/pyjeet.log',level=logging.DEBUG)


class Slave:
    BASE_DIRECTORY = ''
    IPLINKSHOW_FILE = '/var/log/ip_link_show' 
    BRCTLSHOW_FILE = '/var/log/brctl_show'

    def __init__(self, args):
        self.args = args
        self.context = zmq.Context()
        self.server = self.context.socket(zmq.REP)
        self.server.bind('tcp://*:' + str(self.args.port))
        self.command = \
            {
                'get_files': self._get_files,
                'get_interfaces_files': self._get_interfaces_files,
                'get_bridges_files': self._get_bridges_files,
            }

    def run(self):
        while 42:
            try:
                req = self.server.recv_json()
                logging.info("Request received: %s" % str(req))
                if req:
                    result = self.command[req['command']](req['arg'] if 'arg' in req else [])
                    if result:
                        self.server.send_json(result)
            except Exception as e:
                logging.error("Error while processing request %s" % str(e))
                """
                Stayin' alive.
                Stayin' alive.
                Ah, ha, ha, ha,
                Stayin' alive.
                """

    # target_directory=BASE_DIRECTORY
    def _get_files(self, arg=None, from_base_dir=True):
        files = arg
        # if file not specified get all files in log directory
        if files is None:
            os.path.walk(self.BASE_DIRECTORY, self._get_files_list, files)
        result = {}
        for filename in files:
            if '..' in filename: # or (from_base_dir and not filename.endswith('log')):
                result[filename] = {'error': 'Non-authorized file.'}
            else:
                logging.info('GET/ %s' % filename)
                path = self.BASE_DIRECTORY + filename
                try:
                    content = []
                    raw = open(path, 'r')
                    for line in raw:
                        content.append(unicode(line[:-1], errors='replace'))
                    result[filename] = {'content': content}
                except IOError as e:
                    logging.error( path + ': ' + e.strerror)
                    result[filename] = {'error': e.strerror}
        return rfc.create_reply(True, result)

    # get all files in folders and subfolders
    def _get_files_list(self, arg, dirname, names):
        for name in names:
            arg.append(name)

    @staticmethod
    def _get_ip_link_show_path():
        os.system('ip -o addr show > ' + Slave.IPLINKSHOW_FILE)
        return Slave.IPLINKSHOW_FILE

    @staticmethod
    def _get_brctl_path():
        os.system('brctl show > ' + Slave.BRCTLSHOW_FILE)
        return Slave.BRCTLSHOW_FILE

    @staticmethod
    def _get_port_tab_path():
        return '/var/lib/cumulus/porttab'

    @staticmethod
    def interface_files():
        return [Slave._get_ip_link_show_path(), Slave._get_port_tab_path()]

    @staticmethod
    def bridges_files():
        return Slave._get_brctl_path()

    def _get_interfaces_files(self, arg):
        return self._get_files(self.interface_files(), False)

    def _get_bridges_files(self, arg):
        return self._get_files([self.bridges_files()], False)

    def clean(self):
        pass
