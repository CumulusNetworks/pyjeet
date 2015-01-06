#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#


def create_request(command, arg):
    return \
        {
            'command': command,
            'arg': arg,
        }


def create_reply(success, result):
    return \
        {
            'success': success,
            'result': result,
        }