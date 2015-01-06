#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#           Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#

from __future__ import with_statement
import os
import sys
import logging
logging.basicConfig(filename='/var/log/pyjeet.log',level=logging.DEBUG)
from log import Log


class File:
    def __init__(self, path, content=None, rotate=False):
        self.path = path
        self.data = []
        self.max_rotation = 10
        tmp = self.path.split('/')
        self.name = tmp[len(tmp) - 1]
        self.dir_path = "/var/log/pyjeet_temp"
        self.content = content is not None
        self.raw = None
        self._get_file_content(content, rotate)

    def _get_file_content(self, content, rotate):
        if content is not None:
            self.raw = content
        else:
            if rotate is False:
                try:
                    self.raw = open(self.path, 'r')
                except IOError as e:
                    logging.error(self.path + ': ' + e.strerror)
                    self.raw = None
            else:
                logging.info("Unzipping archived logs...")
                if not os.path.exists(self.dir_path):
                    os.makedirs(self.dir_path)
                filenames = self._get_rotated_files()
                with open(self.dir_path + "/" + self.name, 'w') as outfile:
                    #reversed because the highest number is the oldest log file
                    for fname in reversed(filenames):
                        try:
                            with open(fname) as infile:
                                for line in infile:
                                    outfile.write(line)
                        except EnvironmentError as e:
                            logging.error('Could not open:' + fname + ': ' + e.strerror)
                            continue
                try:
                    self.raw = open(self.dir_path + "/" + self.name, 'r')
                except IOError as e:
                    logging.error(self.path + ': ' + e.strerror)
                    self.raw = None

    def _get_rotated_files(self):
        rotation = 1
        rotated_files = [self.path]
        while rotation <= self.max_rotation: 
            path_to_unarchived = self.path + '.' + str(rotation)
            path_to_archive = path_to_unarchived + '.gz'
            if os.path.isfile(path_to_archive):
                archive_name = '.'.join(path_to_archive.split('/')[-1].split('.')[:-1]) 
                output_path = str(self.dir_path + '/' + archive_name)
                os.system("gunzip -c %(input)s > %(output)s" % {'input':path_to_archive, 'output':output_path})
                rotated_files.append(output_path)
            # sometimes you find non compressed rotated log
            elif os.path.isfile(path_to_unarchived):
                archive_name = path_to_unarchived.split('/')[-1] 
                output_path = str(self.dir_path + '/' + archive_name)
                os.system("cp %(input)s  %(output)s" % {'input':path_to_unarchived, 'output':output_path})
                rotated_files.append(output_path)
            rotation += 1
        return rotated_files

    def get_file_name(self):
        return self.name

    def get_path(self):
        return self.path

    def normalize(self, normalizer, timestamp=-1, interval=-1, is_log=True, debug_context=False, normalized_logs=None):
        last_valid_time = 0
        min = timestamp - interval
        max = timestamp + interval
        if self.raw:
            for line in self.raw:
                if not is_log:
                    self.data.append(normalizer.normalize({'raw': line[:-1] if not self.content else line}))
                else:
                    l = Log(self,
                            normalizer.normalize({'raw': line[:-1] if not self.content else line}))
                    if not l.date:
                        l.date = last_valid_time
                    else:
                        last_valid_time = l.date
                    if timestamp == -1 or interval == -1 or l.is_in_interval((min, max)):
                        self.data.append(l)
                if normalized_logs:
                    # increase current number of normalized logs
                    normalized_logs['number'] += 1
                    # increase chunk counter if needed, seen by load display thread
                    if normalized_logs['number'] % normalized_logs['chunk_size'] == 0:
                        normalized_logs['current_chunk'] += 1
        return self
