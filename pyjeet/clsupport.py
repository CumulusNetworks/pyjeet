#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#

from logcontainer import *
import logging
logging.basicConfig(filename='/var/log/pyjeet.log',level=logging.DEBUG)


class Clsupport(LogContainer):
    def __init__(self, path_to_archive):
        LogContainer.__init__(self)
        self.path_to_archive = path_to_archive
        self.path_to_untar = None
        self.name = None
        self._get_name_from_path()
        self.untar()

    def _get_name_from_path(self):
        if "cl_support__" not in self.path_to_archive:
            raise ValueError("The given path does not point to a cl-support archive: %s" % self.path_to_archive)
        else:
            self.name = self.path_to_archive.split('/')[-1].split('_')[3] + '(cls)'
            self.path_to_untar = self.path_to_archive.split('.')[0]
            self.parent_path = '/'.join(self.path_to_untar.split('/')[:-1])

    def untar(self):
        os.system("tar -xf %(arch)s -C %(parent)s" % {'arch':self.path_to_archive, 'parent':self.parent_path})

    def get_interfaces_files(self, standalone):
        #get files from untared archive in config folder
        porttab = self.path_to_untar + "/support/porttab"
        ipaddr = self.path_to_untar + "/support/ip.addr"
        files = [{'name': porttab, 'content': open(porttab, 'r')}]
        files.append({'name': ipaddr, 'content': open(ipaddr, 'r')})
        return files

    def get_bridges_files(self, standalone):
        #get files from untared archive in config folder
        brctl_show = self.path_to_untar + "/support/brctl.show"
        return open(brctl_show, 'r')

    def set_files(self, selected_files, unzip):
        for filename in selected_files:
            path_to_file = self.path_to_untar + '/var/log/' + filename
            if not os.path.isfile(path_to_file):
                logging.warn('[' + self.name + '] Error: ' + path_to_file + ': File not found in clsupport')
                continue
            else:
                self.files.append(File(path_to_file, None, unzip))

    def clean(self):
        if os.path.exists(self.path_to_untar):
            os.system("rm -rf %s" % self.path_to_untar)
            pass
