#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#
from abc import ABCMeta, abstractmethod
from file import *
from network_obj import *

class LogContainer:
    __metaclass__ = ABCMeta

    def __init__(self):
        self.files = []
        self.logs = []
        self.interfaces = []
        self.selected_interfaces = []
        self.bridges = []
        self.selected_bridges = []

    @abstractmethod
    def get_interfaces_files(self, standalone):
        '''
        Return the config files needed to configure interfaces
        '''
        pass

    def set_selected_interfaces(self, selected_interfaces, normalizer=None):
        #select user interfaces with user input in the loaded interfaces
        if not self.interfaces and normalizer:
            self.load_interfaces(normalizer)
        #if no particular interface is chosen get them all on all keyword
        if len(selected_interfaces) and "all" in selected_interfaces: 
            self.selected_interfaces = self.interfaces
        else:
            self.selected_interfaces = self.get_interfaces_from_names(selected_interfaces)

    def set_selected_bridges(self, selected_bridges, normalizer=None):
        #select bridges  with user input in the loaded bridges
        if not self.bridges and normalizer:
            self.load_bridges(normalizer)
        #if no particular bridge is chosen get them all on all keyword
        if len(selected_bridges) and "all" in selected_bridges: 
            self.selected_bridges = self.bridges
        else:
            self.selected_bridges = self.get_bridges_from_names(selected_bridges)

    def clear_selected_interfaces(self):
        self.selected_interfaces = []

    def clear_selected_bridges(self):
        self.selected_bridges = []

    def load_interfaces(self, normalizer, standalone=False):
        #loads all interfaces from interface conf files
        files_info = self.get_interfaces_files(standalone)
        for info in files_info:
            for data in File(info['name'], info['content']).normalize(normalizer, is_log=False,debug_context=True).data:
                if not self.find_interface(data):
                    if not data.has_key('linux_interface'):
                        continue
                    self.interfaces.append(Interface(data))
        return self

    def load_bridges(self, standalone=False):
        #loads all bridges from brctl conf files
        brctl_data = self.get_bridges_files(standalone)
        for line in brctl_data:
            line = line.split()
            if len(line) == 1:
                # if vlan interface given take the whole interface
                inf = self.get_if_object_from_name(line[0].split('.')[-1])
                if inf is not None:
                    inf.set_bridge(self.bridges[-1])
                    self.bridges[-1].add_if(inf)
            elif len(line) == 4:
                self.bridges.append(Bridge(line[0]))
                inf = self.get_if_object_from_name(line[-1].split('.')[-1])
                if inf is not None:
                    inf.set_bridge(self.bridges[-1])
                    self.bridges[-1].add_if(inf)
            else:
                logging.debug("Weird number of parameters in line from brctl show")
                continue
        return self

    def get_if_object_from_name(self, linux_name):
        for interface in self.interfaces:
            if interface.linux == linux_name:
                return interface

    def find_interface(self, data):
        for interface in self.interfaces:
            linux = data.get('linux_interface')
            if linux and interface.linux == linux:
                interface.update(data)
                return True
            sdk = data.get('sdk_interface')
            if sdk and interface.sdk == sdk:
                interface.update(data)
                return True
            id = data.get('id_interface')
            if id and interface.id == id:
                interface.update(data)
                return True
        return False

    def get_interfaces_from_names(self, interfaces_name):
        return [interface for interface in self.interfaces if
                (interface.linux and interfaces_name.count(interface.linux)) or (
                    interface.sdk and interfaces_name.count(interface.sdk))]

    def get_bridges_from_names(self, bridges_name):
        return [bridge for bridge in self.bridges if
                (bridge.name and bridges_name.count(bridge.name))]

    def normalize_files(self, normalizer, timestamp, interval, normalized_logs=None):
        for f in self.files:
            f.normalize(normalizer, timestamp, interval, True, True, normalized_logs)
        return self

    def sort_logs(self):
        for f in self.files:
            self.logs.extend(f.data)
        self.logs.sort(lambda l1, l2: int(l1.date - l2.date))
        return self
