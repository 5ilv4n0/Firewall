#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys



class Firewall(object):
    FW = '/sbin/iptables'
    if not os.path.exists(FW):
        print 'FW not found! Abort!'
        sys.exit()


    CHAINS = ['INPUT','FORWARD','OUTPUT','PREROUTING', 'POSTROUTING']
    MAIN_CHAINS = CHAINS[:3]

    counter = {}

    def __init__(self, wan_interface, policy='DROP'):
        self.policy = policy
        self.wan_interface = wan_interface

        self.flush()
        self.set_policy(self.policy)
        self.allow_loopback()

        self.enable_stateful_filtering('INPUT')
        self.enable_stateful_filtering('OUTPUT')

        self.prepare_FW_2_WAN_chain()
        self.prepare_WAN_2_FW_chain()


    #os.system('iptables -I INPUT ! -i lo -s 127.0.0.0/8 -j DROP')


        self.create_chain('TRAFFIC_OUT')
        os.system(self.FW + ' -A TRAFFIC_OUT -p tcp')
        os.system(self.FW + ' -A TRAFFIC_OUT -p udp')
        os.system(self.FW + ' -A TRAFFIC_OUT -p icmp')

    def prepare_FW_2_WAN_chain(self):
        self.create_chain('FW_2_WAN')
        self.add_rule('FW_2_WAN', '', 'LOG', '--log-prefix "WALL: FW_2_WAN->DROP:" --log-level 6')
        self.add_rule('FW_2_WAN', '', self.policy)
        self.add_rule('OUTPUT', '-o ' + self.wan_interface, 'FW_2_WAN')

    def prepare_WAN_2_FW_chain(self):
        self.create_chain('WAN_2_FW')
        self.add_rule('WAN_2_FW', '', 'LOG', '--log-prefix "WALL: WAN_2_FW->DROP:" --log-level 6')
        self.add_rule('WAN_2_FW', '', self.policy)
        self.add_rule('INPUT', '-i ' + self.wan_interface, 'WAN_2_FW')


    def insert_outgoing_rule(self, protocol, destination_port, accept, logging=False):
        if destination_port == -1 or destination_port == 'all':
            destination_port = ''
        else:
            destination_port = ' --dport ' + str(destination_port)

        target = 'DROP'
        if accept:
            target = 'ACCEPT'
        match = '-p ' + protocol + destination_port
        self.insert_rule(self.counter['FW_2_WAN'], 'FW_2_WAN', match, target, target_parameter='')
        self.counter['FW_2_WAN'] += 1
        if logging:
            self.insert_rule(self.counter['FW_2_WAN'], 'FW_2_WAN', match, 'LOG', '--log-prefix "WALL: FW_2_WAN['+protocol+'('+str(destination_port)+')]->'+target+':" --log-level 6')
            self.counter['FW_2_WAN'] += 1

    def insert_incoming_rule(self, protocol, destination_port, accept, logging=False):
        if destination_port == -1 or destination_port == 'all':
            destination_port = ''
        else:
            destination_port = ' --dport ' + str(destination_port)

        target = 'DROP'
        if accept:
            target = 'ACCEPT'
        match = '-p ' + protocol + destination_port
        self.insert_rule(self.counter['WAN_2_FW'], 'WAN_2_FW', match, target, target_parameter='')
        self.counter['WAN_2_FW'] += 1
        if logging:
            self.insert_rule(self.counter['WAN_2_FW'], 'WAN_2_FW', match, 'LOG', '--log-prefix "WALL: WAN_2_FW['+protocol+'('+str(destination_port)+')]->'+target+':" --log-level 6')
            self.counter['WAN_2_FW'] += 1



    def activate_traffic_accounting(self):
        self.insert_rule(1, 'OUTPUT', '', 'TRAFFIC_OUT')


    def flush(self):
        commands = ['-F','-X','-t nat -F']
        for parameter in commands:
            command = self.FW + ' ' + parameter
            result = self.__execute(command)

    def set_policy(self, policy):
        for chain in self.MAIN_CHAINS:
            template = [self.FW, '-P', chain, policy]
            command = ' '.join(template)
            result = self.__execute(command)

    def enable_stateful_filtering(self, chain):
        #self.add_rule(chain, '-m state --state ESTABLISHED,RELATED', 'ACCEPT')
        self.add_rule(chain, '-m conntrack --ctstate RELATED,ESTABLISHED', 'ACCEPT')

    def allow_loopback(self):
        self.add_rule('INPUT', '-i lo', 'ACCEPT')

    def add_rule(self, chain, match, target, target_parameter=''):
        template = [self.FW, '-A', chain, match, '-j', target, target_parameter]
        command = ' '.join(template)
        self.__execute(command)

    def insert_rule(self, id, chain, match, target, target_parameter=''):
        template = [self.FW, '-I', chain, str(id), match, '-j', target, target_parameter]
        command = ' '.join(template)
        self.__execute(command)

    def create_chain(self, name):
        self.counter[name] = 1
        command = self.FW + ' -N ' + name
        self.__execute(command)

    def __execute(self, command):
        result = True
        if os.popen(command).read() != '':
            result = False
        print result, repr(command)
        return result

    def __del__(self):
        pass
        #self.flush()
        #self.set_policy('ACCEPT')



ACCEPT = 'ACCEPT'
DROP = 'DROP'


fw = Firewall('wlan0')

fw.insert_outgoing_rule('icmp', 'all', ACCEPT)
fw.insert_outgoing_rule('tcp', 'all', ACCEPT)
fw.insert_outgoing_rule('udp', 'all', ACCEPT)
fw.activate_traffic_accounting()



fw.insert_incoming_rule('icmp', 'all', ACCEPT)
fw.insert_incoming_rule('tcp', 22, ACCEPT)
fw.insert_incoming_rule('tcp', 443, ACCEPT)
fw.insert_incoming_rule('tcp', 8080, ACCEPT)
fw.insert_incoming_rule('tcp', 8023, ACCEPT)
fw.insert_incoming_rule('tcp', 8784, ACCEPT)
fw.insert_incoming_rule('tcp', 10443, ACCEPT)
fw.insert_incoming_rule('tcp', 8081, ACCEPT)
fw.insert_incoming_rule('udp', 1194, ACCEPT)
