#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys
import json

class Firewall(object):

    def __init__(self, **keyword_args):
        self.keyword_args = keyword_args

        self.policy = self.get_policy_from_keyword_args()
        self.chain_policies = self.get_chain_policies_from_keyword_args()

        self.flush()
        self.set_policy(self.policy,
                        INPUT=self.chain_policies['INPUT'],
                        FORWARD=self.chain_policies['FORWARD'],
                        OUTPUT=self.chain_policies['OUTPUT'])

        self.allow_loopback_input()
        self.deny_wrong_loopback_input()
        self.activate_statefull_firewall()

        self.wan_interface = self.get_wan_interface_from_keyword_args()
        self.lan_interfaces = self.get_lan_interfaces_from_keyword_args()

        if not self.lan_interfaces == False:
            self.init_forwarding()




    def get_policy_from_keyword_args(self):
        if 'POLICY' in self.keyword_args.keys():
            return self.keyword_args['POLICY']
        return False

    def get_chain_policies_from_keyword_args(self):
        chains = ['INPUT', 'FORWARD', 'OUTPUT']
        chain_policies = {'INPUT': self.policy, 'FORWARD': self.policy, 'OUTPUT': self.policy}
        for id, chain in enumerate(chains):
            try:
                chain_policies[chains[id]] = self.keyword_args[chains[id]]
            except KeyError:
                pass
        return chain_policies

    def flush(self):
        for rule in ('iptables -F', 'iptables -X', 'iptables -t nat -F'):
            self.execute(rule)

    def set_policy(self, policy, **keyword_args):
        if policy == False:
            policy = 'DROP'
        elif policy == True:
            policy = 'ACCEPT'

        rule_template = 'iptables -P '

        for chain in ('INPUT', 'FORWARD', 'OUTPUT'):
            if chain in keyword_args.keys():
                if keyword_args[chain]:
                    rule = (rule_template, chain, 'ACCEPT')
                else:
                    rule = (rule_template, chain, 'DROP')
            else:
                rule = (rule_template, chain, policy)

            command = ' '.join(rule)
            self.execute(command)

    def allow_loopback_input(self):
        return self.execute('iptables -A INPUT -i lo -j ACCEPT')

    def deny_wrong_loopback_input(self):
        return self.execute('iptables -I INPUT ! -i lo -s 127.0.0.0/8 -j DROP')

    def activate_statefull_firewall(self):
        rules = (   'iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
                    'iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
                    'iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        for rule in rules:
            self.execute(rule)

    def init_forwarding(self):
        sysctl_command = 'sysctl -w net.ipv4.ip_forward=1'
        rule = 'iptables -t nat -A POSTROUTING -o ' + self.wan_interface + ' -j MASQUERADE'
        os.system(sysctl_command)
        self.execute(rule)

    def execute(self, command):
        if os.popen('sudo '+ command).read() != '':
            return False
        return True

    def get_lan_interfaces_from_keyword_args(self):
        try:
            lan_interfaces = self.keyword_args['LAN']
            if lan_interfaces == False:
                raise KeyError
            if ',' in lan_interfaces:
                lan_interfaces = lan_interfaces.split(',')
                return lan_interfaces
            else:
                return [lan_interfaces]
        except KeyError:
            print 'No LAN interface selected! Use local FW only!'
            return False

    def get_wan_interface_from_keyword_args(self):
        try:
            return self.keyword_args['WAN']
        except KeyError:
            print 'No WAN interface selected! Abort!'
            sys.exit(1)

    def input_rule(self, protocol, target_port=False, interface=False, accept=True):
        target = 'DROP'
        if accept == True:
            target = 'ACCEPT'
        elif accept == None:
            target = 'REJECT'
        rule = 'iptables -A INPUT '
        if not interface == False:
            rule += '-i ' + interface
        rule += ' -p ' + protocol
        if not target_port == False:
            rule += ' --dport ' + str(target_port)
        rule += ' -j ' + target
        self.execute(rule)

    def output_rule(self, protocol, target_port=False, interface=False, accept=True):
        target = 'DROP'
        if accept == True:
            target = 'ACCEPT'
        elif accept == None:
            target = 'REJECT'
        rule = 'iptables -A OUTPUT '
        if not interface == False:
            rule += '-o ' + interface
        rule += ' -p ' + protocol
        if not target_port == False:
            rule += ' --dport ' + str(target_port)
        rule += ' -j ' + target
        self.execute(rule)

    def forward_rule(self, lan_interface, network, protocol, target_port, accept=True):
        target = 'DROP'
        if accept == True:
            target = 'ACCEPT'
        elif accept == None:
            target = 'REJECT'
        rule = 'iptables -A FORWARD -i ' + lan_interface + ' -o ' + self.wan_interface + ' -s ' + network + ' -p ' + protocol + ' -m ' + protocol + ' --dport ' + str(target_port) + ' -j ' + target
        self.execute(rule)

    def port_forwarding_rule(self, protocol, extern_port, target_ip, target_port=False):
        rule_1 = 'iptables -t nat -A PREROUTING -i ' + self.wan_interface + ' -p ' + protocol + ' --dport ' + str(extern_port) + ' -j DNAT --to '+ target_ip
        if not target_port == False:
            rule_1 += ':' + str(target_port)
        else:
            target_port = extern_port
        rule_2 = 'iptables -A FORWARD -p ' + protocol + ' -d ' + target_ip + ' --dport ' + str(target_port) + ' -j ACCEPT'
        self.execute(rule_1)
        self.execute(rule_2)





















class Firewall2(object):
    FW = '/sbin/iptables'
    if not os.path.exists(FW):
        print 'FW not found! Abort!'
        sys.exit()


    CHAINS = ['INPUT','FORWARD','OUTPUT','PREROUTING', 'POSTROUTING']
    MAIN_CHAINS = CHAINS[:3]
    ACCEPT = 'ACCEPT'
    DROP = 'DROP'

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


    def activate_nat_traffic_from_intern(self):
        command = 'iptables -t nat -A POSTROUTING -o ' + self.wan_interface + ' -j MASQUERADE'
        self.__execute(command)

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
        self.add_rule('OUTPUT', '-o lo', 'ACCEPT')

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





# fw = Firewall2('wlan0')
#
# fw.insert_outgoing_rule('icmp', 'all', fw.ACCEPT)
# fw.insert_outgoing_rule('tcp', 'all', fw.ACCEPT)
# fw.insert_outgoing_rule('udp', 'all', fw.ACCEPT)
# fw.activate_traffic_accounting()
#
#
#
# fw.insert_incoming_rule('icmp', 'all', ACCEPT)
# fw.insert_incoming_rule('tcp', 22, ACCEPT)
# fw.insert_incoming_rule('tcp', 443, ACCEPT)
# fw.insert_incoming_rule('tcp', 8080, ACCEPT)
# fw.insert_incoming_rule('tcp', 8023, ACCEPT)
# fw.insert_incoming_rule('tcp', 8784, ACCEPT)
# fw.insert_incoming_rule('tcp', 10443, ACCEPT)
# fw.insert_incoming_rule('tcp', 8081, ACCEPT)
# fw.insert_incoming_rule('udp', 1194, ACCEPT)
