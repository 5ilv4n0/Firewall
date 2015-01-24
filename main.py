#!/usr/bin/env python
# -*- coding: utf-8 -*-

from firewall import Firewall

fw = Firewall(WAN='wlan0', POLICY=True)

fw.input_rule('tcp', 80, 'wlan0', False)
fw.output_rule('tcp', 22, 'wlan0', True)
fw.forward_rule('eth0', '10.10.0.0/16','tcp',443, None)
fw.port_forwarding_rule('tcp',10022,'10.10.0.2',22)
