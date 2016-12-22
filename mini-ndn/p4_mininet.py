# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ConfigParser
import time

from mininet.net import Mininet
from mininet.node import Switch
from mininet.log import setLogLevel, info

        
class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__( self, name, config_path = None,
		 # json_path = None,
                 # thrift_port = None,
                 # pcap_dump = False,
                 # verbose = False,
                  device_id = None,
                  **kwargs ):
        Switch.__init__( self, name, **kwargs )
	#self.parseConfig( config_path )
        logfile = '/tmp/p4s.%s.log' % self.name
        self.output = open(logfile, 'w')
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-%d-log.ipc" % self.device_id

    @classmethod
    def setup( cls ):
        pass

    def start( self, controllers ):
        "Start up a new P4 switch"
        print "Starting P4 switch", self.name
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend( ['-i', str(port) + "@" + intf.name] )
        if self.pcap_dump:
            args.append("--pcap")
        if self.thrift_port:
            args.extend( ['--thrift-port', str(self.thrift_port)] )
        if self.nanomsg:
            args.extend( ['--nanolog', self.nanomsg] )
        if self.verbose:
            args.append("--log-console")
        args.extend( ['--device-id', str(self.device_id)] )
        P4Switch.device_id += 1
        args.append(self.json_path)

        logfile = '/tmp/p4s.%s.log' % self.name

        print ' '.join(args)
	
	self.dropIPv6()
        self.cmd( ' '.join(args) + ' >' + logfile + ' 2>&1 &' )

        print "switch has been started"
	
	time.sleep(5)

	if self.commands is not None:
	  self.fillTables()

    def fillTables( self ):
	print ("Filling switch tables using %s" % self.commands )
	#res = self.cmd("python ~/p4/bmv2/targets/simple_switch/runtime_CLI --json ~/p4/p4factory/targets/ndn_router/p4src/ndn_router.json < %s" % self.commands)
	res = self.cmd("python %s --json %s < %s" % (self.cli_path, self.json_path, self.commands))
	print res

    def dropIPv6( self ):
	# disable IPv6
	print "Disable IPv6 forwarding on the P4Switch"
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    def stop( self ):
        "Terminate IVS switch."
        self.output.flush()
        self.cmd( 'kill %' + self.sw_path )
        self.cmd( 'wait' )
        self.deleteIntfs()

    def attach( self, intf ):
        "Connect a data port"
        assert(0)

    def detach( self, intf ):
        "Disconnect a data port"
        assert(0)

    def parseConfig( self, config_path ):
        print "Reading config file ", config_path
	config = ConfigParser.RawConfigParser()
	config.read(config_path)
        self.sw_path = config.get('basic', 'exe')
        self.json_path = config.get('basic', 'json')
        self.cli_path = config.get('basic', 'cli')
	assert(self.json_path), "The p4 switch cannot be started without a valid json file as argument"
        self.mode = config.get('basic', 'mode')
        self.thrift_port = config.get('basic', 'thrift-port')
        self.pcap_dump = config.getboolean('basic', 'pcap-dump')
        self.verbose = config.getboolean('basic', 'verbose')
        self.commands = config.get('basic', 'commands')
	print '%s %s %s %s %s %s %s %s' % (self.sw_path, self.cli_path, self.json_path, self.mode, self.thrift_port, self.pcap_dump, self.verbose, self.commands)
