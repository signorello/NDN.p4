#<This file is part of NDN.p4,i.e., an NDN implementation written in P4.>
#Copyright (C) 2016, the University of Luxembourg
#Salvatore Signorello <salvatore.signorello@uni.lu>
#
#NDN.p4 is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#NDN.p4 is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with NDN.p4.  If not, see <http://www.gnu.org/licenses/>.

import time

from ndn.experiments.experiment import Experiment

class P4NdnExperiment(Experiment):

    def __init__(self, args):
        Experiment.__init__(self,args)


    def start(self):
        self.setup()
	# let give nfd the time to register the face
	time.sleep(1)
        self.run()

    def setup(self):
        for host in self.net.hosts:
	  if host.name == 'a':
	      # dirty method to get the face id parsing nfd-status output. I also think that awk can do it in one shot, but I have no time to check this out now 
	      tmpfile = "/tmp/%s/tmp.txt" % host.name
	      res2 = ''
	      while not res2:
		res1 = host.cmd("nfd-status > %s" % tmpfile)
		res2 = host.cmd("grep eth0 %s" % tmpfile)
		time.sleep(1)

	      res3 = host.cmd("awk '/eth0/ { split($1,a,\"=\");print a[2]}' %s " % tmpfile)
	      # somewhere someone adds trailing \r\n to the output, throwing them away
	      if '\r' in res3:
		faceid = res3.split('\\')[0]
	      else:
		faceid = res3
	      print("Printing eth0 faceID: %s" % faceid)
	      host.cmd("nfdc register ndn:/snt/sedan/state %s" % faceid)
	      time.sleep(0.5)
	      host.cmd("nfdc register ndn:/snt/sedan %s" % faceid)
	      time.sleep(0.5)
	      host.cmd("nfdc register ndn:/snt %s" % faceid)

    def run(self):
        for host in self.net.hosts:
	  if host.name == 'a':
	      host.cmd("ndnpeek -p ndn:/p4softwareswitch/signorello.pdf > packetPayload.txt")
	  elif host.name == 'b':
	      host.cmd("echo 'Hello world' | ndnpoke -w 30000 ndn:/p4softwareswitch/signorello.pdf &")

Experiment.register("P4_NDN_experiment", P4NdnExperiment)
