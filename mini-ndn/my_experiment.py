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
import pdb

from ndn.experiments.experiment import Experiment

class P4NdnExperiment(Experiment):

    def __init__(self, args):
        Experiment.__init__(self,args)


    def start(self):
        self.setup()
	# let give nfd the time to register the face
	time.sleep(5)
        self.run()

    def setup(self):
        for host in self.net.hosts:
	  tmpfile = "/tmp/%s/tmp.txt" % host.name

	  # dirty method to get the face id parsing nfd-status output. I also think that awk can do it in one shot, but I have no time to check this out now 
	  res2 = ''
	  attempts = 0;
	  while not res2 and attempts < 10:
		res1 = host.cmd("nfd-status > %s" % tmpfile)
		res2 = host.cmd("grep eth0 %s" % tmpfile)
		# watch out with the following waiting time, halving it caused the experiment to fail on our host machine
		time.sleep(1)
		attempts+=1

	  if attempts == 10:
		print("Failed to get nfd-status after %d attempts on host %s" % (attempts,host.name))
		raise AssertionError(res1)

	  if host.name == 'a':
	      res3 = host.cmd("awk '/eth0/ { split($1,a,\"=\");print a[2]}' %s " % tmpfile)
	      # somewhere someone adds trailing \r\n to the output, throwing them away
	      if '\r' in res3:
		faceid = res3.split('\\')[0]
	      else:
		faceid = res3
	      print("Printing eth0 faceID: %s" % faceid)
	      host.cmd("nfdc register ndn:/snt/sedan/state %s &>> %s" % (faceid,tmpfile) )
	      time.sleep(0.5)
	      host.cmd("nfdc register ndn:/snt/sedan %s &>> %s " % (faceid,tmpfile) )
	      time.sleep(0.5)
	      host.cmd("nfdc register ndn:/snt %s &>> %s" % (faceid,tmpfile) )
	      time.sleep(0.5)
	      host.cmd("nfd-status &>> %s" % tmpfile)

    def run(self):
        for host in self.net.hosts:
	  if host.name == 'a':
	      host.cmd("ndnpeek -p ndn:/snt/sedan/state/signorello.pdf > packetPayload.txt")
	  elif host.name == 'b':
	      host.cmd("echo 'Hello world' | ndnpoke -w 30000 ndn:/snt/sedan/state/signorello.pdf &")

Experiment.register("P4_NDN_experiment", P4NdnExperiment)
