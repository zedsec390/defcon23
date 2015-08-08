# TN3270 Library based heavily on x3270 and python telnet lib
# Created by Phil "Soldier of Fortran" Young
#
# To use this library create a tn3270 object
# >>> import tn3270lib
# >>> tn3270 = tn3270lib.TN3270()
# To connect to a host use the initiate function. 
# This library will attempt SSL first
# then connect without ssl if that fails.
# >>> host = "10.10.0.10"
# >>> port = 23 
# >>> tn3270.initiate(host, port)
# True
# >>> data = tn3270.get_screen()
# >>> print data
# z/OS V1R13 PUT Level 1209                          IP Address = 10.10.0.13
#                                                    VTAM Terminal =
#
#                        Application Developer System
#
#                                 //  OOOOOOO   SSSSS
#                                //  OO    OO SS
#                        zzzzzz //  OO    OO SS
#                          zz  //  OO    OO SSSS
#                        zz   //  OO    OO      SS
#                      zz    //  OO    OO      SS
#                    zzzzzz //   OOOOOOO  SSSS
#
#
#                    System Customization - ADCD.Z113H.*
#
#
#
#
#  ===> Enter "LOGON" followed by the TSO userid. Example "LOGON IBMUSER" or
#  ===> Enter L followed by the APPLID
#  ===> Examples: "L TSO", "L CICSTS41", "L CICSTS42", "L IMS11", "L IMS12"
# >>> tn3270.disconnect()
#
# A check function has also been created to check if the server accepts tn3270 connections. 
# Returns True if the socket supports tn3270, False if not. 
#
# >>> tn3270.check_tn3270(host, port)
# True
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

import errno
import sys
import socket
import ssl
import select
import struct
import binascii
import math


# Tunable parameters
DEBUGLEVEL = 0

# Telnet protocol commands
SE   = chr(240) #End of subnegotiation parameters
SB   = chr(250) #Sub-option to follow
WILL = chr(251) #Will; request or confirm option begin
WONT = chr(252) #Wont; deny option request
DO   = chr(253) #Do = Request or confirm remote option
DONT = chr(254) #Don't = Demand or confirm option halt
IAC  = chr(255) #Interpret as Command
SEND = chr(001) #Sub-process negotiation SEND command
IS   = chr(000) #Sub-process negotiation IS command


#TN3270 Telnet Commands
TN_ASSOCIATE  = chr(0)
TN_CONNECT    = chr(1)
TN_DEVICETYPE = chr(2)
TN_FUNCTIONS  = chr(3)
TN_IS         = chr(4)
TN_REASON     = chr(5)
TN_REJECT     = chr(6)
TN_REQUEST    = chr(7)
TN_RESPONSES  = chr(2)
TN_SEND       = chr(8)
TN_EOR        = chr(239) #End of Record

#Supported Telnet Options
options = {
	'BINARY'  : chr(0),
	'EOR'     : chr(25),
	'TTYPE'   : chr(24),
	'TN3270'  : chr(40)
  }

#TN3270 Stream Commands: TCPIP
EAU   = chr(15)
EW    = chr(5)
EWA   = chr(13)
RB    = chr(2)
RM    = chr(6)
RMA   = ''
W     = chr(1)
WSF   = chr(17)
NOP   = chr(3)
SNS   = chr(4)
SNSID = chr(228)
#TN3270 Stream Commands: SNA
SNA_RMA   = chr(110)
SNA_EAU   = chr(111)
SNA_EWA   = chr(126)
SNA_W     = chr(241)
SNA_RB    = chr(242)
SNA_WSF   = chr(243) 
SNA_EW    = chr(245)
SNA_NOP   = chr(003)
SNA_RM    = chr(246) 


#TN3270 Stream Orders
SF  = chr(29)
SFE = chr(41)
SBA = chr(17)
SA  = chr(40)
MF  = chr(44)
IC  = chr(19)
PT  = chr(5)
RA  = chr(60)
EUA = chr(18)
GE  = chr(8)


#TN3270 Format Control Orders
NUL = chr(0)
SUB = chr(63)
DUP = chr(28)
FM  = chr(30)
FF  = chr(12)
CR  = chr(13)
NL  = chr(21)
EM  = chr(25)
EO  = chr(255)

#TN3270 Attention Identification (AIDS)
#####
# SoF ## Left this as hex because i coulnd't
#        be bothered to convert to decimal
#####
NO      = chr(0x60) #no aid
QREPLY  = chr(0x61) #reply
ENTER   = chr(0x7d) #enter
PF1     = chr(0xf1)
PF2     = chr(0xf2)
PF3     = chr(0xf3)
PF4     = chr(0xf4)
PF5     = chr(0xf5)
PF6     = chr(0xf6)
PF7     = chr(0xf7)
PF8     = chr(0xf8)
PF9     = chr(0xf9)
PF10    = chr(0x7a)
PF11    = chr(0x7b)
PF12    = chr(0x7c)
PF13    = chr(0xc1)
PF14    = chr(0xc2)
PF15    = chr(0xc3)
PF16    = chr(0xc4)
PF17    = chr(0xc5)
PF18    = chr(0xc6)
PF19    = chr(0xc7)
PF20    = chr(0xc8)
PF21    = chr(0xc9)
PF22    = chr(0x4a)
PF23    = chr(0x4b)
PF24    = chr(0x4c)
OICR    = chr(0xe6)
MSR_MHS = chr(0xe7)
SELECT  = chr(0x7e)
PA1     = chr(0x6c)
PA2     = chr(0x6e)
PA3     = chr(0x6b)
CLEAR   = chr(0x6d)
SYSREQ  = chr(0xf0)
 
 #TN3270 Code table to transalte buffer addresses
 
code_table=[0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
			0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
			0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
			0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
			0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
			0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
			0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
			0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]

#TN3270 Datatream Processing flags
NO_OUTPUT      = 0
OUTPUT         = 1
BAD_COMMAND    = 2
BAD_ADDRESS    = 3
NO_AID         = 0x60

#Header response flags.
NO_RESPONSE       = 0x00
ERROR_RESPONSE    = 0x01
ALWAYS_RESPONSE   = 0x02
POSITIVE_RESPONSE = 0x00
NEGATIVE_RESPONSE = 0x01

#Header data type names.
DT_3270_DATA    = 0x00
DT_SCS_DATA     = 0x01
DT_RESPONSE     = 0x02
DT_BIND_IMAGE   = 0x03
DT_UNBIND       = 0x04
DT_NVT_DATA     = 0x05
DT_REQUEST      = 0x06
DT_SSCP_LU_DATA = 0x07
DT_PRINT_EOJ    = 0x08

#Header response data.
POS_DEVICE_END             = 0x00
NEG_COMMAND_REJECT         = 0x00
NEG_INTERVENTION_REQUIRED  = 0x01
NEG_OPERATION_CHECK        = 0x02
NEG_COMPONENT_DISCONNECTED = 0x03

#TN3270E Header variables
tn3270_header = {
	'data_type'     : '',
	'request_flag'  : '',
	'response_flag' : '',
	'seq_number'    : ''
}


#Global Vars
NEGOTIATING    = 1
CONNECTED      = 2
TN3270_DATA    = 3
TN3270E_DATA   = 4
#We only support 3270 model 2 wich was 24x80.
DEVICE_TYPE    = "IBM-3278-2"
COLS           = 80 # hardcoded width. 
ROWS           = 24 # hardcoded rows. 
WORD_STATE     = ["Negotiating", "Connected", "TN3270 mode", "TN3270E mode"]
TELNET_PORT    = 23


class TN3270:
	def __init__(self, host=None, port=0,
				 timeout=10):

		self.debuglevel = DEBUGLEVEL
		self.host       = host
		self.port       = port
		self.timeout    = timeout
		self.eof        = 0
		self.sock       = None
		self._has_poll  = hasattr(select, 'poll')

		self.telnet_state   = 0 # same as TNS_DATA to begin with
		self.server_options = {}
		self.client_options = {}
		self.sb_options     = ''
		self.connected_lu   = ''
		self.connected_dtype= ''
		self.negotiated     = False
		self.first_screen   = False
		self.aid            = NO_AID  #initial Attention Identifier is No AID
		self.telnet_data    = ''
		self.tn_buffer      = ''
		self.raw_tn         = [] #Stores raw TN3270 'frames' for use
		self.state          = 0
		self.buffer_address = 0
		self.formatted      = False,

		#TN3270 Buffer Address Location
		self.buffer_addr = 0
		#TN3270 Cursor Tracking Location
		self.cursor_addr = 0
		self.screen          = []
		self.printableScreen = []
		self.header          = []

		#TN3270 Buffers
		self.buffer         = []
		self.fa_buffer      = []
		self.output_buffer  = []
		self.overwrite_buf  = []
		self.header_sequence = 0


		if host is not None:
			self.initiate(host, port, timeout)

	def connect(self, host, port=0, timeout=30):
		"""Connects to a TN3270 Server. aka a Mainframe!"""
		self.ssl = False
		if not port:
			port = TELNET_PORT
		self.host = host
		self.port = port
		self.timeout = timeout
		try:
			non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
			ssl_sock.settimeout(self.timeout)
			ssl_sock.connect((host,port))
			self.sock = ssl_sock
			self.ssl = True
		except ssl.SSLError, e:
			non_ssl.close()
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(timeout)
				sock.connect((host,port))
				self.sock = sock
			except Exception, e:
				self.msg('Non-SSL Error: %r', e)
				return False
		except Exception, e:
			self.msg('SSL Error: %r', e)
			return False
		return True

	def __del__(self):
		"""Destructor ## close the connection."""
		self.disconnect()

	def msg(self, msg, *args):
		"""Print a debug message, when the debug level is > 0.

		If extra arguments are present, they are substituted in the
		message using the standard string formatting operator.

		"""
		if self.debuglevel > 0:
			print 'TN3270(%s,%s):' % (self.host, self.port),
			if args:
				print msg % args
			else:
				print msg

	def set_debuglevel(self, debuglevel):
		"""Set the debug level.

		The higher it is, the more debug output you get (on sys.stdout).

		"""
		self.debuglevel = debuglevel

	def disconnect(self):
		"""Close the connection."""
		sock = self.sock
		self.sock = 0
		if sock:
			sock.close()

	def get_socket(self):
		"""Return the socket object used internally."""
		return self.sock

	def send_data(self, data):
		"""Sends raw data to the TN3270 server """
		self.msg("send %r", data)
		self.sock.sendall(data)

	def recv_data(self):
		""" Receives 256 bytes of data; blocking"""
		self.msg("Getting Data")
		buf = self.sock.recv(256)
		self.msg("Got Data: %r", buf)
		return buf

	def DECODE_BADDR(self, byte1, byte2):
		""" Decodes Buffer Addresses.
			Buffer addresses can come in 14 or 12 (this terminal doesn't support 16 bit)
			this function takes two bytes (buffer addresses are two bytes long) and returns
			the decoded buffer address."""
		if (byte1 & 0xC0) == 0:
			return (((byte1 & 0x3F) << 8) | byte2) + 1 
		else:
			return ((byte1 & 0x3F) << 6) | (byte2 & 0x3F)

	def ENCODE_BADDR(self, address):
		""" Encodes Buffer Addresses. 
		    We need the +1 because LUA tables start at 1"""
		b1 = struct.pack(">B",code_table[((address >> 6) & 0x3F)+1])
		b2 = struct.pack(">B",code_table[(address & 0x3F)+1])
		return b1 + b2

	def BA_TO_ROW( self, addr ):
		""" Returns the current row of a buffer address """
		return math.ceil((addr / COLS) + 0.5)

	def BA_TO_COL( self, addr ):
		""" Returns the current column of a buffer address """
		return addr % COLS

	def INC_BUF_ADDR( self, addr ):
		""" Increments the buffer address by one """
		return ((addr + 1) % (COLS * ROWS))

	def DEC_BUF_ADDR( self, addr ):
		""" Decreases the buffer address by one """
		return ((addr + 1) % (COLS * ROWS))

	def check_tn3270( self, host, port=0, timeout=3 ):
		""" Checks if a host & port supports TN3270 """
		if not port:
			port = TELNET_PORT
		try:
			non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
			ssl_sock.settimeout(timeout)
			ssl_sock.connect((host,port))
			sock = ssl_sock
		except ssl.SSLError, e:
			non_ssl.close()
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(timeout)
				sock.connect((host,port))
			except Exception, e:
				self.msg('Error: %r', e)
				return False
		except Exception, e:
			self.msg('Error: %r', e)
			return False


		data = sock.recv(256)
		if data == IAC + DO + options['TN3270']:
			sock.close()
			return True
		elif data == IAC + DO + options['TTYPE']:
			sock.sendall(IAC + WILL + options['TTYPE'])
			data = sock.recv(256)
			if data != IAC + SB + options['TTYPE'] + SEND + IAC + SE or data == '':
				return False
			sock.sendall(IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE)
			data = sock.recv(256)
			if data[0:2] == IAC + DO:
				sock.close()
				return True
		return False

	def initiate( self, host, port=0, timeout=5 ):
		""" Initiates a TN3270 connection until it gets the first 'screen' """
		#if not self.check_tn3270(host, port): 
		#	return False
		if not self.connect(host,port, timeout):
			return False

		self.client_options = {}
		self.server_options = {}
		self.state = NEGOTIATING
		self.first_screen = False

		while not self.first_screen:
			self.telnet_data = self.recv_data()
			self.msg("Got telnet_data: %r", self.telnet_data)
			self.process_packets()
		return True

	def get_data( self ):
		""" Gets the tn3270 buffer currently on the stack """
		status = True
		self.first_screen = False
		while not self.first_screen and status:
			self.telnet_data = self.recv_data()
			self.process_packets()
		#end

	def get_all_data( self ):
		""" Mainframes will often send a 'confirmed' screen before it sends 
		    the screen we care about, this function clumsily gets all screens
		    sent so far """
		self.first_screen = False
		self.sock.settimeout(2)
		while True:
			try:
				self.telnet_data = self.recv_data()
				self.process_packets()
			except socket.timeout, e:
				err = e.args[0]
				if err == 'timed out':
					#sleep(1)
					self.msg("recv timed out! We're done here")
					break
			except socket.error, e:
		        # Something else happened, handle error, exit, etc.
				self.msg("Error Received: %r", e)
		self.sock.settimeout(None)

	def process_packets( self ):
		""" Processes Telnet data """
		for i in self.telnet_data:
			#self.msg("Processing: %r", i)
			self.ts_processor(i)
			self.telnet_data = '' #once all the data has been processed we clear out the buffer

	def ts_processor( self, data ):
		""" Consumes/Interprets Telnet/TN3270 data """
		TNS_DATA   = 0
		TNS_IAC    = 1
		TNS_WILL   = 2 
		TNS_WONT   = 3
		TNS_DO     = 4
		TNS_DONT   = 5
		TNS_SB     = 6
		TNS_SB_IAC = 7
		DO_reply   = IAC + DO
		DONT_reply = IAC + DONT
		WILL_reply = IAC + WILL
		WONT_reply = IAC + WONT

		#self.msg('State is: %r', self.telnet_state)
		if self.telnet_state == TNS_DATA:
		  if data == IAC:
			## got an IAC
			self.telnet_state = TNS_IAC
			return True
		  self.store3270(data)
		elif self.telnet_state == TNS_IAC:
		  if data == IAC:
			## insert this 0xFF in to the buffer
			self.store3270(data)
			self.telnet_state = TNS_DATA
		  elif data == TN_EOR:
			## we're at the end of the TN3270 data
			## let's process it and see what we've got
			## but only if we're in 3270 mode
			if self.state == TN3270_DATA or self.state == TN3270E_DATA: 
			  self.process_data() 
			self.telnet_state = TNS_DATA
		  elif data == WILL: self.telnet_state = TNS_WILL
		  elif data == WONT: self.telnet_state = TNS_WONT
		  elif data == DO  : self.telnet_state = TNS_DO
		  elif data == DONT: self.telnet_state = TNS_DONT
		  elif data == SB  : self.telnet_state = TNS_SB
		elif self.telnet_state == TNS_WILL:
		  if (data == options['BINARY'] or 
		  	  data == options['EOR']    or
			  data == options['TTYPE']  ): #  or data == options['TN3270'] then
			if not self.server_options.get(data, False): ## if we haven't already replied to this, let's reply
			  self.server_options[data] = True
			  self.send_data(DO_reply + data)
			  self.msg("Sent Will Reply %r", data)
			  self.in3270()
		  else:
			self.send_data(DONT_reply+data)
			self.msg("Sent DONT Reply %r", data)
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_WONT:
		  if self.server_options.get(data, False):
			self.server_options[data] = False
			self.send_data(DONT_reply + data)
			self.msg("Sent WONT Reply %r", data)
			self.in3270()
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_DO:
		  if ( data == options['BINARY'] or 
		  	   data == options['EOR']    or
			   data == options['TTYPE']  ): # or data == options['TN3270']:
			 ## data == options['STARTTLS ## ssl encryption to be added later
			 if not self.client_options.get(data, False):
			  self.client_options[data] = True
			  self.send_data(WILL_reply + data)
			  self.msg("Sent DO Reply %r", data)
			  self.in3270()
		  else:
			self.send_data(WONT_reply+data)
			self.msg("Got unsupported Do. Sent Won't Reply: %r ", data)
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_DONT:
		  if self.client_options.get(data, False):
			self.client_options[data] = False
			self.send_data(WONT_reply + data)
			self.msg("Sent DONT Reply %r", data)
			self.in3270()
		  self.telnet_state = TNS_DATA
		elif self.telnet_state == TNS_SB:
		  if data == IAC:
			self.telnet_state = TNS_SB_IAC
		  else:
			self.sb_options = self.sb_options + data
		elif self.telnet_state == TNS_SB_IAC:
		  self.msg("Got SB, processing")
		  self.sb_options = self.sb_options + data
		  if data == SE:
			self.telnet_state = TNS_DATA
			if (self.sb_options[0] == options['TTYPE'] and
			    self.sb_options[1] == SEND ):
			  self.send_data(IAC + SB + options['TTYPE'] + IS + DEVICE_TYPE + IAC + SE)
			elif self.client_optionsget(options['TN3270'], False) and self.sb_options[0] == options['TN3270']:
			  if not self.negotiate_tn3270(): 
				return false
		
			  self.msg("Done Negotiating Options")
			else:
			  self.telnet_state = TNS_DATA
			self.sb_options = ''
		return True

	## Stores a character on a buffer to be processed
	def store3270(self, char ):
		""" Stores a character on the tn3270 buffer """
		self.tn_buffer += char

	## Also known as process_eor in x3270
	def process_data( self ):
		""" Processes TN3270 data """
		reply = 0
		self.msg("Processing TN3270 Data")
	## We currently don't support TN3270E but this is here for future expansion
	#	if self.state == self.TN3270E_DATA:
	#		self.tn3270_header.data_type     = self.tn_buffer:sub(1,1)
	#		self.tn3270_header.request_flag  = self.tn_buffer:sub(2,2)
	#		self.tn3270_header.response_flag = self.tn_buffer:sub(3,3)
	#		self.tn3270_header.seq_number    = self.tn_buffer:sub(4,5)
	#		if self.tn3270_header.data_type == "\000":
	#			reply = self:process_3270(self.tn_buffer:sub(6))
    # if reply < 0 and self.tn3270_header.request_flag ~= self.TN3270E_RSF_NO_RESPONSE:
    #    self:tn3270e_nak(reply)
    #  elseif reply == self.NO_OUTPUT and 
    #         self.tn3270_header.request_flag == self.ALWAYS_RESPONSE then
    #    self:tn3270e_ack()
    #  end
    #else
		self.process_3270(self.tn_buffer)
		self.raw_tn.append(self.tn_buffer)
    #end
    #nsedebug.print_hex(self.tn_buffer)

		self.tn_buffer = ''
		return  True

	def in3270(self):
		if self.client_options.get(options['TN3270'], False):
			if self.negotiated:
				self.state = self.TN3270E_DATA
		elif (  self.server_options.get(options['EOR'], False)    and 
				self.server_options.get(options['BINARY'], False) and
				self.client_options.get(options['BINARY'], False) and
				self.client_options.get(options['TTYPE'], False)  ):
			self.state = TN3270_DATA
		if self.state == TN3270_DATA or self.state == TN3270E_DATA:
			## since we're in TN3270 mode, let's create an empty buffer
			self.msg("Creating Empty IBM-3278-2 Buffer")
			self.buffer = list("\0" * 1920)
			self.fa_buffer = list("\0" * 1920)
			self.overwrite_buf = list("\0" * 1920)
			self.msg("Created buffers of length: %r", 1920)
		self.msg("Current State: %r", WORD_STATE[self.state])

	def clear_screen( self ):
		self.buffer_address = 1
		self.buffer = list("\0" * 1920)
		self.fa_buffer = list("\0" * 1920)
		self.overwrite_buf = list("\0" * 1920)

	def clear_unprotected( self ):
		## We'll ignore this for now since we ignore the protected field anyway
		return

	def process_3270( self, data ):
		""" Processes TN3270 Data """
	    ## the first byte will be the command we have to follow
		com = data[0]
		self.msg("Value Received: %r", com)
		if com == EAU:
			self.msg("TN3270 Command: Erase All Unprotected")
			self.clear_unprotected()
			return NO_OUTPUT
		elif ( com == EWA or com == SNA_EWA or
			   com == EW  or com == SNA_EW  ):
			self.msg("TN3270 Command: Erase Write (Alternate)")
			self.clear_screen()
			self.process_write(data) ##so far should only return No Output
			return NO_OUTPUT
		elif com == W or com == SNA_W:
			self.msg("TN3270 Command: Write")
			self.process_write(data)
		elif com == RB  or com == SNA_RB:
			self.msg("TN3270 Command: Read Buffer")
			self.process_read()
			return OUTPUT
		elif ( com == RM  or com == SNA_RM  or
			   com == RMA or com == SNA_RMA ):
			self.msg("TN3270 Command: Read Modified (All)")
			self.read_modified(self.aid)
			return OUTPUT
		elif com == WSF or com == SNA_WSF:
			self.msg("TN3270 Command: Write Structured Field")
			return self.w_structured_field(data)
		elif com == NOP or com == SNA_NOP:
			self.msg("TN3270 Command: No OP (NOP)")
			return NO_OUTPUT
		else:
			self.msg("Unknown 3270 Data Stream command: %r", com)
			return BAD_COMMAND

	### WCC / tn3270 data stream processor
	def process_write(self, data ):
		""" Processes TN3270 Write commands and 
		    writes them to the screen buffer """
		self.msg("Processing TN3270 Write Command")
		prev = ''
		cp = ''
		num_attr = 0
		last_cmd = False
		i = 2 # skip the first two chars
		while i <= len(data) - 1:
			self.msg("Current Position: " + str(i) + " of " + str(len(data)))
			cp = data[i]
			self.msg("Current Item: %r",cp)
			# awesome, no switch statements here either
			if cp == SF:
				self.msg("Start Field")
				prev = 'ORDER'
				last_cmd = True
				i = i + 1 # skip SF
				self.msg("Writting Zero to buffer at address: %r",self.buffer_address)
				self.msg("Attribute Type: %r", data[i])
				self.write_field_attribute(data[i])
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				#set the current position one ahead (after SF)
				i = i + 1
				self.write_char("\00")

			elif cp == SFE:
				self.msg("Start Field Extended")
				i = i + 1 # skip SFE
				num_attr = struct.unpack(">B",data[i])[0]
				self.msg("Number of Attributes: %r", num_attr)
				for j in range(num_attr):
					i = i + 1
					if struct.unpack(">B", data[i])[0] == 0xc0:
						self.msg("Writting Zero to buffer at address: %r", self.buffer_address)
						self.msg("Attribute Type: %r", data[i])
						self.write_char("\0")
						self.write_field_attribute(data[i])
					i = i + 1
				i = i + 1
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
			elif cp == SBA:
				self.msg("Set Buffer Address (SBA) 0x11")
				self.buffer_address = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
														struct.unpack(">B", data[i + 2])[0])
				self.msg("Buffer Address: %r" , self.buffer_address)
				self.msg("Row: %r" , self.BA_TO_ROW(self.buffer_address))
				self.msg("Col: %r" , self.BA_TO_COL(self.buffer_address))
				last_cmd = True
				prev = 'SBA'
				# the current position is SBA, the next two bytes are the lengths
				i = i + 3
				self.msg("Next Command: %r",data[i])
			elif cp == IC: # Insert Cursor
				self.msg("Insert Cursor (IC) 0x13")
				self.msg("Current Cursor Address: %r" , self.cursor_addr)
				self.msg("Buffer Address: %r", self.buffer_address)
				self.msg("Row: %r" , self.BA_TO_ROW(self.buffer_address))
				self.msg("Col: %r" , self.BA_TO_COL(self.buffer_address))
				prev = 'ORDER'
				self.cursor_addr = self.buffer_address
				last_cmd = True
				i = i + 1
			elif cp == RA: 
			# Repeat address repeats whatever the next char is after the two byte buffer address
			# There's all kinds of weird GE stuff we could do, but not now. Maybe in future vers
				self.msg("Repeat to Address (RA) 0x3C")
				ra_baddr = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
		                                     struct.unpack(">B", data[i + 2])[0])
				self.msg("Repeat Character: %r" , data[i + 1])
				self.msg("Repeat to this Address: %r" , ra_baddr)
				self.msg("Currrent Address: %r", self.buffer_address)
				prev = 'ORDER'
				#char_code = data:sub(i+3,i+3)
				i = i + 3
				char_to_repeat = data[i]
				self.msg("Repeat Character: %r" ,char_to_repeat)
				while (self.buffer_address != ra_baddr):
					self.write_char(char_to_repeat)
					self.buffer_address = self.INC_BUF_ADDR(self.buffer_address) 
			elif cp == EUA:
				self.msg("Erase Unprotected All (EAU) 0x12")
				eua_baddr = self.DECODE_BADDR(struct.unpack(">B", data[i + 1])[0],
		                                      struct.unpack(">B", data[i + 2])[0])
				i = i + 3
				self.msg("EAU to this Address: %r" , eua_baddr)
				self.msg("Currrent Address: %r",  self.buffer_address)
				while (self.buffer_address != eua_baddr):
					# do nothing for now. this feature isn't supported/required at the moment
					# we're technically supposed to delete the buffer
					# but we might want to see whats on there!
					self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
					#stdnse.debug(3,"Currrent Address: " .. self.buffer_address)
					#stdnse.debug(3,"EAU to this Address: " .. eua_baddr)
			elif cp == GE:
				self.msg("Graphical Escape (GE) 0x08")
				prev = 'ORDER'
				i = i + 1 # move to next byte
				ge_char = data[i]
				self.write_char(ge_char)
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
			elif cp == MF:
				# we don't actually have 'fields' at this point
				# so there's nothing to be modified
				self.msg("Modify Field (MF) 0x2C")
				prev = 'ORDER'
				i = i + 1
				num_attr = int(data[i])
				for j in range(num_attr):
		        	#placeholder in case we need to do something here
					i = i + 1
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
			elif cp == SA:
				self.msg("Set Attribute (SA) 0x28")
			# SHHH don't tell anyone that we just skip these
			# But here is where Set Attribue is done. Things like Hidden and Protected
				i = i + 1

			elif ( cp == NUL or
	               cp == SUB or
                   cp == DUP or
                   cp == FM  or
                   cp == FF  or
                   cp == CR  or
                   cp == NL  or
                   cp == EM  or
                   cp == EO  ):
				self.msg("Format Control Order received")
				prev = 'ORDER'
				self.write_char(chr(064))
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				i = i + 1
			else: # whoa we made it.
				ascii_char = cp.decode('EBCDIC-CP-BE').encode('utf-8') 
				self.msg("Inserting "+ ascii_char + " (%r) at the following location:", data[i])
				self.msg("Row: %r" , self.BA_TO_ROW(self.buffer_address))
				self.msg("Col: %r" , self.BA_TO_COL(self.buffer_address))
				self.msg("Buffer Address: %r" , self.buffer_address)
				self.write_char(data[i])
				self.buffer_address = self.INC_BUF_ADDR(self.buffer_address)
				self.first_screen = True
				i = i + 1
			# end of massive if/else
	    # end of while loop
    		self.formatted = True


	def write_char( self, char ):
		""" Writes a character to the screen buffer.
		    If a character already exists at that location, 
		    write the char in the screen buffer to a backup buffer """
		if self.buffer[self.buffer_address-1] == "\0":
			self.buffer[self.buffer_address-1] = char
		else:
			self.overwrite_buf[self.buffer_address-1] = self.buffer[self.buffer_address]
			self.buffer[self.buffer_address-1] = char

	def write_field_attribute( self, attr ):
		""" Writes Field attributes to the field attribute buffer """
		self.fa_buffer[self.buffer_address-1] = attr

	def print_screen( self ):
		""" Prints the current TN3270 screen buffer """
		self.msg("Printing the current TN3270 buffer:")
		buff = ''
		i = 1
		for line in self.buffer:
			if line == "\00":
				buff += " "
			else:
				buff += line.decode('EBCDIC-CP-BE').encode('utf-8')
			if (i + 1) % 80 == 0:
				print buff
				buff = ''
			i = i + 1

	def get_screen ( self ):
		""" Returns the current TN3270 screen buffer formatted for printing """
		self.msg("Generating the current TN3270 buffer in ASCII")
		buff = ''
		i = 1
		for line in self.buffer:
			if line == "\00":
				buff += " "
			else:
				buff += line.decode('EBCDIC-CP-BE').encode('utf-8')
			if (i + 1) % 80 == 0:
				buff += '\n'

			i = i + 1
		return buff

	def process_read( self ):
		""" Processes READ commands from server """
		output_addr = 0
		self.output_buffer = [] 
		self.msg("Generating Read Buffer")
		self.output_buffer.insert(output_addr, struct.pack(">B",self.aid))
		output_addr = output_addr + 1
		self.msg("Output Address: %r", output_addr)
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		self.send_tn3270(self.output_buffer)
    	#need to add while loop for MF, <3 <3 someday

	def send_tn3270( self, data ):
		"""Sends tn3270 data to the server. Adding 3270E options and doubling IACs"""
		packet = ''
		if self.state == TN3270E_DATA:
			packet = "\x00\x00\x00\x00\x00"
			# we need to create the tn3270E (the E is important) header
			# which, in basic 3270E is 5 bytes of 0x00
			# Since we don't support 3270E at the moment this is just a skeleton
			#packet = struct.pack(">B",self.DT_3270_DATA)       + #type
			#struct.pack(">B",0)                       + # request
			#struct.pack(">B",0)                       + # response
			#struct.pack(">S",0)
			#self.tn3270_header.seq_number
		# create send buffer and double up IACs
		for char in data:
			self.msg("Adding %r to the read buffer", char)
			packet += char
		if IAC in packet:
			packet = packet.replace(IAC, IAC+IAC)
		packet += IAC + TN_EOR
		self.send_data(packet) # send the output buffer

	def w_structured_field ( self, wsf_data ):
		# this is the ugliest hack ever
		# but it works and it doesn't matter what we support anyway
		self.msg("Processing TN3270 Write Structured Field Command")

		query_options = binascii.unhexlify(
    	            "8800168186000800f4f100f200f300f400f500f600f700000d8187040" + 
    				"0f0f1f1f2f2f4f4002281858200071000000000070000000065002500" + 
    				"000002b900250100f103c30136002e818103000050001800000100480" + 
    				"001004807100000000000001302000100500018000001004800010048" + 
    				"0710001c81a600000b010000500018005000180b02000007001000070" + 
    				"010000781880001020016818080818485868788a1a6a89699b0b1b2b3" + 
    				"b4b600088184000a0004000681990000ffef")
		self.msg("Current WSF : %r", wsf_data )
		#if wsf_data[4] == "\01":
		self.send_data(query_options)


	def send_cursor( self, data ):
		output_addr = 0
		self.output_buffer = []
		self.msg("Generating Output Buffer for send_cursor")
		self.output_buffer.insert(output_addr, ENTER)
		output_addr += 1
		self.msg("Output Address: %r", output_addr)
		self.msg("Cursor Location ("+ str(self.cursor_addr) +"): Row: %r, Column: %r ", 
					self.BA_TO_ROW(self.cursor_addr), 
					self.BA_TO_COL(self.cursor_addr) )
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		output_addr += 1
		self.output_buffer.insert(output_addr, SBA)
		output_addr += 1
		self.output_buffer.insert(output_addr, self.ENCODE_BADDR(self.cursor_addr))
		output_addr += 1
		for lines in data:
			self.msg('Adding %r to the output buffer', lines.decode('utf-8').encode('EBCDIC-CP-BE'))
			self.output_buffer.insert(output_addr, lines.decode('utf-8').encode('EBCDIC-CP-BE'))
			output_addr += 1
		#--self.output_buffer[output_addr]  = self:ENCODE_BADDR(self.cursor_addr + i)
		#-- for i = 1,#self.fa_buffer do
		#--   if self.fa_buffer[i] ~= "\0" then
		#--     break
		#--   end
		#--   output_addr = self:INC_BUF_ADDR(output_addr)
		#-- end
		#-- stdnse.debug(3,"At Field Attribute: Row: %s, Column %s", 
		#--                 self:BA_TO_ROW(output_addr), 
		#--                 self:BA_TO_COL(output_addr) )
		#--stdnse.debug(1, "sending the following: %s", stdnse.tohex(self.output_buffer))
		return self.send_tn3270(self.output_buffer)


	def hexdump(self, src, length=8):
		""" Used to debug connection issues """
		result = []
		digits = 4 if isinstance(src, unicode) else 2
		for i in xrange(0, len(src), length):
			s = src[i:i+length]
			hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
			text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
			result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )
		return b'\n'.join(result)

	def raw_screen_buffer(self):
		""" returns a list containing all the tn3270 data recieved """
		return self.raw_tn

	def is_ssl(self):
		""" returns True if the connection is SSL. False if not. """
		return self.ssl







