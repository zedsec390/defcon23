#!/usr/bin/python

## Functions used to communicate with NJE
## Created by Soldier of Fortran 2015
# BETA Library Created for DEFCON 23
# Currently only supports NMR and supporting functions
# TODO:
#  - Better RCB/SRCB Detection
#  - JCL Submission
#  - Full NJE Library
#
# Based Heavily on IBM book HAS2A620:
#  "Network Job Entry: Formats and Protocols"
# Available Here: http://publibz.boulder.ibm.com/epubs/pdf/has2a620.pdf
#
# Notes:
#  - TCP is a Non-SNA Buffer Format
#  - The sections are described in alphabetical orders, not in the order of the packet
#  - Not everything is documented well
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

import socket
import sys
import ssl
import re
import struct
from select import select
import binascii
from binascii import hexlify, unhexlify
from bitstring import BitStream, BitArray

DEBUGLEVEL = 0
NJE_PORT = 175
SPACE = "\x40"

class NJE:
	def __init__(self, rhost, ohost, host='', port=0, password='', rip='10.13.37.10'):

		self.debuglevel = DEBUGLEVEL
		self.host       = host
		self.port       = port
		self.sock       = None
		self.RHOST      = self.padding(rhost)
		self.OHOST      = self.padding(ohost)
		self.TYPE       = self.padding("OPEN")
		self.RIP        = socket.inet_aton(rip)
		#self.OIP        = socket.inet_aton(host)
		self.R          = "\x00"
		self.node       = 0
		self.password   = password
		self.own_node   = chr(0x01) # Node is default 1. Can be changed to anything
		self.sequence   = 0x80
		if host:
			self.signon(self.host, self.port)


	def connect(self, host, port=0, timeout=30):
		"""Connects to an NJE Server. aka a Mainframe!"""
		self.ssl = False
		if not port:
			port = NJE_PORT
		self.host = host
		self.port = port
		self.timeout = timeout
		try:
			self.msg("Trying SSL")
			non_ssl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ssl_sock = ssl.wrap_socket(sock=non_ssl,cert_reqs=ssl.CERT_NONE)
			ssl_sock.settimeout(self.timeout)
			ssl_sock.connect((host,port))
			self.sock = ssl_sock
			self.ssl = True
		#except ssl.SSLError, e:
		except Exception, e:
			non_ssl.close()
			self.msg("SSL Failed Trying Non-SSL")
			try:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(timeout)
				sock.connect((host,port))
				self.sock = sock
			except Exception, e:
				self.msg('Non-SSL Connection Failed: %r', e)
				return False
		#except Exception, e:
		#	self.msg('SSL Connection Failed Error: %r', e)
		#	return False
		return True

	def disconnect(self):
		"""Close the connection."""
		sock = self.sock
		self.sock = 0
		if sock:
			sock.close()

	def signoff(self): 
		#Sends a B Record
		adios = ('\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00\x00\x09\x10\x02' +
			       chr(self.sequence) + 
			       '\x8F\xCF\xF0\xC2\x00\x00\x00\x00\x00\x00' )
		self.msg("Sending Signoff Record: %r", self.EbcdicToAscii(adios[18]))
		self.sendData(adios)
		self.disconnect()


	def msg(self, msg, *args):
		"""Print a debug message, when the debug level is > 0.

		If extra arguments are present, they are substituted in the
		message using the standard string formatting operator.

		"""
		if self.debuglevel > 0:
			print 'NJE(%s,%s):' % (self.host, self.port),
			if args:
				print msg % args
			else:
				print msg

	def set_debuglevel(self, debuglevel):
		"""Set the debug level.
		The higher it is, the more debug output you get (on sys.stdout).
		"""
		self.debuglevel = debuglevel
		print "[+] Debug Enabled"

	def INC_SEQUENCE(self):
		self.sequence = (self.sequence & 0x0F)+1|0x80 

	def changeNode(self, node):
		''' Node is the number of the node you'd like to be '''
		self.own_node = node

	def AsciiToEbcdic(self, s):
		''' Converts Ascii to EBCDIC '''
		return s.decode('utf-8').encode('EBCDIC-CP-BE')

	def EbcdicToAscii(self, s):
		''' Converts EBCDIC to UTF-8 '''
		return s.decode('EBCDIC-CP-BE').encode('utf-8')

	def signon(self, host, port=0, timeout=30, password=''):
		""" Implement NJE Signon Procedures by building the initial signon records:

			From has2a620.pdf
			0 1 2 3 4 5 6 7 8 9 A B C D E F
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|  TYPE       |     RHOST     |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|  RIP  |  OHOST      | OIP   |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| R |
			+-+-+
			TYPE : Type of request in EBCDIC characters, left justified and padded with blanks.
		           Acceptable values are OPEN, ACK, and NAK.
		    RHOST: Name of the host sending the control record and is the same value as the RSCS 
		           LOCAL associated with this link. This field is EBCDIC characters, left justified 
		           and padded with blanks.
		    RIP  : Hexadecimal value of the IP address sending the control record.
		    OHOST: The name of the host expected to receive the control record. Same format as RHOST.
		    OIP  : Hexadecimal value of the IP address expected to receive the control record.
		    R    : If TYPE=NAK, reason code in binary, used to return additional information.
			       Valid values are:
			       - X'01' No such link can be found
			       - X'02' Link found in active state and will be reset
			       - X'03' Link found attempting an active open.
		"""

		if not self.connect(host,port, timeout):
			return False
		print "[+] Initiating Singon to", host
		
		if password:
			self.password = password
		elif not password and not self.password:
			self.msg("No password provided, continuing without. "
				     "If you receive a 'B' record, this is likely the reason")

		ip         = socket.gethostbyname(host)
		self.OIP   = socket.inet_aton(ip)
		nje_packet = (self.TYPE  +
			          self.RHOST +
			          self.RIP   +
			          self.OHOST +
			          self.OIP   +
			          self.R     )

		self.msg("Sending  >> TYPE: " + self.EbcdicToAscii(self.TYPE) + 
			     " RHOST: " + self.EbcdicToAscii(self.RHOST) + 
			     " OHOST: " + self.EbcdicToAscii(self.OHOST))

		self.sendData(nje_packet)

		buff   = self.getData()
		bTYPE  = self.EbcdicToAscii(buff[0:8])
		bRHOST = self.EbcdicToAscii(buff[8:16])
		bRIP   = buff[16:20]
		bOHOST = self.EbcdicToAscii(buff[20:28])
		bOIP   = buff[28:32]
		bR     = struct.unpack("b", buff[32])[0]

		self.msg("Response << TYPE: " + bTYPE + " RHOST: " + bRHOST + " OHOST: " + bRHOST + " R: " + str(bR))

		if bTYPE == "NAK     ":
			print "[!] Error, recieved NAK with the following error:", bR
			self.disconnect()
			return False

		self.sendData(self.build_SOHENQ())
		buff = self.getData() # we get the reply data, but don't do anything with it?
		I_record = self.build_I()
		self.msg("Sending  >> Record Type: " + self.EbcdicToAscii(I_record[18]) + 
			     " to Node: " + self.EbcdicToAscii(I_record[20:20+8]))
		self.sendData(I_record)
		self.INC_SEQUENCE() # Increment the sequence number by 1 now

		buff = self.getData()
		self.msg("Response << Record Type: " + self.EbcdicToAscii(buff[18]) + 
			     " from Node: " + self.EbcdicToAscii(buff[20:20+8]) + 
			     " Sequence: " + self.phex(buff[14]) )

		if not self.check_signoff(buff): 
			return False

		self.target_node = buff[28]
		NCCIEVNT = buff[29:29+4]

		if NCCIEVNT == "\x00\x00\x00\x00":
			# Reset the connection with type K
			reply = self.build_reset() #Type 'K'
			self.msg("Sending  >> Reset Record type: %r", self.EbcdicToAscii(reply[18]))
			self.sendData(reply)
			self.INC_SEQUENCE() #Every time we send data we should increment. Maybe I should add this to a 'send NJE'.......
			buff = self.getData()
			self.msg("Response << Record Type: " + self.EbcdicToAscii(buff[18]))
		else:
			# We're not the big boss, send concurrence
			reply = self.build_concurrence(NCCIEVNT) #Type 'L'
			self.msg("Sending  >> Concurrence Record type: %r", self.EbcdicToAscii(reply[18]))
			self.sendData(reply)
			self.INC_SEQUENCE() #Every time we send data we should increment. Maybe I should add this to a 'send NJE'.......
		
		self.msg("Sequence is: " + self.phex(chr(self.sequence)))
		self.msg("Own Node   : " + self.phex(self.own_node))
		self.msg("Dest Node  : " + self.phex(self.target_node))
		return True

	def nmrCommand(self, command):
		self.msg("Sending command: %r", command)
		fake_nmr      = self.createNMR(command)
		NMR_with_TTR  = self.makeTTR_data_block_header(fake_nmr)
		NMR_with_TTB  = self.makeTTB(NMR_with_TTR) # My final form!
		self.sendData(NMR_with_TTB)
		self.INC_SEQUENCE()
		buf = self.getData()
		# All messages will now be compressed using SCB. 
		# Since it's an NMR we'll decode the response
		return self.decodeNMR(buf)

		 

	def createNMR(self, command):
		# Makes Node Message Records. Essentially master console commands
		# command = console command to run

		DLE  = "\x10"
		STX  = "\x02"
		BCB  = chr(self.sequence)
		FCS  = "\x8F\xCF"
		RCB  = "\x9A" # Commands are of the type '9A'
		SRCB = "\x80" # Commands don't have an SRCB	
		NMRFLAG = "\x90"
		NMRLEVEL= "\x77" # The level, we put it as essential
		NMRTYPE = "\x00" # 00 for unformatted commands. Which is what we send
		NMRTO   = self.OHOST + self.own_node # This is TO node name. The last byte should be 00 but I'm wondering if it matters
		NMROUT  = "\x00\x00\x00\x00\x01\x00\x00\x01" # was 00:00:00:00:01:00:00:01 but no idea if it needs to be
		NMRFM   = self.RHOST + self.target_node # From. 01 should be the last byte
		NMRMSG  = self.AsciiToEbcdic(command)
		NMRML   = chr(len(NMRMSG))
		NMR =(NMRFLAG  + 
		      NMRLEVEL +
		      NMRTYPE  +
		      NMRML    +
		      NMRTO    +
		      NMROUT   +
		      NMRFM    +
		      NMRMSG   )
		packet = DLE + STX + BCB + FCS + RCB + SRCB + self.makeSCB(NMR)
		return packet

	def decodeNMR(self, nmr):
		#Since we made a terrible 'recvALL' we gotta deal with this here:
		messages = ''
		while len(nmr) > 0:
			total_length = self.readTTB(nmr)
			self.msg("Total Length (TTB): %r", total_length)
			total_record_length = self.readTTR(nmr[8:])
			self.msg("Record Length (TTR): %r", total_record_length)
			cur_nmr = nmr[12:total_record_length+10] #skip the TTB and TTR. it really should be +8 not +10 but this works for now
			DLE  = cur_nmr[0]
			STX  = cur_nmr[1]
			BCB  = cur_nmr[2]
			FCS  = cur_nmr[3:3+2]
			RCB  = cur_nmr[5]
			SRCB = cur_nmr[6]
			self.readRCB(RCB)
			self.msg("[SRCB] %r", self.phex(SRCB))
			# Everything left in the packet will be compressed using SCB
			# Decompress using the readSCB function
			cur_nmr = self.readSCB(cur_nmr[7:])

			while len(cur_nmr) > 0:
				NMRFLAG  = cur_nmr[0x00]   #Flags TODO: Check these I guess
				NMRLEVEL = cur_nmr[0x01]   #and NMRPRIO techincally
				NMRTYPE  = cur_nmr[0x02]   #Type of Message
				NMRML    = cur_nmr[0x03]   #Length of the message
				NMRTO    = cur_nmr[0x04:0x0C]
				NMRTOQUL = cur_nmr[0x0C]
				NMROUT   = cur_nmr[0x0D:0x15]
				NMRFM    = cur_nmr[0x15:0x1E]
				msg_length = struct.unpack("b", NMRML)[0]

				# An undocumented feature appears! Pads spaces. Thanks IBM! 
				i = 0
				while 0x1E + msg_length + i < len(cur_nmr):
					if cur_nmr[0x1E+msg_length+i] != "\x40":
						break
					else:
						i += 1
				msg_length += i

				NMRMSG   = cur_nmr[0x1E:0x1E+msg_length]   #OMG The ACTUAL contents
				self.msg("NMRFLAG: %r", self.phex(NMRFLAG))
				self.msg("NMRLEVEL: %r", self.phex(NMRLEVEL))
				self.msg("NMRTYPE: %r", self.phex(NMRTYPE))
				self.msg("NMRML: %r", self.phex(NMRML))
				self.msg("Length: %r", msg_length)
				self.msg("NMRTO: %r", self.EbcdicToAscii(NMRTO))
				self.msg("NMRFM: %r", self.EbcdicToAscii(NMRFM[:-1]))				
				self.msg("NMRTOQUL: %r", self.phex(NMRTOQUL))
				self.msg("NMRFMQUL: %r", self.phex(NMRFM[-1]))
				self.msg("NMROUT: %r", self.phex(NMROUT))
				self.msg("Current Message: %r", self.EbcdicToAscii(NMRMSG))
				messages += self.EbcdicToAscii(NMRMSG) + u'\n'
				cur_nmr = cur_nmr[0x1E+msg_length:]
			nmr = nmr[total_length:]
		return messages
					
	def parseNMRFLAG(self, NMRFLAG):
		print "LOOOL"


	def check_signoff(self, buf):
		if self.EbcdicToAscii(buf[18]) == 'B':
			print "[+] Recieved Signoff Record of type 'B'. Closing Connection."
			self.disconnect()
			return False
		else:
			return True

	def build_SOHENQ(self):
		# Now we need to create a TTB. All NJE Packets have a TTB and a TTR.
		self.msg("Sending  >> SOH ENQ")
		# SOH (0x01) and ENQ (0x2D) are control chars and are the next thing we have to send
		#         |-------------TTB----------------|TTR------------|SOH-ENQ|TTB EOB--------|
		# Will be "\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x02\x01\x2D\x00\x00\x00\x00"
		SOHENQ = "\x01\x2D"
		with_TTR = self.makeTTR_data_block_header( SOHENQ )
		with_TTB = self.makeTTB(with_TTR)
		return with_TTB

	def build_I(self):
		''' Creates Initial Signon Record 'I' '''
        # Now we have to send the 'I' for Initial signon. Yes, we built this by hand
        # TODO: TTR/TTB creator function      
		# From Page 111 in has2a620.pdf
		#                    |--------- TTB ------------------|---- TTR ------|DLE-STX|
		Initialize_record = ("\x00\x00\x00\x3E\x00\x00\x00\x00\x00\x00\x00\x2E\x10\x02"
				             ) + chr(self.sequence) + ( #BCB - tracks the sequence number
				             "\x8F\xCF" #FCS
							 "\xF0" # NCCRCB
							 "\xC9" # NCCSRCB: EBCDIC letter 'I'
							 "\x29" # LENGTH OF RECORD
							 )+ self.RHOST + self.own_node + (
							 "\x00\x00\x00\x00" #NCCIEVNT - Not used for I record
							 "\x00\x64" # Node Resistance - NCCIREST
							 "\x80\x00" # Buffer Size. Set to: 32768
							 # Password
							 ) + self.padding(self.password)*2 + (
							 "\x00" # NCCIFLG - 00 for initial signon
							 "\x15\x00\x00\x00" + # NCCIFEAT - Something
							 "\x00\x00\x00\x00"   # and the rest
							 )
		return Initialize_record

	def build_reset(self):
		''' Builds Reset Signon Record '''
		reset_signon =  ("\x00\x00\x00\x1E\x00\x00\x00\x00\x00\x00\x00\x0E\x10\x02"
				)+chr(self.sequence)+( #BCB
				"\x8F\xCF" #FCS
				"\xF0" #NCCRCB
				"\xD2" #SRCB = 'K'
				"\x09") 
		# Now, if you're the primary NCCIEVNT is going to be empty. So we put all FFs. Otherwise, we fill it up with the NCCIEVNT we got back from the primary
		reset_signon += "\xFF\xFF\xFF\xFF" + "\x00\xC8" + "\x00\x00\x00\x00"
		return reset_signon

	def build_concurrence(self, NCCIEVNT):
		''' Builds Reset Signon Record '''
		concurrent_signon =  ("\x00\x00\x00\x1E\x00\x00\x00\x00\x00\x00\x00\x0E\x10\x02"
				)+chr(self.sequence)+( #BCB
				"\x8F\xCF" #FCS
				"\xF0" #NCCRCB
				"\xD3" #SRCB = 'L'
				"\x09") 
		concurrent_signon += NCCIEVNT + "\x00\xC8" + "\x00\x00\x00\x00"
		return concurrent_signon

	def padding(self, word):
		''' Converts text to EBCDIC and appends spaces until the string is 8 bytes long '''
		return self.AsciiToEbcdic(word) + SPACE * (8-len(word))

	def hsize(self, b_array):
		return struct.unpack('>H', b_array)[0]

	def makeTTB(self, data):
		# TTB includes it's own length of 8 plus the EOB of 4 bytes. 
		return ("\x00\x00" + struct.pack('>H', len(data)+8+4) +  
			    "\x00\x00\x00\x00" + data + "\x00\x00\x00\x00")

	def makeTTR_data_block_header(self, data):
		# a datablock TTR doesn't include it's own length of 4 nor an EOB
		return "\x00\x00" + struct.pack('>H', len(data)) + data

	def makeTTR_block_header(self, data):
		# a regular TTR doesn't include it's own length of 4 but does add an EOB for TTR which is one byte long
		return ("\x00\x00" + struct.pack('>H', len(data) + 1) + 
			    "\x00\x00\x00\x00" + data + "\x00" )

	def readTTB(self, TTB):
		''' TTB is 4 bytes long. Only the 2nd and 3rd bytes are used as the length '''
		''' returns an int of the length '''
		return self.hsize(TTB[2:4])	

	def readTTR(self, TTR):
		''' TTR is the length of the record. Only the 2nd and 3rd bytes are used as the length '''
		''' returns an int of the length '''
		return self.hsize(TTR[2:4])

	def getData(self):
		data = ''
		r, w, e = select([self.sock], [], [])		
		for i in r:
			try:
				buf = self.sock.recv(256)
				data += buf
				self.msg("Recieved: %r", self.phex(buf) )
				while( buf != ''):
					buf = self.sock.recv(256)
					data += buf
				if(buf == ''):
					break
			except socket.error:
				pass
	   	return data

	def sendData(self, data):
		"""Sends raw data to the NJE server """
		self.sock.sendall(data)

	def phex(self, stuff):
		hexed = binascii.hexlify(bytearray(stuff))
		return ':'.join(hexed[i:i+2] for i in range(0, len(hexed), 2))

	def readRCB(self,RCB):
		# Record Control Byte  				(Pg 124)
		"""Decodes the RCB: 

			00	End-of-block (BSC)
			90	Request to initiate stream (SRCB=RCB of stream to be initiated)
			A0	Permission to initiate stream (SRCB=RCB of stream to be initiated)
			B0	Negative permission or receiver cancel (SRCB=RCB of stream to be denied)
			C0	Acknowledge transmission complete (SRCB=RCB of stream received)
			D0	Ready to receive stream (SRCB=RCB of stream to be received)
			E0	BCB sequence error
			F0	General control record
			98-F8	SYSIN record
			99-F9	SYSOUT record
			9A	Operator command/console message
		"""
		if RCB == "\x00":
			self.msg("[RCB] End-of-block (BSC) (00)")
			return "EOB"
		elif RCB == "\x90":
			self.msg("[RCB] Request to initiate stream (90)")
			return "INITIATE"
		elif RCB == "\xA0":
			self.msg("[RCB] Permission to initiate stream (A0)")
			return "PERMISSION"
		elif RCB == "\xB0":
			self.msg("[RCB] Negative permission or receiver cancel (B0)")
			return "NEGATIVE"
		elif RCB == "\xC0":
			self.msg("[RCB] Acknowledge transmission complete (C0)")
			return "COMPLETE"
		elif RCB == "\xD0":
			self.msg("[RCB] Ready to receive stream (D0)")
			return "RECIEVE"
		elif RCB == "\xE0":
			self.msg("[RCB] BCB sequence error (E0)")
			return "SEQUENCE"
		elif RCB == "\xF0":
			self.msg("[RCB] General control record (F0)")
			return "CONTROL"
		elif "\x98" <= RCB <= "\xF8":
			self.msg("[RCB] SYSIN record (98-F8)")
			return "SYSIN"
		elif "\x99" <= RCB <= "\xF9":
			self.msg("[RCB] SYSOUT record (99-F9)")
			return "SYSOUT"
		elif RCB == "\x9A":
			self.msg("[RCB] Operator command/console message (9A)")
			return "CONSOLE"

	def readSRCB(self, SRCB):
		# Subrecord Control Byte 				(Pg 125)
		""" Reads the SRCB
			RCB	SRCB
			00	None
			90	RCB of stream to be initiated
			A0	RCB of stream to be initiated
			B0	RCB of stream to be cancelled or rejected
			C0	RCB of completed stream
			D0	RCB of ready stream receiver
			E0	Expected count - BCB sequence error (received count is in BCB)
			F0	An identification character as follows:
						A = Reserved
						B = Network SIGNOFF
						C-H = Reserved
						I = Initial network SIGNON
						Must be only record in transmission buffer
						J = Response to initial network SIGNON
						Must be only record in transmission buffer
						K = Reset network SIGNON
						L = Accept (concurrence) network SIGNON
						M = Add network connection
						N = Delete network connection
						O-R = Reserved for IBM's use
			98-F8	NJE SYSIN control information as follows:
						1000 0000 - Standard record
						1100 0000 - Job header
						1110 0000 - Data set header
						1101 0000 - Job trailer
						1111 0000 - Reserved
						1111 0000 - Reserved for IBM's use
			99-F9	NJE SYSOUT control information as follows:
						10cc 0000 - Carriage control type as follows:
							1000 0000 - No carriage control
							1001 0000 - Machine carriage control
							1010 0000 - ASA carriage control
							1011 0000 - CPDS page mode records (with carriage control)
						10cc ss00 - Spanned record control as follows:
							10.. 0000 - Standard record (not spanned)
							10.. 1000 - First segment of spanned record
							10.. 0100 - Middle segment of spanned record
							10.. 1100 - Last segment of spanned record
						11cc 0000 - Control record as follows:
							1100 0000 - Job header
							1110 0000 - Data set header
							1101 0000 - Job trailer
							1111 0000 - Reserved for IBM's use
			9A	Operator Command/Message (NMR)
						1000 0000 (X'80')
						"""
		return 'Placeholder'

	def hex2ip(self, ip_addr):
		ip = ''
		for i in range(0,len(ip_addr)):
			ip += str(struct.unpack('<B', ip_addr[i])[0])+"."
		return ip[:-1]

	def makeSCB(self, data):
		''' This (painfully) implements the SCB compression. '''
		# String Control Byte 				(Pg 123)
		# More information available here:
		# http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.hasa600/nscb.htm
		if len(data) == '': return ''
		c = 0
		buf = data
		d = '' # Returned Data
		t = '' # Temp data while we count
		while len(buf) > 0:
			if ord(buf[0]) == 0x40 and ord(buf[1]) == 0x40:
				if c > 0: d += chr(0xC0 + c) + t # If we go straight from repeat char to repeat spaces this creates an extra char
				t = ''
				c = 1
				while ord(buf[c]) == 0x40:
					c += 1
				d += chr(0x80 + c)
				buf = buf[c-1:]
				c = 0
			elif len(buf) > 2 and ord(buf[0]) == ord(buf[2]) and ord(buf[0]) == ord(buf[1]):
				if c > 0: d += chr(0xC0 + c) + t # Same as above. This if fixes that
				t = ''
				c = 2
				while ord(buf[c]) == ord(buf[0]):
					c += 1
				d += chr(0xA0 + c) + buf[0]
				buf = buf[c-1:]
				c = 0
			elif c == 63: 
				d += chr(0xC0 + c) + t
				t = ''
				c = 0
			else:
				t += buf[0]
				c += 1
			buf = buf[1:]
		if c > 0: d += chr(0xC0 + c) + t
		return d+'\x00'	

	def readSCB(self, data):
		# String Control Byte 				(Pg 123)
		self.msg("Decompressing String Control Bytes")
		if len(data) <= 0: return ''
		SCB = data[0]
		position = 1
		de_compressed = ''
		SCB_type = ord(SCB) & 0xC0
		if SCB_type == 0xC0:
			self.msg("SCB Type 0xC0")
		# 11cccccc Indicates that 'cccccc' non-compressed characters (maximum of 63) follow the SCB. (The record is compressed; these characters are not.)
			count = ord(SCB) & 0x3f
			self.msg("%r non-compressed chars follow", count)
			#self.msg("remaining: %r", len(data))
			if count >= len(data):
				count = len(data) - 1

			for i in range(0,count):
				de_compressed += data[position]
				position += 1
			de_compressed += self.readSCB(data[position:])
		elif SCB_type == 0x80:
			self.msg("SCB Type 0x80")
			# It's either of type b'101' (chars) or b'100' (blanks aka 0x40)
			count = ord(SCB) & 0x1f
			sub_type = ord(SCB) & 0xE0
			if sub_type == 0xA0:	# 100bbbbb Indicates that 'bbbbb' blanks should be inserted after the SCB.
				self.msg("Sub Type 0xA0")
				de_compressed = data[1] * count
				de_compressed += self.readSCB(data[2:])
			elif sub_type == 0x80:	# 101ddddd Indicates that the single character following the SCB should be duplicated 'ddddd' times.
				self.msg("Sub Type 0x80")
				#if ord(SCB) == 0x98: 
					# UGLY HACK !!!! Fix Later. It ""Appears"" that 0x0098 is the field seperator. 
					#de_compressed = readSCB(data[1:])
				#else: 
				de_compressed = '\x40' * count
				de_compressed += self.readSCB(data[1:])
		elif SCB_type == 0x00:
			self.msg("SCB Type 0x00")
			self.msg("Data remaining: %r", len(data[1:]))
			# 00000000 Indicates the end of the NJE record
			# de_compressed = '\x00'
			if len(data[1:]) > 0: 
				self.msg("Recursing")
				if ord(data[1:2]) == 0x98: 
					de_compressed = self.readSCB(data[2:])		
				else: de_compressed = self.readSCB(data[1:])
		return de_compressed
