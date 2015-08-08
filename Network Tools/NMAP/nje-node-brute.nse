local stdnse    = require "stdnse"
local shortport = require "shortport"
local brute     = require "brute"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local drda      = require "drda"
local nsedebug  = require "nsedebug"

description = [[
z/OS JES Network Job Entry (NJE) target node name brute force.

NJE node communication is made up of an OHOST and an RHOST. Both fields 
must be present when conducting the handshake. This script attemtps to
determine the target systems NJE node name. 

To initiate NJE the client sends a 33 byte record containing the type of 
record, the hostname (RHOST), IP address (RIP), target (OHOST), 
target IP (OIP) and a 1 byte response value (R) as outlined below: 

<code>
0 1 2 3 4 5 6 7 8 9 A B C D E F
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TYPE       |     RHOST     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  RIP  |  OHOST      | OIP   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| R |
+-+-+
</code>

* TYPE: Can either be 'OPEN', 'ACK', or 'NAK', in EBCDIC, padded by spaces to make 8 bytes. This script always send 'OPEN' type.
* RHOST: Name of the local machine initiating the connection. Set to 'FAKE'
* RIP: Hex value of the local systems IP address. Set to '0.0.0.0'
* OHOST: The value being enumerated to determine the target system name.
* OIP: IP address, in hex, of the target system. Set to '0.0.0.0'.
* R: The response. NJE will send an 'R' of 0x01 if the OHOST is wrong or 0x04/0x00 if the OHOST is correct.
]]


---
-- @usage
-- nmap --script=nje-node-brute <target>
--
-- nmap --script=nje-info,nje-node-brute --script-args=userdb=defaults_cics.txt -p 175 10.10.0.200
--
-- @output
-- PORT    STATE SERVICE REASON
-- 175/tcp open  nje     syn-ack
-- | nje-node-brute:
-- |   Node Name:
-- |     NEWYORK:<empty> - Valid credentials
-- |_  Statistics: Performed 14 guesses in 14 seconds, average tps: 1
-- Final times for host: srtt: 1228 rttvar: 3764  to: 100000

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}
dependencies = {"nje-info"}

portrule = shortport.port_or_service({175,2252}, {"nje","njes"})

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000


Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    return o
  end,
  connect = function( self )
    self.socket = nmap.new_socket()
    self.fu = false
    return self.socket:connect( self.host, self.port )
  end,
  disconnect = function( self )
    return self.socket:close()
  end,
  login = function( self, username, password ) -- Technically we're not 'logging in' we're just using password
  	-- Generates an NJE 'OPEN' packet with the node name
  	local patt = "[%w@#%$]"
  	stdnse.verbose(2,"Trying... %s", password)
  	if (string.len(password) <= 8 and string.match(password,patt)) then

	  	local openNJE = string.char(0xd6,0xd7,0xc5,0xd5,0x40,0x40,0x40,0x40,0xc6,0xc1,
	  							    0xd2,0xc5,0x40,0x40,0x40,0x40,0x00,0x00,0x00,0x00) .. 
                      drda.StringUtil.toEBCDIC(string.format("%-8s", string.upper(password))) .. 
                      string.char(0x00,0x00,0x00,0x00,0x00)
	    local status, err, data
	    status, err = self.socket:send( openNJE )
	    status, data = self.socket:receive_bytes(33)
	    --if string.sub(data,-1) == string.char(0x00) or string.sub(data,-1) == string.char(0x04) then
      if self.fu then
        self.fu = false
        stdnse.verbose("Valid Node Name Found: %s", string.upper(password))
	      return true, creds.Account:new(string.upper(password), "Valid", "Node Name")
      else
        self.fu = true
	    end
	end
    return false, brute.Error:new( "Invalid Node Name" )
  end,
}


-- Checks if it's a valid node name
local valid_name = function(x)
	local patt = "[%w@#%$]"
	stdnse.verbose("Checking: %s", x)
	return (string.len(x) <= 8 and string.match(x,patt))
end


action = function( host, port )

  local status, result
  local engine = brute.Engine:new(Driver, host, port)
  local users = unpwdb.filter_iterator(brute.usernames_iterator(),valid_name)

  engine.options:setOption("passonly", true )
  engine:setPasswordIterator(users)
  --engine:setMaxThreads(1)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setTitle("Node Name")
  status, result = engine:start()


  return result
end
