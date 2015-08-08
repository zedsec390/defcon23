local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[Mainframe: Detects ports running z/OS Network Job Entry (NJE)]]

---
-- @output
-- PORT    STATE SERVICE VERSION
-- 175/tcp open  nje     z/OS Network Job Entry

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
        return (port.number == 175 or port.number == 2252 or
                port.service == nil or port.service == "" or
                port.service == "unknown") and (port.protocol == "tcp" or port.protocol == "ssl") 
                and port.state == "open"
                and not(shortport.port_is_excluded(port.number,port.protocol))
end

local NJE_PROTOCOLS = {
  "ssl",
  "tcp"
}

local nje_open = function(host, port)
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  for _, proto in pairs(NJE_PROTOCOLS) do
    local sock = nmap.new_socket()
    sock:set_timeout(2000)
    local status, err = sock:connect(host, port, proto)
    if status then
      NJE_PROTOCOLS = {proto}
      return true, sock
    end
    stdnse.debug2("Can't connect using %s: %s", proto, err)
    sock:close()
  end

  return false, nil
end


-- The Action Section --
action = function(host, port)
  -- NJE either replies 
	local NAK = string.char(0xd5,0xc1,0xd2)
  local ACK = string.char(0xc1,0xc3,0xd2)
  -- openNJE: A fake NJE 'OPEN' BCS packet
  local openNJE = string.char(0xd6,0xd7,0xc5,0xd5,0x40,0x40,0x40,0x40,0xc6,0xc1,0xd2,
                              0xc5,0x40,0x40,0x40,0x40,0x00,0x00,0x00,0x00,0xc6,0xc1,
                              0xd2,0xc5,0x40,0x40,0x40,0x40,0x00,0x00,0x00,0x00,0x00)
  local status, sock = nje_open(host, port)
  if not status then
    return false, nil
  end
  sock:send(openNJE)
  stdnse.verbose(2,"Sent: Type = OPEN & OHOST/RHOST = FAKE")
	
  -- Sending the following BSC NJE packet: 
  -- TYPE        = OPEN
  -- OHOST       = FAKE
  -- RHOST       = FAKE
  -- RIP and OIP = 0.0.0.0
  -- R           = 0
  -- Based on http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.hasa600/init.htm
  
  
	local status, response = sock:receive_bytes(33)
	sock:close()

	if status == true and (string.sub(response,1,3) == NAK or string.sub(response,1,3) == ACK) then
		stdnse.verbose(2,"NJE Detected")
    if NJE_PROTOCOLS[1] == "ssl" then
        port.version.name = "njes"
        port.version.product = "z/OS Network Job Entry over SSL"
    else
        port.version.name = "nje"
        port.version.product = "z/OS Network Job Entry"
    end
    
    nmap.set_port_version(host, port)
    return
	end

return 

end