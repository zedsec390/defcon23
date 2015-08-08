local stdnse = require "stdnse"
local shortport = require "shortport"
local nsedebug  = require "nsedebug"

description = [[Mainframe: Detects ports running TN3270. While TN3270 is similar to telnet it's a specific protocol.]]


---
--
-- @usage
-- nmap --script=tn3270-info -p 23 -sV <targets>
--
-- @output
-- PORT   STATE  SERVICE VERSION
-- 23/tcp open   tn3270  Telnet 3270
-- or if ssl
-- PORT   STATE SERVICE    VERSION
-- 23/tcp open  ssl/tn3270 Telnet 3270 SSL
--
-- @changelog
-- 2015-06-10 - v0.1 - created by Soldier of Fortran
--

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = function(host, port)
        return (port.number == 23 or port.number == 992 or
                port.service == nil or port.service == "" or
                port.service == "unknown" or port.service == "telnets" or
                port.service == "ssl/telnet" or port.service == "telnet") and (port.protocol == "tcp" or port.protocol == "ssl") 
                and port.state == "open"
                and not(shortport.port_is_excluded(port.number,port.protocol))
end

local TN_PROTOCOLS = {
  "ssl",
  "tcp"
}

local tn_open = function(host, port)
  for _, proto in pairs(TN_PROTOCOLS) do
    local sock = nmap.new_socket()
    sock:set_timeout(2000)
    local status, err = sock:connect(host, port, proto)
    if status then
      TN_PROTOCOLS = {proto}
      return true, sock
    end
    stdnse.debug(2,"Can't connect using %s: %s", proto, err)
    sock:close()
  end

  return false, nil
end


-- The Action Section --
action = function(host, port)
  -- TN3270 sends FF:FD:28 if it does TN3270 
	local IAC_DO_TN3270E = string.char(0xff,0xfd,0x28)
  local IAC_DO_TERMINAL_TYPE = string.char(0xff,0xfd,0x18)
  local status, sock = tn_open(host, port)
  if not status then
    return false, nil
  end

  local status, handshake = sock:receive_bytes(3)

  stdnse.debug("Starting TN3270 handshake")

  if status == true and handshake == IAC_DO_TN3270E then
    -- Sometimes we connect and it asks if we want 3270. If so, we're done
    if TN_PROTOCOLS[1] == "ssl" then
      stdnse.verbose(2,"SSL TN3270 Detected")
      port.version.product = "Telnet TN3270 w/SSL"
    else
      stdnse.verbose(2,"TN3270 Detected")
      port.version.product = "Telnet TN3270"
    end
    port.version.name = "tn3270"
    nmap.set_port_version(host, port)

  elseif status == true and handshake == IAC_DO_TERMINAL_TYPE then
    -- Otherwise it will handshake normal telnet so we want to ask it if it supports 3270
    -- if so, we're done
    local IAC_WILL_TERMINAL_TYPE = string.char(0xff,0xfb,0x18)
    local IAC_SEND_TERMINAL_TYPE = string.char(0xff,0xfa,0x18,0x01,0xff,0xf0)
    local IAC_TERMINAL_TYPE      = string.char(0xff,0xfa,0x18,0x00) .. "IBM-3279-4-E" .. string.char(0xff,0xf0)
    local IAC_DO                 = string.char(0xff,0xfd,0x19)
    sock:send(IAC_WILL_TERMINAL_TYPE)
    status, handshake = sock:receive_bytes(6)
    if status == true and handshake == IAC_SEND_TERMINAL_TYPE then
        sock:send(IAC_TERMINAL_TYPE)
        status, handshake = sock:receive_bytes(3)
        if status == true and handshake:sub(1,3) == IAC_DO then
            if TN_PROTOCOLS[1] == "ssl" then
              stdnse.verbose(2,"SSL TN3270 Detected")
              port.version.product = "Telnet TN3270S"
            else
              stdnse.verbose(2,"TN3270 Detected")
              port.version.product = "Telnet TN3270"
            end
            port.version.name = "tn3270"
            nmap.set_port_version(host, port)
        end
    end
	end -- End telnet handshake test
sock:close()
return 

end