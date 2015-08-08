local stdnse = require "stdnse"
local shortport = require "shortport"
local tn3270 = require "tn3270"

description = [[
Connects to a tn3270 'server' and returns the screen.
]]

---
-- @usage
-- nmap --script tn3270-info,tn3270_screen <host> 
--
-- @output
-- PORT     STATE  SERVICE         VERSION
-- 23/tcp   open   tn3270          Telnet TN3270
-- | tn3270-screen:
-- |  Mainframe Operating System                              z/OS V1.6
-- |          FFFFF  AAA  N   N      DDDD  EEEEE      ZZZZZ H   H  III
-- |          F     A   A NN  N      D   D E             Z  H   H   I
-- |          FFFF  AAAAA N N N      D   D EEEE         Z   HHHHH   I
-- |          F     A   A N  NN      D   D E           Z    H   H   I
-- |          F     A   A N   N      DDDD  EEEEE      ZZZZZ H   H  III
-- |
-- |                         ZZZZZ      / OOOOO  SSSS
-- |                            Z      /  O   O S
-- |                           Z      /   O   O  SSS
-- |                          Z      /    O   O     S
-- |                         ZZZZZ  /     OOOOO SSSS
-- |
-- |                   Welcome to Fan DeZhi Mainframe System!
-- |
-- |                       Support: http://zos.efglobe.com
-- |          TSO      - Logon to TSO/ISPF        NETVIEW  - Netview System
-- |          CICS     - CICS System              NVAS     - Netview Access
-- |          IMS      - IMS System               AOF      - Netview Automation
-- |
-- | Enter your choice==>
-- | Hi! Enter one of above commands in red.
-- |
-- |_Your IP(10.10.10.375   :64199), SNA LU(        )       05/30/15 13:33:37
--
-- @changelog
-- 2015-05-30 - v0.1 - created by Soldier of Fortran
--

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}
dependencies = {"tn3270-info"}

portrule = shortport.port_or_service({23,992,623}, {"tn3270"})

action = function(host, port)
  local t = Telnet:new()
  local status, err = t:initiate(host,port)
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return
  else
    status = t:get_all_data()
    if t:any_hidden() then
      local hidden_buggers = t:hidden_fields()
      for i = 1, #hidden_buggers do
        stdnse.verbose("Hidden Field # %s: %s", i, hidden_buggers[i])
      end
    end
    return t:get_screen()
  end
end