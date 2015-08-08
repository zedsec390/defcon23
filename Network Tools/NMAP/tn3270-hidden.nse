local stdnse = require "stdnse"
local shortport = require "shortport"
local tn3270 = require "tn3270"

description = [[
Connects to a tn3270 'server' and displays hidden fields
]]

---
-- @usage
-- nmap --script tn3270-info,tn3270-hidden --script-args tn3270.commands='netview' <host> 
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 23/tcp open  tn3270  syn-ack Telnet TN3270
-- | tn3270-hidden:
-- |   Hidden Field # 1: Type the number of your terminal:
-- |     Column: 1
-- |     Row   : 9
-- |   Hidden Field # 2: SKRIV SYSTEMNAVN ==>
-- |     Column: 40
-- |_    Row   : 9
--
-- @args tn3270.space whether you want to display hidden fields that
--                    only contain space. Set to 'true' to display these
--                    fields.
-- @args tn3270.commands a semi-colon seperated list of commands you want to 
--                       issue before you check the screen for hidden fields.
--                       For example if you want to get to a specific CICS
--                       application you pass the commands 'cics;pay1' to check
--                       the CICS transacion 'pay1'.  
--
-- @changelog
-- 2015-05-03 - v0.1 - created by Soldier of Fortran
--

author = "Soldier of Fortran"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}
dependencies = {"tn3270-info"}

portrule = shortport.port_or_service({23,992,623}, {"tn3270"})

action = function(host, port)
  local t = Telnet:new()
  local status, err = t:initiate(host,port)
  local commands = stdnse.get_script_args('tn3270.commands')
  local spaces = stdnse.get_script_args('tn3270.spaces')
  if not status then
    stdnse.debug("Could not initiate TN3270: %s", err )
    return
  else
    if commands ~= nil then
      status = t:get_all_data()
      t:get_screen_debug() -- prints the current screen in the debug output
      local run = stdnse.strsplit(";%s*", commands)
      for i = 1, #run do 
        stdnse.debug(1,"Issuing Command (#%s of %s): %s", i, #run ,run[i])
        t:send_cursor(run[i])
        t:get_all_data()
        --t:get_screen_debug()
        --t:get_all_data()
      end
    end
    
    if t:any_hidden() then
      local results = {}
      local locations = {}
      local hidden_locs = t:hidden_fields_location()
      local hidden_buggers = t:hidden_fields()
      local j = 1
      for i = 1, #hidden_buggers do
        stdnse.debug(3, "Hidden Field # %s: %s", i, hidden_buggers[i])
        stdnse.debug(3, "Column: %s", t:BA_TO_COL(hidden_locs[j]))
        stdnse.debug(3, "Row   : %s", t:BA_TO_ROW(hidden_locs[j]))
        stdnse.debug(3, "Spaces: %s", spaces)

        if hidden_buggers[i]:find('[%w]') ~= nil then
          table.insert(results, ("Hidden Field # %s: %s"):format(i, hidden_buggers[i]))
          table.insert(locations, ("Column: %s"):format(t:BA_TO_COL(hidden_locs[j])))
          table.insert(locations, ("Row   : %s"):format(t:BA_TO_ROW(hidden_locs[j])))
          table.insert(results, locations)
          locations = {}
        elseif spaces == "true" then
          table.insert(results, ("Hidden Field # %s: %s"):format(i, hidden_buggers[i]))
          table.insert(locations, ("Column: %s"):format(t:BA_TO_COL(hidden_locs[j])))
          table.insert(locations, ("Row   : %s"):format(t:BA_TO_ROW(hidden_locs[j])))
          table.insert(results, locations)
          locations = {}
        end
        j = j + 2

      end -- end for loop
      if #results > 1 then
        return stdnse.format_output( true, results )
      else
        return "All hidden fields only contain spaces. To see these fields use --script-args tn3270.spaces=true"
      end
    else
      return "No Hidden Fields"
    end

  end
end