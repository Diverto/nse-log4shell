local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

author = "Vlatko Kosturjak <kost@linux.hr>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[
Queries dnslog.cn API for dns subdomain
]]


-- Begin
if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    session = ''
  }
end
local registry = nmap.registry[SCRIPT_NAME]

prerule = function()
  return true
end

postrule = function()
  if not nmap.registry[SCRIPT_NAME].session then
    stdnse.debug1("Skipping script as there is no session.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

hostrule = function(host)
  if not nmap.registry[SCRIPT_NAME].session then
    stdnse.debug1("Skipping script as there is no session.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

local function get_log ()
  local request_opts = {
    header = {
      Connection = "close"
    },
    bypass_cache = true,
    no_cache = true
  }

  local pcookie = "PHPSESSID" .. registry.session
  request_opts['header']['Cookie'] = pcookie

  local curlcmd = 'curl --cookie "PHPSESSID='..registry.session..'" http://dnslog.cn/getrecords.php'
  response = http.get( "dnslog.cn", 80, "/getrecords.php", request_opts )
  if (response.status ~= 200) then
    stdnse.debug1("Bad response from dnslog.cn: %s", response.status)
    return 'Error retrieving, try manually with: '..curlcmd
  end
  local result = stdnse.output_table()
  table.insert(result, "List of hosts responded: "..response.body)
  table.insert(result, "Manually retrieve: "..curlcmd)
  table.insert(result, "If list is not empty, check hosts as they are potentially vulnerable")
  return result
  -- return 'List of hosts responded, potentially vulnerable, check them: '..response.body .. ' or manually with ' .. curlcmd

end

hostaction = function(host)
  -- since dnslog.cn expire session, it is critical to query it often
  return get_log()
end

preaction = function()
    local response = http.get("dnslog.cn", 80, "/getdomain.php")
    if (response.status ~= 200) then
      stdnse.debug1("Bad response from dnslog.cn: %s", response.status)
      return nil
    end

    if not response.cookies then
      stdnse.debug1("No cookie from dnslog.cn: %s", response.status)
      return 'server did not return any cookie'
    end

    for _, cookie in pairs(response.cookies) do
      if cookie.name == "PHPSESSID" then
	stdnse.debug1("Found PHP session %s %s", response.body, cookie.value)
	registry.session=cookie.value
	registry.domain=response.body
        local curlcmd = 'curl --cookie "PHPSESSID='..registry.session..'" http://dnslog.cn/getrecords.php'
	local result = stdnse.output_table()
	table.insert(result, "Domain: "..registry.domain)
	table.insert(result, "Manually retrieve: "..curlcmd)
	return result
      end
    end
    return 'could not retrieve dnslog domain name for check: '..response.body
end

postaction = function ()
  return get_log()
end

local ActionsTable = {
  -- prerule: scan target from script-args
  prerule = preaction,
  hostrule = hostaction,
  -- postrule: report results
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
