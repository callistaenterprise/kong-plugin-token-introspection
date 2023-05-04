local M = {}

local get_headers = ngx.req.get_headers
local set_header = kong.service.request.set_header
local clear_header = kong.service.request.clear_header

-- Split a string by whitespace, and represent resulting substrings as a Set
function M.as_set(inputstring)
  local set = {}
  for substring in string.gmatch(inputstring, "([^%s]+)") do
    set[substring] = true
  end
  return set
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  if message then
    local jsonMessage = '{"data":[],"error":{"code":' .. httpStatusCode .. ',"message":"' .. message .. '"}}'
    ngx.header['Content-Type'] = 'application/json'
    ngx.say(jsonMessage)
  end
  ngxCode = ngxCode or httpStatusCode
  ngx.exit(ngxCode)
end

function M.get_header(header)
  return get_headers()[header]
end

function M.set_header(header, value)
  if value then
    set_header(header, value)
  else
    clear_header(header)
  end
end

function M.clear_header(header)
  if header then
    clear_header(header)
  end
end

return M
