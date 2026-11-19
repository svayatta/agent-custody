# The door middleware in front of a Rack app, called with a Rack env as Rails and every Rack server call it.
# DOOR_URL points at `agent-custody door` with "authz": true; CUSTODY_GRANT is a passport scoped to the refund route.
require "socket"
require "stringio"
require_relative "agent_custody_door"

def fail!(msg)
  warn "ruby: #{msg}"
  exit 1
end

door_url = ENV["DOOR_URL"].to_s
grant = ENV["CUSTODY_GRANT"].to_s
fail!("set DOOR_URL and CUSTODY_GRANT") if door_url.empty? || grant.empty?

seen = nil
shop = lambda do |env|
  seen = { receipt: env["HTTP_X_AGENT_CUSTODY_RECEIPT"], class: env["HTTP_X_AGENT_CUSTODY_CLASS"],
           grant: env["HTTP_X_AGENT_CUSTODY_GRANT"], body: env["rack.input"].read }
  [200, { "content-type" => "application/json" }, ['{"shop":"answered"}']]
end

call = lambda do |app, method, path, query: "", body: "", headers: {}|
  seen = nil
  env = { "REQUEST_METHOD" => method, "SCRIPT_NAME" => "", "PATH_INFO" => path, "QUERY_STRING" => query,
          "SERVER_NAME" => "shop.example", "SERVER_PORT" => "443", "SERVER_PROTOCOL" => "HTTP/1.1",
          "HTTP_HOST" => "shop.example", "REMOTE_ADDR" => "203.0.113.7", "rack.url_scheme" => "https",
          "rack.input" => StringIO.new(body), "rack.errors" => $stderr }
  env["CONTENT_LENGTH"] = body.bytesize.to_s unless body.empty?
  headers.each { |k, v| env[k] = v }
  status, response_headers, chunks = app.call(env)
  text = +""
  chunks.each { |c| text << c }
  [status, response_headers, text]
end

guarded = AgentCustody::Door.new(shop, door_url: door_url, timeout: 5)

# 1. A public read: allowed, and the app sees the door's receipt in place of the one the client forged.
status, headers, = call.call(guarded, "GET", "/catalogue/shoes", query: "colour=red",
                             headers: { "HTTP_X_AGENT_CUSTODY_RECEIPT" => "forged", "HTTP_X_FORWARDED_FOR" => "198.51.100.66", "HTTP_USER_AGENT" => "example-browser" })
unless status == 200 && seen && !seen[:receipt].to_s.empty? && seen[:receipt] != "forged" && seen[:receipt] == headers[AgentCustody::Door::RECEIPT] && seen[:class] == "unknown"
  fail!("allowed read: status #{status}, seen #{seen.inspect}")
end
puts "ruby: GET /catalogue/shoes allowed, class #{seen[:class]}"
puts "receipt allowed #{seen[:receipt]}"

# 2. An unknown arrival's refund: refused with the door's 403 and body; the app never runs. The client's own
# X-Original-* headers do not change what the door decides on.
status, headers, text = call.call(guarded, "POST", "/refunds", body: '{"amount":1000}',
                                  headers: { "CONTENT_TYPE" => "application/json", "HTTP_X_ORIGINAL_METHOD" => "GET", "HTTP_X_ORIGINAL_URI" => "/catalogue/free" })
denied = headers[AgentCustody::Door::RECEIPT].to_s
fail!("refused refund: status #{status}, ran #{!seen.nil?}, body #{text}") unless status == 403 && seen.nil? && !denied.empty? && text.include?("refused by the door's policy")
puts "ruby: POST /refunds refused 403"
puts "receipt denied #{denied}"

# 3. A verified agent's refund: allowed after the door committed it to the log; the app gets the body, the receipt,
# and the class, and never the grant.
status, headers, = call.call(guarded, "POST", "/refunds", body: '{"amount":1000}',
                             headers: { "CONTENT_TYPE" => "application/json", "HTTP_X_AGENT_CUSTODY_GRANT" => grant })
unless status == 200 && seen && seen[:class] == "verified" && seen[:grant].nil? && seen[:body] == '{"amount":1000}' && seen[:receipt] == headers[AgentCustody::Door::RECEIPT]
  fail!("verified refund: status #{status}, seen #{seen.inspect}")
end
puts "ruby: POST /refunds with a passport allowed, class #{seen[:class]}"
puts "receipt verified #{seen[:receipt]}"

# 4. A door that is down, and one that never answers: 503, and the app never runs.
gone = TCPServer.new("127.0.0.1", 0)
gone_port = gone.addr[1]
gone.close
status, = call.call(AgentCustody::Door.new(shop, door_url: "http://127.0.0.1:#{gone_port}", timeout: 2), "GET", "/catalogue/shoes")
fail!("unreachable door: status #{status}, ran #{!seen.nil?}") unless status == 503 && seen.nil?
puts "fail-closed unreachable #{status}"
silent = TCPServer.new("127.0.0.1", 0) # accepts connections and never answers
status, = call.call(AgentCustody::Door.new(shop, door_url: "http://127.0.0.1:#{silent.addr[1]}", timeout: 0.5), "GET", "/catalogue/shoes")
silent.close
fail!("silent door: status #{status}, ran #{!seen.nil?}") unless status == 503 && seen.nil?
puts "fail-closed timeout #{status}"
puts "OK"
