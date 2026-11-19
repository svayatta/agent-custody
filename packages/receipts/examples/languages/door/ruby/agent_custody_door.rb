# Rack middleware that asks an agent-custody door in authz mode ("authz": true) about each request before the app
# runs, as nginx auth_request does. Rails mounts it with `config.middleware.insert_before 0, AgentCustody::Door`.
# Standard library only (net/http, json); copy this file into your app.
require "json"
require "net/http"
require "uri"

module AgentCustody
  class Door
    RECEIPT = "x-agent-custody-receipt"
    CLASS = "x-agent-custody-class"
    LOG_PENDING = "x-agent-custody-log-pending"
    # Hop-by-hop and body fields stay off the check, which is its own GET with no body. The three the door decides on
    # are set here, never copied from the client.
    NOT_FORWARDED = %w[connection keep-alive proxy-connection te trailer transfer-encoding upgrade content-length expect
                       x-original-method x-original-uri x-forwarded-for].freeze
    # The door's credentials: the door reads them, the app does not get them.
    DOOR_ONLY = %w[HTTP_X_AGENT_CUSTODY_GRANT HTTP_X_AGENT_CUSTODY_AGENT].freeze

    # A door that cannot be reached, does not answer within `timeout` seconds, or allows without a receipt is a 503:
    # the request never runs ungated. Any answer but 200 goes to the client as the door gave it.
    def initialize(app, door_url: ENV.fetch("AGENT_CUSTODY_DOOR_URL"), timeout: 5)
      @app = app
      @check = URI(door_url.sub(%r{/+\z}, "") + "/_agent_custody")
      @timeout = timeout
    end

    def call(env)
      res = ask(env)
      return unavailable("the door could not be reached") if res.nil?
      receipt = res[RECEIPT].to_s
      return unavailable("the door allowed the request without a receipt") if res.code == "200" && receipt.empty?
      door_headers = [RECEIPT, CLASS, LOG_PENDING].each_with_object({}) { |h, out| out[h] = res[h] if res[h] }
      if res.code != "200"
        %w[content-type retry-after].each { |h| door_headers[h] = res[h] if res[h] }
        return [res.code.to_i, door_headers, [res.body.to_s]]
      end
      DOOR_ONLY.each { |k| env.delete(k) }
      env["HTTP_X_AGENT_CUSTODY_RECEIPT"] = receipt
      env["HTTP_X_AGENT_CUSTODY_CLASS"] = res[CLASS].to_s
      status, headers, body = @app.call(env)
      door_headers.each { |k, v| headers[k] = v }
      [status, headers, body]
    end

    private

    def ask(env)
      req = Net::HTTP::Get.new(@check)
      # net/http's defaults would be recorded as the client's
      %w[accept user-agent accept-encoding].each { |h| req.delete(h) }
      env.each do |key, value|
        next unless value.is_a?(String)
        name = if key.start_with?("HTTP_") then key[5..].tr("_", "-").downcase
               elsif key == "CONTENT_TYPE" then "content-type"
               end
        req[name] = value if name && !NOT_FORWARDED.include?(name)
      end
      req["x-original-method"] = env["REQUEST_METHOD"]
      req["x-original-uri"] = original_uri(env)
      req["x-forwarded-for"] = env["REMOTE_ADDR"].to_s
      Net::HTTP.start(@check.host, @check.port, use_ssl: @check.scheme == "https",
                      open_timeout: @timeout, read_timeout: @timeout, write_timeout: @timeout) { |http| http.request(req) }
    rescue StandardError
      nil
    end

    def original_uri(env)
      path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      path = "/" if path.empty?
      query = env["QUERY_STRING"].to_s
      query.empty? ? path : "#{path}?#{query}"
    end

    def unavailable(reason)
      [503, { "content-type" => "application/json" }, [JSON.generate(error: "not passed on: #{reason}")]]
    end
  end
end
