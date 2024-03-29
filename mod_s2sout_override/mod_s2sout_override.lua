--% requires: s2sout-pre-connect-event

local url = require"socket.url";
local basic_resolver = require "net.resolvers.basic";

local override_for = module:get_option(module.name, {}); -- map of host to "tcp://example.com:5269"

module:hook("s2sout-pre-connect", function(event)
	local override = override_for[event.session.to_host] or override_for[event.session.to_host:gsub("^[^.]+%.", "*.")] or override_for["*"];
	if type(override) == "string" then
		override = url.parse(override);
	end
	if type(override) == "table" and override.scheme == "tcp" and type(override.host) == "string" then
		event.resolver = basic_resolver.new(override.host, tonumber(override.port) or 5269, override.scheme, {});
	elseif type(override) == "table" and override.scheme == "tls" and type(override.host) == "string" then
		event.resolver = basic_resolver.new(override.host, tonumber(override.port) or 5270, "tcp",
			{ servername = event.session.to_host; sslctx = event.session.ssl_ctx });
	end
end);
