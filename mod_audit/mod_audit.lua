module:set_global();

local audit_log_limit = module:get_option_number("audit_log_limit", 10000);
local cleanup_after = module:get_option_string("audit_log_expires_after", "2w");

local attach_ips = module:get_option_boolean("audit_log_ips", true);
local attach_ipv4_prefix = module:get_option_number("audit_log_ipv4_prefix", nil);
local attach_ipv6_prefix = module:get_option_number("audit_log_ipv6_prefix", nil);

local have_geoip, geoip = pcall(require, "geoip.country");
local attach_location = have_geoip and module:get_option_boolean("audit_log_location", true);

local geoip4_country, geoip6_country;
if have_geoip and attach_location then
	geoip4_country = geoip.open(module:get_option_string("geoip_ipv4_country", "/usr/share/GeoIP/GeoIP.dat"));
	geoip6_country = geoip.open(module:get_option_string("geoip_ipv6_country", "/usr/share/GeoIP/GeoIPv6.dat"));
end

local time_now = os.time;
local ip = require "util.ip";
local st = require "util.stanza";
local moduleapi = require "core.moduleapi";

local host_wide_user = "@";

local stores = {};

local function get_store(self, host)
	local store = rawget(self, host);
	if store then
		return store
	end
	store = module:context(host):open_store("audit", "archive");
	rawset(self, host, store);
	return store;
end

setmetatable(stores, { __index = get_store });

local function get_ip_network(ip_addr)
	local _ip = ip.new_ip(ip_addr);
	local proto = _ip.proto;
	local network;
	if proto == "IPv4" and attach_ipv4_prefix then
		network = ip.truncate(_ip, attach_ipv4_prefix).normal.."/"..attach_ipv4_prefix;
	elseif proto == "IPv6" and attach_ipv6_prefix then
		network = ip.truncate(_ip, attach_ipv6_prefix).normal.."/"..attach_ipv6_prefix;
	end
	return network;
end

local function session_extra(session)
	local attr = {
		xmlns = "xmpp:prosody.im/audit",
	};
	if session.id then
		attr.id = session.id;
	end
	if session.type then
		attr.type = session.type;
	end
	local stanza = st.stanza("session", attr);
	if attach_ips and session.ip then
		local remote_ip, network = session.ip;
		if attach_ipv4_prefix or attach_ipv6_prefix then
			network = get_ip_network(remote_ip);
		end
		stanza:text_tag("remote-ip", network or remote_ip);
	end
	if attach_location and session.ip then
		local remote_ip = ip.new(session.ip);
		local geoip_country = ip.proto == "IPv6" and geoip6_country or geoip4_country;
		stanza:tag("location", {
			country = geoip_country:query_by_addr(remote_ip.normal);
		}):up();
	end
	if session.client_id then
		stanza:text_tag("client", session.client_id);
	end
	return stanza
end

local function audit(host, user, source, event_type, extra)
	if not host or host == "*" then
		error("cannot log audit events for global");
	end
	local user_key = user or host_wide_user;

	local attr = {
		["source"] = source,
		["type"] = event_type,
	};
	if user_key ~= host_wide_user then
		attr.user = user_key;
	end
	local stanza = st.stanza("audit-event", attr);
	if extra ~= nil then
		if extra.session then
			local child = session_extra(extra.session);
			if child then
				stanza:add_child(child);
			end
		end
		if extra.custom then
			for _, child in extra.custom do
				if not st.is_stanza(child) then
					error("all extra.custom items must be stanzas")
				end
				stanza:add_child(child);
			end
		end
	end

	local id, err = stores[host]:append(nil, nil, stanza, time_now(), user_key);
	if err then
		module:log("error", "failed to persist audit event: %s", err);
		return
	else
		module:log("debug", "persisted audit event %s as %s", stanza:top_tag(), id);
	end
end

function moduleapi.audit(module, user, event_type, extra)
	audit(module.host, user, "mod_" .. module:get_name(), event_type, extra);
end
