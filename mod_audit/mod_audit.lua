module:set_global();

local audit_log_limit = module:get_option_number("audit_log_limit", 10000);
local cleanup_after = module:get_option_string("audit_log_expires_after", "2w");

local time_now = os.time;
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
	if session.ip then
		stanza:text_tag("remote-ip", session.ip);
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
