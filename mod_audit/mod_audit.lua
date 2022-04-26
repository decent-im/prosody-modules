module:set_global();

local time_now = os.time;
local st = require "util.stanza";

local host_wide_user = "@";

local stores = {};

local function get_store(self, host)
	local store = rawget(self, host);
	if store then
		return store
	end
	local store = module:context(host):open_store("audit", "archive");
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
	local user = user or host_wide_user;

	local attr = {
		["source"] = source,
		["type"] = event_type,
	};
	if user ~= host_wide_user then
		attr.user = user;
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

	local id, err = stores[host]:append(nil, nil, stanza, time_now(), user);
	if err then
		module:log("error", "failed to persist audit event: %s", err);
		return
	else
		module:log("debug", "persisted audit event %s as %s", stanza:top_tag(), id);
	end
end

local module_api = getmetatable(module).__index;

function module_api:audit(user, event_type, extra)
	audit(self.host, user, "mod_" .. self:get_name(), event_type, extra);
end

module:hook("audit", audit, 0);
