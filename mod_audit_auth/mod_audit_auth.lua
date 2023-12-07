local jid = require"util.jid";
local st = require "util.stanza";

module:depends("audit");
-- luacheck: read globals module.audit

local only_passwords = module:get_option_boolean("audit_auth_passwords_only", true);

module:hook("authentication-failure", function(event)
	local session = event.session;
	module:audit(jid.join(session.sasl_handler.username, module.host), "authentication-failure", {
		session = session,
	});
end)

module:hook("authentication-success", function(event)
	local session = event.session;
	if only_passwords and session.sasl_handler.fast then
		return;
	end
	module:audit(jid.join(session.sasl_handler.username, module.host), "authentication-success", {
		session = session,
	});
end)

module:hook("client_management/new-client", function (event)
	local session, client = event.session, event.client;

	local client_info = st.stanza("client", { id = client.id });

	if client.user_agent then
		local user_agent = st.stanza("user-agent", { xmlns = "urn:xmpp:sasl:2" })
		if client.user_agent.software then
			user_agent:text_tag("software", client.user_agent.software, { id = client.user_agent.software_id; version = client.user_agent.software_version });
		end
		if client.user_agent.device then
			user_agent:text_tag("device", client.user_agent.device);
		end
		if client.user_agent.uri then
			user_agent:text_tag("uri", client.user_agent.uri);
		end
		client_info:add_child(user_agent);
	end

	if client.legacy then
		client_info:text_tag("legacy");
	end

	module:audit(jid.join(session.username, module.host), "new-client", {
		session = session;
		custom = {
		};
	});
end);
