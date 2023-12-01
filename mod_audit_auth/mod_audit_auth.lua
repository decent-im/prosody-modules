local jid = require"util.jid";

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
