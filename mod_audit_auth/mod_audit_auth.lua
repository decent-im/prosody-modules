local jid = require"util.jid";

module:depends("audit");
-- luacheck: read globals module.audit

module:hook("authentication-failure", function(event)
	local session = event.session;
	module:audit(jid.join(session.sasl_handler.username, module.host), "authentication-failure", {
		session = session,
	});
end)

module:hook("authentication-success", function(event)
	local session = event.session;
	module:audit(jid.join(session.sasl_handler.username, module.host), "authentication-success", {
		session = session,
	});
end)
