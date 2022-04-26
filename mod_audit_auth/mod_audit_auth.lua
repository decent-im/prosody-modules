module:depends("audit");

module:hook("authentication-failure", function(event)
	local session = event.session;
	module:audit(session.sasl_handler.username, "authentication-failure", {
		session = session,
	});
end)

module:hook("authentication-success", function(event)
	local session = event.session;
	module:audit(session.sasl_handler.username, "authentication-success", {
		session = session,
	});
end)
