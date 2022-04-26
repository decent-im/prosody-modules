module:depends("audit");
-- luacheck: read globals module.audit

local st = require "util.stanza";

module:hook("user-registered", function(event)
	local session = event.session;
	local custom = {};
	local invite = event.validated_invite or (event.session and event.session.validated_invite);
	if invite then
		table.insert(custom, st.stanza(
			"invite-used",
			{
				xmlns = "xmpp:prosody.im/audit",
				token = invite.token,
			}
		))
	end
	module:audit(event.username, "user-registered", {
		session = session,
		custom = custom,
	});
end);
