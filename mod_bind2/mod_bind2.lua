local mm = require "core.modulemanager";
local sm = require "core.sessionmanager";

local xmlns_sasl2 --[[<const>]] = "urn:xmpp:sasl:1";
local xmlns_bind2 --[[<const>]] = "urn:xmpp:bind2:0";
local xmlns_carbons --[[<const>]] = "urn:xmpp:carbons:2";

module:depends("sasl2");
module:depends("carbons");

module:hook("stream-features", function(event)
	local origin, features = event.origin, event.features;
	if origin.type ~= "c2s_unauthed" then return end
	features:tag("bind", xmlns_bind2):up();
end);

module:hook_tag(xmlns_sasl2, "authenticate", function (session, auth)
	session.bind2 = auth:get_child("bind", xmlns_bind2);
end, 1);

module:hook("sasl2/c2s/success", function (event)
	local session = event.session;
	if not session.bind2 then return end

	-- When it receives a bind 2.0 on an authenticated not-yet-bound session, the
	-- server MUST:

	-- Clear the offline messages for this user, if any, without sending them (as
	-- they will be provided by MAM).
	if mm.is_loaded(module.host, "offline") then -- luacheck: ignore 542
		-- TODO
	end

	-- Perform resource binding to a random resource (see 6120)
	if not sm.bind_resource(session, nil) then
		-- FIXME How should this be handled even?
		session:close("reset");
		return true;
	end

	-- Work out which contacts have unread messages in the user's MAM archive,
	-- how many, and what the id of the last read message is
	-- XXX How do we know what the last read message was?
	-- TODO archive:summary(session.username, { after = ??? });

	-- Get the id of the newest stanza in the user's MAM archive
	-- TODO archive:find(session.username, { reverse = true, limit = 1 });

	-- Silently enable carbons for this session
	session.carbons = xmlns_carbons;

	-- After processing the bind stanza, as above, the server MUST respond with
	-- an element of type 'bound' in the namespace 'urn:xmpp:bind2:0', as in the
	-- below example
	event.success:tag("bound", xmlns_bind2):text_tag("jid", session.full_jid):up();

	session.bind2 = nil;
end);
