local jid = require "util.jid";
local sha256 = require "util.hashes".sha256;
local st = require "util.stanza";

local rtbl_service_jid = assert(module:get_option_string("muc_rtbl_jid"), "No RTBL JID supplied");
local rtbl_node = module:get_option_string("muc_rtbl_node", "muc_bans_sha256");

local banned_hashes = module:shared("banned_hashes");

module:depends("pubsub_subscription");

module:add_item("pubsub-subscription", {
	service = rtbl_service_jid;
	node = rtbl_node;

	-- Callbacks:
	on_subscribed = function()
		module:log("info", "RTBL active");
	end;

	on_error = function(err)
		module:log("error", "Failed to subscribe to RTBL: %s::%s:  %s", err.type, err.condition, err.text);
	end;

	on_item = function(event)
		local hash = event.item.attr.id;
		if not hash then return; end
		module:log("debug", "Received new hash: %s", hash);
		banned_hashes[hash] = hash;
	end;

	on_retract = function (event)
		local hash = event.item.attr.id;
		if not hash then return; end
		module:log("debug", "Retracted hash: %s", hash);
		banned_hashes[hash] = nil;
	end;
});

module:hook("muc-occupant-pre-join", function (event)
	local from_bare = jid.bare(event.stanza.attr.from);
	local hash = sha256(jid.bare(event.stanza.attr.from), true);
	if banned_hashes[hash] then
		module:log("info", "Blocked user <%s> from room <%s> due to RTBL match", from_bare, event.stanza.attr.to);
		local error_reply = st.error_reply(event.stanza, "cancel", "forbidden", "You are banned from this service", event.room.jid);
		event.origin.send(error_reply);
		return true;
	end
end);
