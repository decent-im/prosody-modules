local st = require "util.stanza";
local jid = require "util.jid";

local bots = module:get_option_set("known_bots", {});

module:hook("muc-occupant-groupchat", function(event)
	if event.occupant then return end -- skip messages from actual occupants
	local room = event.room;

	if bots:contains(jid.bare(event.from)) or bots:contains(jid.host(event.from)) then

		local nick = room:get_registered_nick(jid);

		if not nick then
			-- Allow bot to specify its own nick, but we're appending '[bot]' to it.
			-- FIXME HATS!!!
			nick = event.stanza:get_child_text("nick", "http://jabber.org/protocol/nick");
			nick = (nick or jid.bare(event.from)) .. "[bot]";
		end

		local virtual_occupant_jid = jid.prep(room.jid .. "/" .. nick, true);
		if not virtual_occupant_jid then
			module:send(st.error_reply(event.stanza, "modify", "jid-malformed", "Nickname must pass strict validation", room.jid));
			return true;
		end

		-- Inject virtual occupant to trick all the other hooks on this event that
		-- this is an actual legitimate participant.
		-- XXX Hack!
		event.occupant = {
			nick = virtual_occupant_jid;
			bare_jid = jid.bare(event.from);
			role = "participant";
		};

	end
end, 66);

module:hook("muc-occupant-pre-join", function(event)
	local room = event.room;
	local nick = jid.resource(event.occupant.nick);
	if nick:sub(-5, -1) == "[bot]" then
		event.origin.send(st.error_reply(event.stanza, "modify", "policy-violation", "Only known bots may use the [bot] suffix", room.jid));
		return true;
	end
end, 3);

module:hook("muc-occupant-pre-change", function(event)
	local room = event.room;
	local nick = jid.resource(event.dest_occupant.nick);
	if nick:sub(-5, -1) == "[bot]" then
		event.origin.send(st.error_reply(event.stanza, "modify", "policy-violation", "Only known bots may use the [bot] suffix", room.jid));
		return true;
	end
end, 3);

assert(string.sub("foo[bot]", -5, -1) == "[bot]", "substring indicies, how do they work?");
