local bare_jid = require"util.jid".bare;
local mod_muc = module:depends("muc");

local function filter_avatar_advertisement(tag)
	if tag.attr.xmlns == "vcard-temp:x:update" then
		return nil;
	end

	return tag;
end

module:hook("presence/full", function(event)
	local stanza = event.stanza;
	local room = mod_muc.get_room_from_jid(bare_jid(stanza.attr.to));

	if not room:get_affiliation(stanza.attr.from) then
		stanza:maptags(filter_avatar_advertisement);
	end
end, 1);
