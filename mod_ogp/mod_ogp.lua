local mod_muc = module:depends("muc")
local http = require "net.http"
local st = require "util.stanza"

local ogp_pattern = [[<meta property=["'](og:.-)["'] content=["'](.-)["'].->]]
local ogp_pattern2 = [[<meta content=["'](.-)["'] property=["'](og:.-)["'].->]]
local url_pattern = [[https?://%S+]]

local function ogp_handler(event)
	local room, stanza = event.room, st.clone(event.stanza)
	local body = stanza:get_child_text("body")
	if not body then return; end

	local url = body:match(url_pattern)
	if not url then return; end

	local origin_id = stanza:find("{urn:xmpp:sid:0}origin-id@id")
	if not origin_id then return; end

	http.request(
		url,
		nil,
		function(response_body, response_code, _)
			if response_code ~= 200 then
				return
			end

			local to = room.jid
			local from = room and room.jid or module.host
			local fastening = st.message({to = to, from = from}):tag("apply-to", {xmlns = "urn:xmpp:fasten:0", id = origin_id})
			local found_metadata = false
			local message_body = ""
			for property, content in response_body:gmatch(ogp_pattern) do
				module:log("info", property .. "\t" .. content)
				fastening:tag(
					"meta",
					{
						xmlns = "http://www.w3.org/1999/xhtml",
						property = property,
						content = content
					}
				):up()
				found_metadata = true
				message_body = message_body .. property .. "\t" .. content .. "\n"
			end
			for content, property in response_body:gmatch(ogp_pattern2) do
				module:log("info", property .. "\t" .. content)
				fastening:tag(
					"meta",
					{
						xmlns = "http://www.w3.org/1999/xhtml",
						property = property,
						content = content
					}
				):up()
				found_metadata = true
				message_body = message_body .. property .. "\t" .. content .. "\n"
			end

			if found_metadata then
				mod_muc.get_room_from_jid(room.jid):broadcast_message(fastening)
			end
			module:log("info", tostring(fastening))
		end
	)
end

module:hook("muc-occupant-groupchat", ogp_handler)
