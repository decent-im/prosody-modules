local array = require "util.array";
local base64 = require "util.encodings".base64;
local ciphers = require "openssl.cipher";
local jid = require "util.jid";
local json = require "util.json";
local random = require "util.random";
local set = require "util.set";
local st = require "util.stanza";

local xmlns_jmi = "urn:xmpp:jingle-message:0";
local xmlns_jingle_apps_rtp = "urn:xmpp:jingle:apps:rtp:1";
local xmlns_push = "urn:xmpp:push:0";
local xmlns_push_encrypt = "tigase:push:encrypt:0";
local xmlns_push_encrypt_aes_128_gcm = "tigase:push:encrypt:aes-128-gcm";

-- https://xeps.tigase.net//docs/push-notifications/encrypt/#41-discovering-support
local function account_disco_info(event)
	event.reply:tag("feature", {var=xmlns_push_encrypt}):up();
	event.reply:tag("feature", {var=xmlns_push_encrypt_aes_128_gcm}):up();
end
module:hook("account-disco-info", account_disco_info);

function handle_register(event)
	local encrypt = event.stanza:get_child("enable", xmlns_push):get_child("encrypt", xmlns_push_encrypt);
	if not encrypt then return; end

	local algorithm = encrypt.attr.alg;
	if algorithm ~= "aes-128-gcm" then
		event.origin.send(st.error_reply(
			event.stanza, "modify", "feature-not-implemented", "Unknown encryption algorithm"
		));
		return false;
	end

	local key_base64 = encrypt:get_text();
	local key_binary = base64.decode(key_base64);
	if not key_binary or #key_binary ~= 16 then
		event.origin.send(st.error_reply(
			event.stanza, "modify", "bad-request", "Invalid encryption key"
		));
		return false;
	end

	event.push_info.encryption = {
		algorithm = algorithm;
		key_base64 = key_base64;
	};
end

function handle_push(event)
	local encryption = event.push_info.encryption;
	if not encryption then return; end

	if encryption.algorithm ~= "aes-128-gcm" then
		event.reason = "Unsupported encryption algorithm: "..tostring(encryption.algorithm);
		return true;
	end

	local push_summary = event.push_summary;

	local original_stanza = event.original_stanza;
	local body = original_stanza:get_child_text("body");
	if body and #body > 255 then
		body = body:sub(1, 255);
	end

	local push_payload = {
		unread = tonumber(push_summary["message-count"]) or 1;
		sender = jid.bare(original_stanza.attr.from);
		message = body;
	};

	if original_stanza.name == "message" then
		if original_stanza.attr.type == "groupchat" then
			push_payload.type = "groupchat";
			push_payload.nickname = jid.resource(original_stanza.attr.from);
		elseif original_stanza.attr.type ~= "error" then
			local jmi_propose = original_stanza:get_child("propose", xmlns_jmi);
			if jmi_propose then
				push_payload.type = "call";
				push_payload.sid = jmi_propose.attr.id;
				local media_types = set.new();
				for description in jmi_propose:childtags("description", xmlns_jingle_apps_rtp) do
					local media_type = description.attr.media;
					if media_type then
						media_types:add(media_type);
					end
				end
				push_payload.media = array.collect(media_types:items());
				push_payload.sender = original_stanza.attr.from;
			else
				push_payload.type = "chat";
			end
		end
	elseif original_stanza.name == "presence"
	and original_stanza.attr.type == "subscribe" then
		push_payload.type = "subscribe";
	end

	local iv = random.bytes(12);
	local key_binary = base64.decode(encryption.key_base64);
	local push_json = json.encode(push_payload);

	-- FIXME: luaossl does not expose the EVP_CTRL_GCM_GET_TAG API, so we append 16 NUL bytes
	-- Siskin does not validate the tag anyway.
	local encrypted_payload = base64.encode(ciphers.new("AES-128-GCM"):encrypt(key_binary, iv):final(push_json)..string.rep("\0", 16));
	local encrypted_element = st.stanza("encrypted", { xmlns = xmlns_push_encrypt, iv = base64.encode(iv) })
		:text(encrypted_payload);
	if push_payload.type == "call" then
		encrypted_element.attr.type = "voip";
		event.important = true;
	end
	-- Replace the unencrypted notification data with the encrypted one
	event.notification_payload
		:remove_children("x", "jabber:x:data")
		:add_child(encrypted_element);
end

module:hook("cloud_notify/registration", handle_register);
module:hook("cloud_notify/push", handle_push, 1);
