local array = require "util.array";
local it = require "util.iterators";
local jid = require "util.jid";
local sha256 = require "util.hashes".sha256;
local set = require "util.set";
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
		banned_hashes[hash] = true;
	end;

	on_retract = function (event)
		local hash = event.item.attr.id;
		if not hash then return; end
		module:log("debug", "Retracted hash: %s", hash);
		banned_hashes[hash] = nil;
	end;
});

function request_list()
	local items_request = st.iq({ to = rtbl_service_jid, from = module.host, type = "get", id = "rtbl-request" })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("items", { node = rtbl_node }):up()
		:up();

	module:send(items_request);
end

function update_list(event)
	local from_jid = event.stanza.attr.from;
	if from_jid ~= rtbl_service_jid then
		module:log("debug", "Ignoring RTBL response from unknown sender");
		return;
	end
	local items_el = event.stanza:find("{http://jabber.org/protocol/pubsub}pubsub/items");
	if not items_el then
		module:log("warn", "Invalid items response from RTBL service");
		return;
	end

	local old_entries = set.new(array.collect(it.keys(banned_hashes)));

	local n_added, n_removed, n_total = 0, 0, 0;
	for item in items_el:childtags("item") do
		local hash = item.attr.id;
		if hash then
			n_total = n_total + 1;
			if not old_entries:contains(hash) then
				-- New entry
				n_added = n_added + 1;
				banned_hashes[hash] = true;
			else
				-- Entry already existed
				old_entries:remove(hash);
			end
		end
	end

	-- Remove old entries that weren't in the received list
	for hash in old_entries do
		n_removed = n_removed + 1;
		banned_hashes[hash] = nil;
	end

	module:log("info", "%d RTBL entries received from %s (%d added, %d removed)", n_total, from_jid, n_added, n_removed);
	return true;
end

module:hook("iq-result/host/rtbl-request", update_list);

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

if prosody.start_time then
	request_list();
else
	module:hook("server-started", request_list);
end
