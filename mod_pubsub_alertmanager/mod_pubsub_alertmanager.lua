local st = require "util.stanza";
local json = require "util.json";
local uuid_generate = require "util.uuid".generate;

module:depends("http");

local pubsub_service = module:depends("pubsub").service;

local error_mapping = {
	["forbidden"] = 403;
	["item-not-found"] = 404;
	["internal-server-error"] = 500;
	["conflict"] = 409;
};

local function publish_payload(node, actor, item_id, payload)
	local post_item = st.stanza("item", { xmlns = "http://jabber.org/protocol/pubsub", id = item_id, })
		:add_child(payload);
	local ok, err = pubsub_service:publish(node, actor, item_id, post_item);
	module:log("debug", ":publish(%q, true, %q, %s) -> %q", node, item_id, payload:top_tag(), err or "");
	if not ok then
		return error_mapping[err] or 500;
	end
	return 202;
end

function handle_POST(event, path)
	local request = event.request;

	local payload = json.decode(event.request.body);
	if type(payload) ~= "table" then return 400; end
	if payload.version ~= "4" then return 501; end

	for _, alert in ipairs(payload.alerts) do
		local item = st.stanza("alerts", {xmlns = "urn:uuid:e3bec775-c607-4e9b-9a3f-94de1316d861:v4", status=alert.status});
		for k, v in pairs(alert.annotations) do
			item:text_tag("annotation", v, { name=k });
		end
		for k, v in pairs(alert.labels) do
			item:text_tag("label", v, { name=k });
		end
		item:tag("starts", { at = alert.startsAt}):up();
		if alert.endsAt then
			item:tag("ends", { at = alert.endsAt }):up();
		end
		if alert.generatorURL then
			item:tag("link", { href=alert.generatorURL }):up();
		end

		local ret = publish_payload(path, request.ip, uuid_generate(), item);
		if ret ~= 202 then
			return ret
		end
	end
	return 202;
end

module:provides("http", {
	route = {
		["POST /*"] = handle_POST;
	};
});
