local unified_push_secret = assert(module:get_option_string("unified_push_secret"), "required option: unified_push_secret");
local push_registration_ttl = module:get_option_number("unified_push_registration_ttl", 86400);

local base64 = require "util.encodings".base64;
local datetime = require "util.datetime";
local id = require "util.id";
local jwt_sign, jwt_verify = require "util.jwt".init("HS256", unified_push_secret);
local st = require "util.stanza";
local urlencode = require "util.http".urlencode;

local xmlns_up = "http://gultsch.de/xmpp/drafts/unified-push";

module:depends("http");
module:depends("disco");

module:add_feature(xmlns_up);

local function check_sha256(s)
	if not s then return nil, "no value provided"; end
	local d = base64.decode(s);
	if not d then return nil, "invalid base64"; end
	if #d ~= 32 then return nil, "incorrect decoded length, expected 32"; end
	return s;
end

-- Handle incoming registration from XMPP client
function handle_register(event)
	local origin, stanza = event.origin, event.stanza;
	local instance, instance_err = check_sha256(stanza.tags[1].attr.instance);
	if not instance then
		return st.error_reply(stanza, "modify", "bad-request", "instance: "..instance_err);
	end
	local application, application_err = check_sha256(stanza.tags[1].attr.application);
	if not application then
		return st.error_reply(stanza, "modify", "bad-request", "application: "..application_err);
	end
	local expiry = os.time() + push_registration_ttl;
	local url = module:http_url("push").."/"..urlencode(jwt_sign({
		instance = instance;
		application = application;
		sub = stanza.attr.from;
		exp = expiry;
	}));
	module:log("debug", "New push registration successful");
	return origin.send(st.reply(stanza):tag("registered", {
		expiration = datetime.datetime(expiry);
		endpoint = url;
		xmlns = xmlns_up;
	}));
end

module:hook("iq-set/host/"..xmlns_up..":register", handle_register);

-- Handle incoming POST
function handle_push(event, subpath)
	module:log("debug", "Incoming push received!");
	local ok, data = jwt_verify(subpath);
	if not ok then
		module:log("debug", "Received push to unacceptable token (%s)", data);
		return 404;
	end
	local payload = event.request.body;
	if not payload or payload == "" then
		module:log("warn", "Missing or empty push payload");
		return 400;
	elseif #payload > 4096 then
		module:log("warn", "Push payload too large");
		return 413;
	end
	local push_id = event.request.id or id.short();
	module:log("debug", "Push notification received [%s], relaying to device...", push_id);
	local push_iq = st.iq({ type = "set", to = data.sub, from = module.host, id = push_id })
		:text_tag("push", base64.encode(payload), { instance = data.instance, application = data.application, xmlns = xmlns_up });
	return module:send_iq(push_iq):next(function ()
		module:log("debug", "Push notification delivered [%s]", push_id);
		return 201;
	end, function (error_event)
		local e_type, e_cond, e_text = error_event.stanza:get_error();
		if e_cond == "item-not-found" or e_cond == "feature-not-implemented" then
			module:log("debug", "Push rejected [%s]", push_id);
			return 404;
		elseif e_cond == "service-unavailable" or e_cond == "recipient-unavailable" then
			module:log("debug", "Recipient temporarily unavailable [%s]", push_id);
			return 503;
		end
		module:log("warn", "Unexpected push error response: %s/%s/%s", e_type, e_cond, e_text);
		return 500;
	end);
end

module:provides("http", {
	name = "push";
	route = {
		["GET /*"] = function (event)
			event.response.headers.content_type = "application/json";
			return [[{"unifiedpush":{"version":1}}]];
		end;
		["POST /*"] = handle_push;
	};
});
