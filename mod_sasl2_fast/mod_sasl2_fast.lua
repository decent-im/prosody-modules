local tokenauth = module:depends("tokenauth");
local sasl = require "util.sasl";
local dt = require "util.datetime";
local st = require "util.stanza";

local fast_token_ttl = module:get_option_number("sasl2_fast_token_ttl", 86400*21);

local xmlns_fast = "urn:xmpp:fast:0";
local xmlns_sasl2 = "urn:xmpp:sasl:2";

function get_sasl_handler(session) --luacheck: ignore session
	local token_auth_profile = {
		token_test = function (_, client_id, token, mech_name, counter) --luacheck: ignore
			return false; -- FIXME
		end;
	};
	return sasl.new(module.host, token_auth_profile);
end

-- Advertise FAST to connecting clients
module:hook("advertise-sasl-features", function (event)
	local sasl_handler = get_sasl_handler(event.session);
	if not sasl_handler then return; end
	event.session.fast_sasl_handler = sasl_handler;
	local fast = st.stanza("fast", { xmlns = xmlns_fast });
	for mech in sasl_handler:mechanisms() do
		fast:text_tag("mechanism", mech);
	end
	event.features:add_child(fast);
end);

-- Process any FAST elements in <authenticate/>
module:hook_tag(xmlns_sasl2, "authenticate", function (session, auth)
	-- Cache action for future processing (after auth success)
	local fast_auth = auth:get_child(xmlns_fast, "fast");
	if fast_auth then
		-- Client says it is using FAST auth, so set our SASL handler
		session.log("debug", "Client is authenticating using FAST");
		session.sasl_handler = session.fast_sasl_handler;
	end
	session.fast_sasl_handler = nil;
	local fast_token_request = auth:get_child(xmlns_fast, "request-token");
	if fast_token_request then
		local mech = fast_token_request.attr.mechanism;
		session.log("debug", "Client requested new FAST token for %s", mech);
		session.fast_token_request = {
			mechanism = mech;
		};
	end
end, 100);

-- Process post-success (new token generation, etc.)
module:hook("sasl2/c2s/success", function (event)
	local session = event.session;

	local token_request = session.fast_token_request;
	if token_request then
		local token, token_info = tokenauth.create_jid_token(
			session.full_jid,
			session.full_jid,
			session.role,
			fast_token_ttl,
			{
				fast_token = true;
				fast_mechanism = token_request.mechanism;
			}
		);
		if token then
			event.success:tag("token", {
				xmlns = xmlns_fast;
				expiry = dt.datetime(token_info.expiry);
				token = token;
			}):up();
		end
	end
end, 75);


-- X-PLAIN-TOKEN mechanism

local function x_plain_token(self, message) --luacheck: ignore 212/self
	if not message then
		return nil, "malformed-request";
	end
	return nil, "temporary-auth-failure"; -- FIXME
end

sasl.registerMechanism("X-PLAIN-TOKEN", { "token_test" }, x_plain_token);
