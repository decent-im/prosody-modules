local sasl = require "util.sasl";
local dt = require "util.datetime";
local id = require "util.id";
local jid = require "util.jid";
local st = require "util.stanza";
local now = require "util.time".now;
local hash = require "util.hashes";

local fast_token_ttl = module:get_option_number("sasl2_fast_token_ttl", 86400*21);

local xmlns_fast = "urn:xmpp:fast:0";
local xmlns_sasl2 = "urn:xmpp:sasl:2";

local token_store = module:open_store("fast_tokens", "map");

local function make_token(username, client_id, mechanism)
	local new_token = "secret-token:fast-"..id.long();
	local key = hash.sha256(client_id, true).."-new";
	local issued_at = now();
	token_store:set(username, key, {
		mechanism = mechanism;
		secret = new_token;
		issued_at = issued_at;
		expires_at = issued_at + fast_token_ttl;
	});
end

local function new_token_tester(username, hmac_f)
	return function (mechanism, client_id, token_hash, cb_data)
		local tried_current_token = false;
		local key = hash.sha256(client_id, true).."-new";
		local token;
		repeat
			token = token_store:get(username, key);
			if token and token.mechanism == mechanism then
				local expected_hash = hmac_f(token.secret, "Initiator"..cb_data);
				if hash.equals(expected_hash, token_hash) then
					if token.expires_at < now() then
						token_store:set(username, key, nil);
						return nil, "credentials-expired";
					end
					if not tried_current_token then
						-- The new token is becoming the current token
						token_store:set_keys(username, {
							[key] = token_store.remove;
							[key:sub(1, -4).."-cur"] = token;
						});
					end
					return true, username, hmac_f(token.secret, "Responder"..cb_data);
				end
			end
			if not tried_current_token then
				-- Try again with the current token instead
				tried_current_token = true;
				key = key:sub(1, -4).."-cur";
			else
				return nil;
			end
		until false;
	end
end

function get_sasl_handler(username)
	local token_auth_profile = {
		ht_sha_256 = new_token_tester(username, hash.hmac_sha256);
		token_test = function (_, client_id, token, mech_name, counter) --luacheck: ignore
			return false; -- FIXME
		end;
	};
	return sasl.new(module.host, token_auth_profile);
end

-- Advertise FAST to connecting clients
module:hook("advertise-sasl-features", function (event)
	local session = event.origin;
	local username = session.username;
	if not username then
		username = jid.node(event.stream.from);
		if not username then return; end
	end
	local sasl_handler = get_sasl_handler(username);
	if not sasl_handler then return; end
	session.fast_sasl_handler = sasl_handler;
	local fast = st.stanza("fast", { xmlns = xmlns_fast });
	for mech in pairs(sasl_handler:mechanisms()) do
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
		local fast_sasl_handler = session.fast_sasl_handler;
		if fast_sasl_handler then
			session.log("debug", "Client is authenticating using FAST");
			fast_sasl_handler.profile._client_id = session.client_id;
			session.sasl_handler = fast_sasl_handler;
		else
			session.log("warn", "Client asked to auth via FAST, but no SASL handler available");
			local failure = st.stanza("failure", { xmlns = xmlns_sasl2 })
				:tag("malformed-request"):up()
				:text_tag("text", "FAST is not available on this stream");
			session.send(failure);
			return true;
		end
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
	local client_id = session.client_id;
	if token_request then
		if not client_id then
			session.log("warn", "FAST token requested, but missing client id");
			return;
		end
		local token_info = make_token(session.username, client_id, token_request.mechanism)
		if token_info then
			event.success:tag("token", {
				xmlns = xmlns_fast;
				expiry = dt.datetime(token_info.expires_at);
				token = token_info.token;
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


-- HT-* mechanisms

local function new_ht_mechanism(mechanism_name, backend_profile_name, cb_name)
	return function (sasl_handler, message)
		local backend = sasl_handler.profile[backend_profile_name];
		local ok, status, response = backend(mechanism_name, sasl_handler._client_id, message, cb_name and sasl_handler.profile.cb[cb_name] or "");
		if not ok then
			return "failure", status or "not-authorized";
		end
		return "success", response;
	end
end

local function register_ht_mechanism(name, backend_profile_name, cb_name)
	return sasl.registerMechanism(name, { backend_profile_name }, new_ht_mechanism(
		name,
		backend_profile_name,
		cb_name
	));
end

register_ht_mechanism("HT-SHA-256-NONE", "ht_sha_256", nil);
register_ht_mechanism("HT-SHA-256-UNIQ", "ht_sha_256", "tls-unique");
register_ht_mechanism("HT-SHA-256-ENDP", "ht_sha_256", "tls-endpoint");
register_ht_mechanism("HT-SHA-256-EXPR", "ht_sha_256", "tls-exporter");
