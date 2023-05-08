local http = require "net.http";
local async = require "util.async";
local jid = require "util.jid";
local json = require "util.json";
local sasl = require "util.sasl";

local issuer_identity = module:get_option_string("oauth_external_issuer");
local oidc_discovery_url = module:get_option_string("oauth_external_discovery_url",
	issuer_identity and issuer_identity .. "/.well-known/oauth-authorization-server" or nil);
local validation_endpoint = module:get_option_string("oauth_external_validation_endpoint");
local token_endpoint = module:get_option_string("oauth_external_token_endpoint");

local username_field = module:get_option_string("oauth_external_username_field", "preferred_username");
local allow_plain = module:get_option_boolean("oauth_external_resource_owner_password", true);

-- XXX Hold up, does whatever done here even need any of these things? Are we
-- the OAuth client? Is the XMPP client the OAuth client? What are we???
local client_id = module:get_option_string("oauth_external_client_id");
local client_secret = module:get_option_string("oauth_external_client_secret");

--[[ More or less required endpoints
digraph "oauth endpoints" {
issuer -> discovery -> { registration validation }
registration -> { client_id client_secret }
{ client_id client_secret validation } -> required
}
--]]

local host = module.host;
local provider = {};

function provider.get_sasl_handler()
	local profile = {};
	profile.http_client = http.default; -- TODO configurable
	local extra = { oidc_discovery_url = oidc_discovery_url };
	if token_endpoint and allow_plain then
		local map_username = function (username, _realm) return username; end; --jid.join; -- TODO configurable
		function profile:plain_test(username, password, realm)
			local tok, err = async.wait_for(self.profile.http_client:request(token_endpoint, {
				headers = { ["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"; ["Accept"] = "application/json" };
				body = http.formencode({
					grant_type = "password";
					client_id = client_id;
					client_secret = client_secret;
					username = map_username(username, realm);
					password = password;
					scope = "openid";
				});
			}))
			if err or not (tok.code >= 200 and tok.code < 300) then
				return false, nil;
			end
			local token_resp = json.decode(tok.body);
			if not token_resp or string.lower(token_resp.token_type or "") ~= "bearer" then
				return false, nil;
			end
			if not validation_endpoint then
				-- We're not going to get more info, only the username
				self.username = jid.escape(username);
				self.token_info = token_resp;
				return true, true;
			end
			local ret, err = async.wait_for(self.profile.http_client:request(validation_endpoint,
				{ headers = { ["Authorization"] = "Bearer " .. token_resp.access_token; ["Accept"] = "application/json" } }));
			if err then
				return false, nil;
			end
			if not (ret.code >= 200 and ret.code < 300) then
				return false, nil;
			end
			local response = json.decode(ret.body);
			if type(response) ~= "table" or (response[username_field]) ~= username then
				return false, nil, nil;
			end
			if response.jid then
				self.username, self.realm, self.resource = jid.prepped_split(response.jid, true);
			end
			self.role = response.role;
			self.token_info = response;
			return true, true;
		end
	end
	if validation_endpoint then
		function profile:oauthbearer(token)
			if token == "" then
				return false, nil, extra;
			end

			local ret, err = async.wait_for(self.profile.http_client:request(validation_endpoint, {
				headers = { ["Authorization"] = "Bearer " .. token; ["Accept"] = "application/json" };
			}));
			if err then
				return false, nil, extra;
			end
			local response = ret and json.decode(ret.body);
			if not (ret.code >= 200 and ret.code < 300) then
				return false, nil, response or extra;
			end
			if type(response) ~= "table" or type(response[username_field]) ~= "string" then
				return false, nil, nil;
			end

			return response[username_field], true, response;
		end
	end
	return sasl.new(host, profile);
end

module:provides("auth", provider);
