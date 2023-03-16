local http = require "net.http";
local async = require "util.async";
local json = require "util.json";
local sasl = require "util.sasl";

-- TODO -- local issuer_identity = module:get_option_string("oauth_external_issuer");
local oidc_discovery_url = module:get_option_string("oauth_external_discovery_url")
local validation_endpoint = module:get_option_string("oauth_external_validation_endpoint");

local username_field = module:get_option_string("oauth_external_username_field", "preferred_username");

-- XXX Hold up, does whatever done here even need any of these things? Are we
-- the OAuth client? Is the XMPP client the OAuth client? What are we???
-- TODO -- local client_id = module:get_option_string("oauth_external_client_id");
-- TODO -- local client_secret = module:get_option_string("oauth_external_client_secret");

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
	function profile:oauthbearer(token)
		if token == "" then
			return false, nil, extra;
		end

		local ret, err = async.wait_for(self.profile.http_client:request(validation_endpoint,
			{ headers = { ["Authorization"] = "Bearer " .. token; ["Accept"] = "application/json" } }));
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
	return sasl.new(host, profile);
end

module:provides("auth", provider);
