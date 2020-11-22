local hashes = require "util.hashes";
local http = require "util.http";
local jid = require "util.jid";
local json = require "util.json";
local usermanager = require "core.usermanager";
local errors = require "util.error";
local url = require "socket.url";
local uuid = require "util.uuid";
local encodings = require "util.encodings";
local base64 = encodings.base64;

local tokens = module:depends("tokenauth");

local clients = module:open_store("oauth2_clients", "map");
local codes = module:open_store("oauth2_codes", "map");

local function oauth_error(err_name, err_desc)
	return errors.new({
		type = "modify";
		condition = "bad-request";
		code = err_name == "invalid_client" and 401 or 400;
		text = err_desc and (err_name..": "..err_desc) or err_name;
		context = { oauth2_response = { error = err_name, error_description = err_desc } };
	});
end

local function new_access_token(token_jid, scope, ttl)
	local token = tokens.create_jid_token(token_jid, token_jid, scope, ttl);
	return {
		token_type = "bearer";
		access_token = token;
		expires_in = ttl;
		-- TODO: include refresh_token when implemented
	};
end

local grant_type_handlers = {};
local response_type_handlers = {};

function grant_type_handlers.password(params)
	local request_jid = assert(params.username, oauth_error("invalid_request", "missing 'username' (JID)"));
	local request_password = assert(params.password, oauth_error("invalid_request", "missing 'password'"));
	local request_username, request_host, request_resource = jid.prepped_split(request_jid);
	if params.scope and params.scope ~= "" then
		return oauth_error("invalid_scope", "unknown scope requested");
	end
	if not (request_username and request_host) or request_host ~= module.host then
		return oauth_error("invalid_request", "invalid JID");
	end
	if usermanager.test_password(request_username, request_host, request_password) then
		local granted_jid = jid.join(request_username, request_host, request_resource);
		return json.encode(new_access_token(granted_jid, nil, nil));
	end
	return oauth_error("invalid_grant", "incorrect credentials");
end

function response_type_handlers.code(params, granted_jid)
	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end
	if not params.redirect_uri then return oauth_error("invalid_request", "missing 'redirect_uri'"); end
	if params.scope and params.scope ~= "" then
		return oauth_error("invalid_scope", "unknown scope requested");
	end

	local client_owner, client_host, client_id = jid.prepped_split(params.client_id);
	if client_host ~= module.host then
		return oauth_error("invalid_client", "incorrect credentials");
	end
	local client, err = clients:get(client_owner, client_id);
	if err then error(err); end
	if not client then
		return oauth_error("invalid_client", "incorrect credentials");
	end

	local code = uuid.generate();
	assert(codes:set(client_owner, client_id .. "#" .. code, {issued = os.time(); granted_jid = granted_jid}));

	local redirect = url.parse(params.redirect_uri);
	local query = http.formdecode(redirect.query or "");
	if type(query) ~= "table" then query = {}; end
	table.insert(query, { name = "code", value = code })
	if params.state then
		table.insert(query, { name = "state", value = params.state });
	end
	redirect.query = http.formencode(query);

	return {
		status_code = 302;
		headers = {
			location = url.build(redirect);
		};
	}
end

local pepper = module:get_option_string("oauth2_client_pepper", "");

local function verify_secret(stored, salt, i, secret)
	return base64.decode(stored) == hashes.pbkdf2_hmac_sha256(secret, salt .. pepper, i);
end

function grant_type_handlers.authorization_code(params)
	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end
	if not params.client_secret then return oauth_error("invalid_request", "missing 'client_secret'"); end
	if not params.code then return oauth_error("invalid_request", "missing 'code'"); end
	if params.scope and params.scope ~= "" then
		return oauth_error("invalid_scope", "unknown scope requested");
	end

	local client_owner, client_host, client_id = jid.prepped_split(params.client_id);
	if client_host ~= module.host then
		module:log("debug", "%q ~= %q", client_host, module.host);
		return oauth_error("invalid_client", "incorrect credentials");
	end
	local client, err = clients:get(client_owner, client_id);
	if err then error(err); end
	if not client or not verify_secret(client.secret_hash, client.salt, client.iteration_count, params.client_secret) then
		module:log("debug", "client_secret mismatch");
		return oauth_error("invalid_client", "incorrect credentials");
	end
	local code, err = codes:get(client_owner, client_id .. "#" .. params.code);
	if err then error(err); end
	if not code or type(code) ~= "table" or os.difftime(os.time(), code.issued) > 900 then
		module:log("debug", "authorization_code invalid or expired: %q", code);
		return oauth_error("invalid_client", "incorrect credentials");
	end
	assert(codes:set(client_owner, client_id .. "#" .. params.code, nil));

	return json.encode(new_access_token(code.granted_jid, nil, nil));
end

local function check_credentials(request)
	local auth_type, auth_data = string.match(request.headers.authorization, "^(%S+)%s(.+)$");

	if auth_type == "Basic" then
		local creds = base64.decode(auth_data);
		if not creds then return false; end
		local username, password = string.match(creds, "^([^:]+):(.*)$");
		if not username then return false; end
		username, password = encodings.stringprep.nodeprep(username), encodings.stringprep.saslprep(password);
		if not username then return false; end
		if not usermanager.test_password(username, module.host, password) then
			return false;
		end
		return username;
	end
	return nil;
end

if module:get_host_type() == "component" then
	local component_secret = assert(module:get_option_string("component_secret"), "'component_secret' is a required setting when loaded on a Component");

	function grant_type_handlers.password(params)
		local request_jid = assert(params.username, oauth_error("invalid_request", "missing 'username' (JID)"));
		local request_password = assert(params.password, oauth_error("invalid_request", "missing 'password'"));
		local request_username, request_host, request_resource = jid.prepped_split(request_jid);
		if params.scope then
			return oauth_error("invalid_scope", "unknown scope requested");
		end
		if not request_host or request_host ~= module.host then
			return oauth_error("invalid_request", "invalid JID");
		end
		if request_password == component_secret then
			local granted_jid = jid.join(request_username, request_host, request_resource);
			return json.encode(new_access_token(granted_jid, nil, nil));
		end
		return oauth_error("invalid_grant", "incorrect credentials");
	end

	-- TODO How would this make sense with components?
	-- Have an admin authenticate maybe?
	response_type_handlers.code = nil;
	grant_type_handlers.authorization_code = nil;
	check_credentials = function () return false end
end

function handle_token_grant(event)
	event.response.headers.content_type = "application/json";
	local params = http.formdecode(event.request.body);
	if not params then
		return oauth_error("invalid_request");
	end
	local grant_type = params.grant_type
	local grant_handler = grant_type_handlers[grant_type];
	if not grant_handler then
		return oauth_error("unsupported_grant_type");
	end
	return grant_handler(params);
end

local function handle_authorization_request(event)
	local request, response = event.request, event.response;
	if not request.headers.authorization then
		response.headers.www_authenticate = string.format("Basic realm=%q", module.host.."/"..module.name);
		return 401;
	end
	local user = check_credentials(request);
	if not user then
		return 401;
	end
	if not request.url.query then
		response.headers.content_type = "application/json";
		return oauth_error("invalid_request");
	end
	local params = http.formdecode(request.url.query);
	if not params then
		return oauth_error("invalid_request");
	end
	local response_type = params.response_type;
	local response_handler = response_type_handlers[response_type];
	if not response_handler then
		response.headers.content_type = "application/json";
		return oauth_error("unsupported_response_type");
	end
	return response_handler(params, jid.join(user, module.host));
end

module:depends("http");
module:provides("http", {
	route = {
		["POST /token"] = handle_token_grant;
		["GET /authorize"] = handle_authorization_request;
	};
});

local http_server = require "net.http.server";

module:hook_object_event(http_server, "http-error", function (event)
	local oauth2_response = event.error and event.error.context and event.error.context.oauth2_response;
	if not oauth2_response then
		return;
	end
	event.response.headers.content_type = "application/json";
	event.response.status_code = event.error.code or 400;
	return json.encode(oauth2_response);
end, 5);
