local hashes = require "util.hashes";
local cache = require "util.cache";
local http = require "util.http";
local jid = require "util.jid";
local json = require "util.json";
local usermanager = require "core.usermanager";
local errors = require "util.error";
local url = require "socket.url";
local id = require "util.id";
local encodings = require "util.encodings";
local base64 = encodings.base64;
local random = require "util.random";
local schema = require "util.jsonschema";
local set = require "util.set";
local jwt = require"util.jwt";
local it = require "util.iterators";
local array = require "util.array";
local st = require "util.stanza";

local function read_file(base_path, fn, required)
	local f, err = io.open(base_path .. "/" .. fn);
	if not f then
		module:log(required and "error" or "debug", "Unable to load template file: %s", err);
		if required then
			return error("Failed to load templates");
		end
		return nil;
	end
	local data = assert(f:read("*a"));
	assert(f:close());
	return data;
end

local template_path = module:get_option_path("oauth2_template_path", "html");
local templates = {
	login = read_file(template_path, "login.html", true);
	consent = read_file(template_path, "consent.html", true);
	error = read_file(template_path, "error.html", true);
	css = read_file(template_path, "style.css");
	js = read_file(template_path, "script.js");
};

local site_name = module:get_option_string("site_name", module.host);

local _render_html = require"util.interpolation".new("%b{}", st.xml_escape);
local function render_page(template, data, sensitive)
	data = data or {};
	data.site_name = site_name;
	local resp = {
		status_code = 200;
		headers = {
			["Content-Type"] = "text/html; charset=utf-8";
			["Content-Security-Policy"] = "default-src 'self'";
			["X-Frame-Options"] = "DENY";
			["Cache-Control"] = (sensitive and "no-store" or "no-cache")..", private";
		};
		body = _render_html(template, data);
	};
	return resp;
end

local tokens = module:depends("tokenauth");

local default_access_ttl = module:get_option_number("oauth2_access_token_ttl", 86400);
local default_refresh_ttl = module:get_option_number("oauth2_refresh_token_ttl", nil);

-- Used to derive client_secret from client_id, set to enable stateless dynamic registration.
local registration_key = module:get_option_string("oauth2_registration_key");
local registration_algo = module:get_option_string("oauth2_registration_algorithm", "HS256");
local registration_options = module:get_option("oauth2_registration_options", { default_ttl = 60 * 60 * 24 * 90 });

local verification_key;
local jwt_sign, jwt_verify;
if registration_key then
	-- Tie it to the host if global
	verification_key = hashes.hmac_sha256(registration_key, module.host);
	jwt_sign, jwt_verify = jwt.init(registration_algo, registration_key, registration_key, registration_options);
end

local function parse_scopes(scope_string)
	return array(scope_string:gmatch("%S+"));
end

local openid_claims = set.new({ "openid", "profile"; "email"; "address"; "phone" });

local function filter_scopes(username, requested_scope_string)
	local selected_role, granted_scopes = nil, array();

	if requested_scope_string then -- Specific role(s) requested
		local requested_scopes = parse_scopes(requested_scope_string);
		for _, scope in ipairs(requested_scopes) do
			if openid_claims:contains(scope) then
				granted_scopes:push(scope);
			end
			if selected_role == nil and usermanager.user_can_assume_role(username, module.host, scope) then
				selected_role = scope;
			end
		end
	end

	if not selected_role then
		-- By default use the users' default role
		selected_role = usermanager.get_user_role(username, module.host).name;
	end
	granted_scopes:push(selected_role);

	return granted_scopes:concat(" "), selected_role;
end

local function code_expires_in(code) --> number, seconds until code expires
	return os.difftime(code.expires, os.time());
end

local function code_expired(code) --> boolean, true: has expired, false: still valid
	return code_expires_in(code) < 0;
end

local codes = cache.new(10000, function (_, code)
	return code_expired(code)
end);

-- Periodically clear out unredeemed codes.  Does not need to be exact, expired
-- codes are rejected if tried. Mostly just to keep memory usage in check.
module:hourly("Clear expired authorization codes", function()
	local k, code = codes:tail();
	while code and code_expired(code) do
		codes:set(k, nil);
		k, code = codes:tail();
	end
end)

local function get_issuer()
	return (module:http_url(nil, "/"):gsub("/$", ""));
end

local loopbacks = set.new({ "localhost", "127.0.0.1", "::1" });
local function is_secure_redirect(uri)
	local u = url.parse(uri);
	return u.scheme ~= "http" or loopbacks:contains(u.host);
end

local function oauth_error(err_name, err_desc)
	return errors.new({
		type = "modify";
		condition = "bad-request";
		code = err_name == "invalid_client" and 401 or 400;
		text = err_desc and (err_name..": "..err_desc) or err_name;
		extra = { oauth2_response = { error = err_name, error_description = err_desc } };
	});
end

-- client_id / client_metadata are pretty large, filter out a subset of
-- properties that are deemed useful e.g. in case tokens issued to a certain
-- client needs to be revoked
local function client_subset(client)
	return { name = client.client_name; uri = client.client_uri };
end

local function new_access_token(token_jid, role, scope_string, client, id_token, refresh_token_info)
	local token_data = { oauth2_scopes = scope_string, oauth2_client = nil };
	if client then
		token_data.oauth2_client = client_subset(client);
	end
	if next(token_data) == nil then
		token_data = nil;
	end

	local refresh_token;
	local grant = refresh_token_info and refresh_token_info.grant;
	if not grant then
		-- No existing grant, create one
		grant = tokens.create_grant(token_jid, token_jid, default_refresh_ttl, token_data);
		-- Create refresh token for the grant if desired
		refresh_token = refresh_token_info ~= false and tokens.create_token(token_jid, grant, nil, nil, "oauth2-refresh");
	else
		-- Grant exists, reuse existing refresh token
		refresh_token = refresh_token_info.token;

		refresh_token_info.grant = nil; -- Prevent reference loop
	end

	local access_token, access_token_info = tokens.create_token(token_jid, grant, role, default_access_ttl, "oauth2");

	local expires_at = access_token_info.expires;
	return {
		token_type = "bearer";
		access_token = access_token;
		expires_in = expires_at and (expires_at - os.time()) or nil;
		scope = scope_string;
		id_token = id_token;
		refresh_token = refresh_token or nil;
	};
end

local function get_redirect_uri(client, query_redirect_uri) -- record client, string : string
	if not query_redirect_uri then
		if #client.redirect_uris ~= 1 then
			-- Client registered multiple URIs, it needs specify which one to use
			return;
		end
		-- When only a single URI is registered, that's the default
		return client.redirect_uris[1];
	end
	-- Verify the client-provided URI matches one previously registered
	for _, redirect_uri in ipairs(client.redirect_uris) do
		if query_redirect_uri == redirect_uri then
			return redirect_uri
		end
	end
end

local grant_type_handlers = {};
local response_type_handlers = {};

function grant_type_handlers.password(params)
	local request_jid = assert(params.username, oauth_error("invalid_request", "missing 'username' (JID)"));
	local request_password = assert(params.password, oauth_error("invalid_request", "missing 'password'"));
	local request_username, request_host, request_resource = jid.prepped_split(request_jid);

	if not (request_username and request_host) or request_host ~= module.host then
		return oauth_error("invalid_request", "invalid JID");
	end
	if not usermanager.test_password(request_username, request_host, request_password) then
		return oauth_error("invalid_grant", "incorrect credentials");
	end

	local granted_jid = jid.join(request_username, request_host, request_resource);
	local granted_scopes, granted_role = filter_scopes(request_username, params.scope);
	return json.encode(new_access_token(granted_jid, granted_role, granted_scopes, nil));
end

function response_type_handlers.code(client, params, granted_jid, id_token)
	local request_username, request_host = jid.split(granted_jid);
	if not request_host or request_host ~= module.host then
		return oauth_error("invalid_request", "invalid JID");
	end
	local granted_scopes, granted_role = filter_scopes(request_username, params.scope);

	local code = id.medium();
	local ok = codes:set(params.client_id .. "#" .. code, {
		expires = os.time() + 600;
		granted_jid = granted_jid;
		granted_scopes = granted_scopes;
		granted_role = granted_role;
		id_token = id_token;
	});
	if not ok then
		return {status_code = 429};
	end

	local redirect_uri = get_redirect_uri(client, params.redirect_uri);
	if redirect_uri == "urn:ietf:wg:oauth:2.0:oob" then
		-- TODO some nicer template page
		-- mod_http_errors will set content-type to text/html if it catches this
		-- event, if not text/plain is kept for the fallback text.
		local response = { status_code = 200; headers = { content_type = "text/plain" } }
		response.body = module:context("*"):fire_event("http-message", {
			response = response;
			title = "Your authorization code";
			message = "Here's your authorization code, copy and paste it into " .. (client.client_name or "your client");
			extra = code;
		}) or ("Here's your authorization code:\n%s\n"):format(code);
		return response;
	elseif not redirect_uri then
		return 400;
	end

	local redirect = url.parse(redirect_uri);

	local query = http.formdecode(redirect.query or "");
	if type(query) ~= "table" then query = {}; end
	table.insert(query, { name = "code", value = code });
	table.insert(query, { name = "iss", value = get_issuer() });
	if params.state then
		table.insert(query, { name = "state", value = params.state });
	end
	redirect.query = http.formencode(query);

	return {
		status_code = 303;
		headers = {
			location = url.build(redirect);
		};
	}
end

-- Implicit flow
function response_type_handlers.token(client, params, granted_jid)
	local request_username, request_host = jid.split(granted_jid);
	if not request_host or request_host ~= module.host then
		return oauth_error("invalid_request", "invalid JID");
	end
	local granted_scopes, granted_role = filter_scopes(request_username, params.scope);
	local token_info = new_access_token(granted_jid, granted_role, granted_scopes, client, nil);

	local redirect = url.parse(get_redirect_uri(client, params.redirect_uri));
	token_info.state = params.state;
	redirect.fragment = http.formencode(token_info);

	return {
		status_code = 303;
		headers = {
			location = url.build(redirect);
		};
	}
end

local function make_client_secret(client_id) --> client_secret
	return hashes.hmac_sha256(verification_key, client_id, true);
end

local function verify_client_secret(client_id, client_secret)
	return hashes.equals(make_client_secret(client_id), client_secret);
end

function grant_type_handlers.authorization_code(params)
	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end
	if not params.client_secret then return oauth_error("invalid_request", "missing 'client_secret'"); end
	if not params.code then return oauth_error("invalid_request", "missing 'code'"); end
	if params.scope and params.scope ~= "" then
		return oauth_error("invalid_scope", "unknown scope requested");
	end

	local client_ok, client = jwt_verify(params.client_id);
	if not client_ok then
		return oauth_error("invalid_client", "incorrect credentials");
	end

	if not verify_client_secret(params.client_id, params.client_secret) then
		module:log("debug", "client_secret mismatch");
		return oauth_error("invalid_client", "incorrect credentials");
	end
	local code, err = codes:get(params.client_id .. "#" .. params.code);
	if err then error(err); end
	-- MUST NOT use the authorization code more than once, so remove it to
	-- prevent a second attempted use
	codes:set(params.client_id .. "#" .. params.code, nil);
	if not code or type(code) ~= "table" or code_expired(code) then
		module:log("debug", "authorization_code invalid or expired: %q", code);
		return oauth_error("invalid_client", "incorrect credentials");
	end

	return json.encode(new_access_token(code.granted_jid, code.granted_role, code.granted_scopes, client, code.id_token));
end

function grant_type_handlers.refresh_token(params)
	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end
	if not params.client_secret then return oauth_error("invalid_request", "missing 'client_secret'"); end
	if not params.refresh_token then return oauth_error("invalid_request", "missing 'refresh_token'"); end

	local client_ok, client = jwt_verify(params.client_id);
	if not client_ok then
		return oauth_error("invalid_client", "incorrect credentials");
	end

	if not verify_client_secret(params.client_id, params.client_secret) then
		module:log("debug", "client_secret mismatch");
		return oauth_error("invalid_client", "incorrect credentials");
	end

	local refresh_token_info = tokens.get_token_info(params.refresh_token);
	if not refresh_token_info or refresh_token_info.purpose ~= "oauth2-refresh" then
		return oauth_error("invalid_grant", "invalid refresh token");
	end

	-- new_access_token() requires the actual token
	refresh_token_info.token = params.refresh_token;

	return json.encode(new_access_token(
		refresh_token_info.jid, refresh_token_info.role, refresh_token_info.grant.data.oauth2_scopes, client, nil, refresh_token_info
	));
end

-- Used to issue/verify short-lived tokens for the authorization process below
local new_user_token, verify_user_token = jwt.init("HS256", random.bytes(32), nil, { default_ttl = 600 });

-- From the given request, figure out if the user is authenticated and has granted consent yet
-- As this requires multiple steps (seek credentials, seek consent), we have a lot of state to
-- carry around across requests. We also need to protect against CSRF and session mix-up attacks
-- (e.g. the user may have multiple concurrent flows in progress, session cookies aren't unique
--  to one of them).
-- Our strategy here is to preserve the original query string (containing the authz request), and
-- encode the rest of the flow in form POSTs.
local function get_auth_state(request)
	local form = request.method == "POST"
	         and request.body
	         and request.body ~= ""
	         and request.headers.content_type == "application/x-www-form-urlencoded"
	         and http.formdecode(request.body);

	if type(form) ~= "table" then return {}; end

	if not form.user_token then
		-- First step: login
		local username = encodings.stringprep.nodeprep(form.username);
		local password = encodings.stringprep.saslprep(form.password);
		if not (username and password) or not usermanager.test_password(username, module.host, password) then
			return {
				error = "Invalid username/password";
			};
		end
		return {
			user = {
				username = username;
				host = module.host;
				token = new_user_token({ username = username, host = module.host });
			};
		};
	elseif form.user_token and form.consent then
		-- Second step: consent
		local ok, user = verify_user_token(form.user_token);
		if not ok then
			return {
				error = user == "token-expired" and "Session expired - try again" or nil;
			};
		end

		local scope = array():append(form):filter(function(field)
			return field.name == "scope";
		end):pluck("value"):concat(" ");

		user.token = form.user_token;
		return {
			user = user;
			scope = scope;
			consent = form.consent == "granted";
		};
	end

	return {};
end

local function get_request_credentials(request)
	if not request.headers.authorization then return; end

	local auth_type, auth_data = string.match(request.headers.authorization, "^(%S+)%s(.+)$");

	if auth_type == "Basic" then
		local creds = base64.decode(auth_data);
		if not creds then return; end
		local username, password = string.match(creds, "^([^:]+):(.*)$");
		if not username then return; end
		return {
			type = "basic";
			username = username;
			password = password;
		};
	elseif auth_type == "Bearer" then
		return {
			type = "bearer";
			bearer_token = auth_data;
		};
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
			return json.encode(new_access_token(granted_jid, nil, nil, nil));
		end
		return oauth_error("invalid_grant", "incorrect credentials");
	end

	-- TODO How would this make sense with components?
	-- Have an admin authenticate maybe?
	response_type_handlers.code = nil;
	response_type_handlers.token = nil;
	grant_type_handlers.authorization_code = nil;
end

-- OAuth errors should be returned to the client if possible, i.e. by
-- appending the error information to the redirect_uri and sending the
-- redirect to the user-agent. In some cases we can't do this, e.g. if
-- the redirect_uri is missing or invalid. In those cases, we render an
-- error directly to the user-agent.
local function error_response(request, err)
	local q = request.url.query and http.formdecode(request.url.query);
	local redirect_uri = q and q.redirect_uri;
	if not redirect_uri or not is_secure_redirect(redirect_uri) then
		module:log("warn", "Missing or invalid redirect_uri <%s>, rendering error to user-agent", redirect_uri or "");
		return render_page(templates.error, { error = err });
	end
	local redirect_query = url.parse(redirect_uri);
	local sep = redirect_query.query and "&" or "?";
	redirect_uri = redirect_uri
		.. sep .. http.formencode(err.extra.oauth2_response)
		.. "&" .. http.formencode({ state = q.state, iss = get_issuer() });
	module:log("warn", "Sending error response to client via redirect to %s", redirect_uri);
	return {
		status_code = 303;
		headers = {
			location = redirect_uri;
		};
	};
end

local allowed_grant_type_handlers = module:get_option_set("allowed_oauth2_grant_types", {"authorization_code", "password", "refresh_token"})
for handler_type in pairs(grant_type_handlers) do
	if not allowed_grant_type_handlers:contains(handler_type) then
		module:log("debug", "Grant type %q disabled", handler_type);
		grant_type_handlers[handler_type] = nil;
	else
		module:log("debug", "Grant type %q enabled", handler_type);
	end
end

-- "token" aka implicit flow is considered insecure
local allowed_response_type_handlers = module:get_option_set("allowed_oauth2_response_types", {"code"})
for handler_type in pairs(response_type_handlers) do
	if not allowed_response_type_handlers:contains(handler_type) then
		module:log("debug", "Response type %q disabled", handler_type);
		response_type_handlers[handler_type] = nil;
	else
		module:log("debug", "Response type %q enabled", handler_type);
	end
end

function handle_token_grant(event)
	local credentials = get_request_credentials(event.request);

	event.response.headers.content_type = "application/json";
	local params = http.formdecode(event.request.body);
	if not params then
		return error_response(event.request, oauth_error("invalid_request"));
	end

	if credentials and credentials.type == "basic" then
		params.client_id = http.urldecode(credentials.username);
		params.client_secret = http.urldecode(credentials.password);
	end

	local grant_type = params.grant_type
	local grant_handler = grant_type_handlers[grant_type];
	if not grant_handler then
		return error_response(event.request, oauth_error("unsupported_grant_type"));
	end
	return grant_handler(params);
end

local function handle_authorization_request(event)
	local request = event.request;

	if not request.url.query then
		return error_response(request, oauth_error("invalid_request"));
	end
	local params = http.formdecode(request.url.query);
	if not params then
		return error_response(request, oauth_error("invalid_request"));
	end

	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end

	local ok, client = jwt_verify(params.client_id);

	if not ok then
		return oauth_error("invalid_client", "incorrect credentials");
	end

	local auth_state = get_auth_state(request);
	if not auth_state.user then
		-- Render login page
		return render_page(templates.login, { state = auth_state, client = client });
	elseif auth_state.consent == nil then
		-- Render consent page
		return render_page(templates.consent, { state = auth_state; client = client; scopes = parse_scopes(params.scope or "") }, true);
	elseif not auth_state.consent then
		-- Notify client of rejection
		return error_response(request, oauth_error("access_denied"));
	end
	-- else auth_state.consent == true

	params.scope = auth_state.scope;

	local user_jid = jid.join(auth_state.user.username, module.host);
	local client_secret = make_client_secret(params.client_id);
	local id_token_signer = jwt.new_signer("HS256", client_secret);
	local id_token = id_token_signer({
		iss = get_issuer();
		sub = url.build({ scheme = "xmpp"; path = user_jid });
		aud = params.client_id;
		nonce = params.nonce;
	});
	local response_type = params.response_type;
	local response_handler = response_type_handlers[response_type];
	if not response_handler then
		return error_response(request, oauth_error("unsupported_response_type"));
	end
	return response_handler(client, params, user_jid, id_token);
end

local function handle_revocation_request(event)
	local request, response = event.request, event.response;
	if request.headers.authorization then
		local credentials = get_request_credentials(request);
		if not credentials or credentials.type ~= "basic" then
			response.headers.www_authenticate = string.format("Basic realm=%q", module.host.."/"..module.name);
			return 401;
		end
		-- OAuth "client" credentials
		if not verify_client_secret(credentials.username, credentials.password) then
			return 401;
		end
	end

	local form_data = http.formdecode(event.request.body or "");
	if not form_data or not form_data.token then
		response.headers.accept = "application/x-www-form-urlencoded";
		return 415;
	end
	local ok, err = tokens.revoke_token(form_data.token);
	if not ok then
		module:log("warn", "Unable to revoke token: %s", tostring(err));
		return 500;
	end
	return 200;
end

local registration_schema = {
	type = "object";
	required = {
		-- These are shown to users in the template
		"client_name";
		"client_uri";
		-- We need at least one redirect URI for things to work
		"redirect_uris";
	};
	properties = {
		redirect_uris = { type = "array"; minLength = 1; items = { type = "string"; format = "uri" } };
		token_endpoint_auth_method = { type = "string"; enum = { "none"; "client_secret_post"; "client_secret_basic"; default = "client_secret_basic" } };
		grant_types = {
			type = "array";
			items = {
				type = "string";
				enum = {
					"authorization_code";
					"implicit";
					"password";
					"client_credentials";
					"refresh_token";
					"urn:ietf:params:oauth:grant-type:jwt-bearer";
					"urn:ietf:params:oauth:grant-type:saml2-bearer";
				};
			};
			default = { "authorization_code" };
		};
		application_type = { type = "string"; enum = { "native"; "web" }; default = "web" };
		response_types = { type = "array"; items = { type = "string"; enum = { "code"; "token" } }; default = { "code" } };
		client_name = { type = "string" };
		client_uri = { type = "string"; format = "uri"; luaPattern = "^https:" };
		logo_uri = { type = "string"; format = "uri"; luaPattern = "^https:" };
		scope = { type = "string" };
		contacts = { type = "array"; items = { type = "string" } };
		tos_uri = { type = "string"; format = "uri"; luaPattern = "^https:" };
		policy_uri = { type = "string"; format = "uri"; luaPattern = "^https:" };
		jwks_uri = { type = "string"; format = "uri"; luaPattern = "^https:" };
		jwks = { type = "object"; description = "JSON Web Key Set, RFC 7517" };
		software_id = { type = "string"; format = "uuid" };
		software_version = { type = "string" };
	};
	luaPatternProperties = {
		-- Localized versions of descriptive properties and URIs
		["^client_name#"] = { description = "Localized version of 'client_name'"; type = "string" };
		["^[a-z_]+_uri#"] = { type = "string"; format = "uri"; luaPattern = "^https:" };
	};
}

local function redirect_uri_allowed(redirect_uri, client_uri, app_type)
	local uri = url.parse(redirect_uri);
	if app_type == "native" then
		return uri.scheme == "http" and uri.host == "localhost" or uri.scheme ~= "https";
	elseif app_type == "web" then
		return uri.scheme == "https" and uri.host == client_uri.host;
	end
end

function create_client(client_metadata)
	if not schema.validate(registration_schema, client_metadata) then
		return nil, oauth_error("invalid_request", "Failed schema validation.");
	end

	-- Fill in default values
	for propname, propspec in pairs(registration_schema.properties) do
		if client_metadata[propname] == nil and type(propspec) == "table" and propspec.default ~= nil then
			client_metadata[propname] = propspec.default;
		end
	end

	local client_uri = url.parse(client_metadata.client_uri);
	if not client_uri or client_uri.scheme ~= "https" then
		return nil, oauth_error("invalid_request", "Missing, invalid or insecure client_uri");
	end

	for _, redirect_uri in ipairs(client_metadata.redirect_uris) do
		if not redirect_uri_allowed(redirect_uri, client_uri, client_metadata.application_type) then
			return nil, oauth_error("invalid_request", "Invalid, insecure or inappropriate redirect URI.");
		end
	end

	for field, prop_schema in pairs(registration_schema.properties) do
		if field ~= "client_uri" and prop_schema.format == "uri" and client_metadata[field] then
			local components = url.parse(client_metadata[field]);
			if components.scheme ~= "https" then
				return nil, oauth_error("invalid_request", "Insecure URI forbidden");
			end
			if components.authority ~= client_uri.authority then
				return nil, oauth_error("invalid_request", "Informative URIs must have the same hostname");
			end
		end
	end

	-- Localized URIs should be secure too
	for k, v in pairs(client_metadata) do
		if k:find"_uri#" then
			local uri = url.parse(v);
			if not uri or uri.scheme ~= "https" then
				return nil, oauth_error("invalid_request", "Missing, invalid or insecure "..k);
			elseif uri.host ~= client_uri.host then
				return nil, oauth_error("invalid_request", "All URIs must use the same hostname as client_uri");
			end
		end
	end

	-- Ensure each signed client_id JWT is unique, short ID and issued at
	-- timestamp should be sufficient to rule out brute force attacks
	client_metadata.nonce = id.short();

	-- Do we want to keep everything?
	local client_id = jwt_sign(client_metadata);
	local client_secret = make_client_secret(client_id);

	client_metadata.client_id = client_id;
	client_metadata.client_secret = client_secret;
	client_metadata.client_id_issued_at = os.time();
	client_metadata.client_secret_expires_at = 0;

	if not registration_options.accept_expired then
		client_metadata.client_secret_expires_at = client_metadata.client_id_issued_at + (registration_options.default_ttl or 3600);
	end

	return client_metadata;
end

local function handle_register_request(event)
	local request = event.request;
	local client_metadata, err = json.decode(request.body);
	if err then
		return oauth_error("invalid_request", "Invalid JSON");
	end

	local response, err = create_client(client_metadata);
	if err then return err end

	return {
		status_code = 201;
		headers = { content_type = "application/json" };
		body = json.encode(response);
	};
end

if not registration_key then
	module:log("info", "No 'oauth2_registration_key', dynamic client registration disabled")
	handle_authorization_request = nil
	handle_register_request = nil
end

local function handle_userinfo_request(event)
	local request = event.request;
	local credentials = get_request_credentials(request);
	if not credentials or not credentials.bearer_token then
		module:log("debug", "Missing credentials for UserInfo endpoint: %q", credentials)
		return 401;
	end
	local token_info,err = tokens.get_token_info(credentials.bearer_token);
	if not token_info then
		module:log("debug", "UserInfo query failed token validation: %s", err)
		return 403;
	end
	local scopes = set.new()
	if type(token_info.grant.data) == "table" and type(token_info.grant.data.oauth2_scopes) == "string" then
		scopes:add_list(parse_scopes(token_info.grant.data.oauth2_scopes));
	else
		module:log("debug", "token_info = %q", token_info)
	end

	if not scopes:contains("openid") then
		module:log("debug", "Missing the 'openid' scope in %q", scopes)
		-- The 'openid' scope is required for access to this endpoint.
		return 403;
	end

	local user_info = {
		iss = get_issuer();
		sub = url.build({ scheme = "xmpp"; path = token_info.jid });
	}

	local token_claims = set.intersection(openid_claims, scopes);
	token_claims:remove("openid"); -- that's "iss" and "sub" above
	if not token_claims:empty() then
		-- Another module can do that
		module:fire_event("token/userinfo", {
			token = token_info;
			claims = token_claims;
			username = jid.split(token_info.jid);
			userinfo = user_info;
		});
	end

	return {
		status_code = 200;
		headers = { content_type = "application/json" };
		body = json.encode(user_info);
	};
end

module:depends("http");
module:provides("http", {
	route = {
		-- User-facing login and consent view
		["GET /authorize"] = handle_authorization_request;
		["POST /authorize"] = handle_authorization_request;

		-- Create OAuth client
		["POST /register"] = handle_register_request;

		["POST /token"] = handle_token_grant;
		["POST /revoke"] = handle_revocation_request;

		-- OpenID
		["GET /userinfo"] = handle_userinfo_request;

		-- Optional static content for templates
		["GET /style.css"] = templates.css and {
			headers = {
				["Content-Type"] = "text/css";
			};
			body = _render_html(templates.css, module:get_option("oauth2_template_style"));
		} or nil;
		["GET /script.js"] = templates.js and {
			headers = {
				["Content-Type"] = "text/javascript";
			};
			body = templates.js;
		} or nil;
	};
});

local http_server = require "net.http.server";

module:hook_object_event(http_server, "http-error", function (event)
	local oauth2_response = event.error and event.error.extra and event.error.extra.oauth2_response;
	if not oauth2_response then
		return;
	end
	event.response.headers.content_type = "application/json";
	event.response.status_code = event.error.code or 400;
	return json.encode(oauth2_response);
end, 5);

-- OIDC Discovery

module:provides("http", {
	name = "oauth2-discovery";
	default_path = "/.well-known/oauth-authorization-server";
	route = {
		["GET"] = {
			headers = { content_type = "application/json" };
			body = json.encode {
				-- RFC 8414: OAuth 2.0 Authorization Server Metadata
				issuer = get_issuer();
				authorization_endpoint = handle_authorization_request and module:http_url() .. "/authorize" or nil;
				token_endpoint = handle_token_grant and module:http_url() .. "/token" or nil;
				jwks_uri = nil; -- TODO?
				registration_endpoint = handle_register_request and module:http_url() .. "/register" or nil;
				scopes_supported = usermanager.get_all_roles and array(it.keys(usermanager.get_all_roles(module.host))):append(array(openid_claims:items()));
				response_types_supported = array(it.keys(response_type_handlers));
				authorization_response_iss_parameter_supported = true;

				-- OpenID
				userinfo_endpoint = handle_register_request and module:http_url() .. "/userinfo" or nil;
			};
		};
	};
});

module:shared("tokenauth/oauthbearer_config").oidc_discovery_url = module:http_url("oauth2-discovery", "/.well-known/oauth-authorization-server");
