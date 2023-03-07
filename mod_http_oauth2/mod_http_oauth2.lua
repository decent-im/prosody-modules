local hashes = require "util.hashes";
local cache = require "util.cache";
local http = require "util.http";
local jid = require "util.jid";
local json = require "util.json";
local usermanager = require "core.usermanager";
local errors = require "util.error";
local url = require "socket.url";
local uuid = require "util.uuid";
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

local function filter_scopes(username, host, requested_scope_string)
	if host ~= module.host then
		return usermanager.get_jid_role(username.."@"..host, module.host).name;
	end

	if requested_scope_string then -- Specific role requested
		-- TODO: The requested scope string is technically a space-delimited list
		-- of scopes, but for simplicity we're mapping this slot to role names.
		if usermanager.user_can_assume_role(username, module.host, requested_scope_string) then
			return requested_scope_string;
		end
	end

	return usermanager.get_user_role(username, module.host).name;
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
module:add_timer(900, function()
	local k, code = codes:tail();
	while code and code_expired(code) do
		codes:set(k, nil);
		k, code = codes:tail();
	end
	return code and code_expires_in(code) + 1 or 900;
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

local function new_access_token(token_jid, scope, ttl)
	local token = tokens.create_jid_token(token_jid, token_jid, scope, ttl, nil, "oauth2");
	return {
		token_type = "bearer";
		access_token = token;
		expires_in = ttl;
		scope = scope;
		-- TODO: include refresh_token when implemented
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
	local granted_scopes = filter_scopes(request_username, request_host, params.scope);
	return json.encode(new_access_token(granted_jid, granted_scopes, nil));
end

function response_type_handlers.code(client, params, granted_jid)
	local request_username, request_host = jid.split(granted_jid);
	local granted_scopes = filter_scopes(request_username, request_host, params.scope);

	local code = uuid.generate();
	local ok = codes:set(params.client_id .. "#" .. code, {
		expires = os.time() + 600;
		granted_jid = granted_jid;
		granted_scopes = granted_scopes;
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
		return {status_code = 400};
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
	local granted_scopes = filter_scopes(request_username, request_host, params.scope);
	local token_info = new_access_token(granted_jid, granted_scopes, nil);

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

local function make_secret(client_id) --> client_secret
	return hashes.hmac_sha256(verification_key, client_id, true);
end

local function verify_secret(client_id, client_secret)
	return hashes.equals(make_secret(client_id), client_secret);
end

function grant_type_handlers.authorization_code(params)
	if not params.client_id then return oauth_error("invalid_request", "missing 'client_id'"); end
	if not params.client_secret then return oauth_error("invalid_request", "missing 'client_secret'"); end
	if not params.code then return oauth_error("invalid_request", "missing 'code'"); end
	if params.scope and params.scope ~= "" then
		return oauth_error("invalid_scope", "unknown scope requested");
	end

	local client = jwt_verify(params.client_id);
	if not client then
		return oauth_error("invalid_client", "incorrect credentials");
	end

	if not verify_secret(params.client_id, params.client_secret) then
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

	return json.encode(new_access_token(code.granted_jid, code.granted_scopes, nil));
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
	         and #request.body > 0
	         and request.headers.content_type == "application/x-www-form-urlencoded"
	         and http.formdecode(request.body);

	if not form then return {}; end

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

		user.token = form.user_token;
		return {
			user = user;
			consent = form.consent == "granted";
		};
	end

	return {};
end

local function check_credentials(request, allow_token)
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
	elseif auth_type == "Bearer" and allow_token then
		local token_info = tokens.get_token_info(auth_data);
		if not token_info or not token_info.session or token_info.session.host ~= module.host then
			return false;
		end
		return token_info.session.username;
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
	response_type_handlers.token = nil;
	grant_type_handlers.authorization_code = nil;
	check_credentials = function () return false end
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
	local sep = redirect_query and "&" or "?";
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

local allowed_grant_type_handlers = module:get_option_set("allowed_oauth2_grant_types", {"authorization_code", "password"})
for handler_type in pairs(grant_type_handlers) do
	if not allowed_grant_type_handlers:contains(handler_type) then
		grant_type_handlers[handler_type] = nil;
	end
end

-- "token" aka implicit flow is considered insecure
local allowed_response_type_handlers = module:get_option_set("allowed_oauth2_response_types", {"code"})
for handler_type in pairs(response_type_handlers) do
	if not allowed_response_type_handlers:contains(handler_type) then
		grant_type_handlers[handler_type] = nil;
	end
end

function handle_token_grant(event)
	event.response.headers.content_type = "application/json";
	local params = http.formdecode(event.request.body);
	if not params then
		return error_response(event.request, oauth_error("invalid_request"));
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
		return render_page(templates.consent, { state = auth_state, client = client }, true);
	elseif not auth_state.consent then
		-- Notify client of rejection
		return error_response(request, oauth_error("access_denied"));
	end

	local response_type = params.response_type;
	local response_handler = response_type_handlers[response_type];
	if not response_handler then
		return error_response(request, oauth_error("unsupported_response_type"));
	end
	return response_handler(client, params, jid.join(auth_state.user.username, module.host));
end

local function handle_revocation_request(event)
	local request, response = event.request, event.response;
	if not request.headers.authorization then
		response.headers.www_authenticate = string.format("Basic realm=%q", module.host.."/"..module.name);
		return 401;
	elseif request.headers.content_type ~= "application/x-www-form-urlencoded"
	or not request.body or request.body == "" then
		return 400;
	end
	local user = check_credentials(request, true);
	if not user then
		return 401;
	end

	local form_data = http.formdecode(event.request.body);
	if not form_data or not form_data.token then
		return 400;
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
	required = { "client_name"; "redirect_uris" };
	properties = {
		redirect_uris = { type = "array"; minLength = 1; items = { type = "string"; format = "uri" } };
		token_endpoint_auth_method = { enum = { "none"; "client_secret_post"; "client_secret_basic" }; type = "string" };
		grant_types = {
			items = {
				enum = {
					"authorization_code";
					"implicit";
					"password";
					"client_credentials";
					"refresh_token";
					"urn:ietf:params:oauth:grant-type:jwt-bearer";
					"urn:ietf:params:oauth:grant-type:saml2-bearer";
				};
				type = "string";
			};
			type = "array";
		};
		response_types = { items = { enum = { "code"; "token" }; type = "string" }; type = "array" };
		client_name = { type = "string" };
		client_uri = { type = "string"; format = "uri" };
		logo_uri = { type = "string"; format = "uri" };
		scope = { type = "string" };
		contacts = { items = { type = "string" }; type = "array" };
		tos_uri = { type = "string" };
		policy_uri = { type = "string"; format = "uri" };
		jwks_uri = { type = "string"; format = "uri" };
		jwks = { type = "object"; description = "JSON Web Key Set, RFC 7517" };
		software_id = { type = "string"; format = "uuid" };
		software_version = { type = "string" };
	};
}

local function handle_register_request(event)
	local request = event.request;
	local client_metadata = json.decode(request.body);

	if not schema.validate(registration_schema, client_metadata) then
		return oauth_error("invalid_request", "Failed schema validation.");
	end

	-- Ensure each signed client_id JWT is unique
	client_metadata.nonce = uuid.generate();

	-- Do we want to keep everything?
	local client_id = jwt_sign(client_metadata);
	local client_secret = make_secret(client_id);

	local client_desc = {
		client_id = client_id;
		client_secret = client_secret;
		client_id_issued_at = os.time();
		client_secret_expires_at = 0;
	}
	if not registration_options.accept_expired then
		client_desc.client_secret_expires_at = client_desc.client_id_issued_at + (registration_options.default_ttl or 3600);
	end

	return {
		status_code = 201;
		headers = { content_type = "application/json" };
		body = json.encode(client_desc);
	};
end

if not registration_key then
	module:log("info", "No 'oauth2_registration_key', dynamic client registration disabled")
	handle_authorization_request = nil
	handle_register_request = nil
end

module:depends("http");
module:provides("http", {
	route = {
		["POST /token"] = handle_token_grant;
		["GET /authorize"] = handle_authorization_request;
		["POST /authorize"] = handle_authorization_request;
		["POST /revoke"] = handle_revocation_request;
		["POST /register"] = handle_register_request;

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
				issuer = get_issuer();
				authorization_endpoint = handle_authorization_request and module:http_url() .. "/authorize" or nil;
				token_endpoint = handle_token_grant and module:http_url() .. "/token" or nil;
				jwks_uri = nil; -- TODO?
				registration_endpoint = handle_register_request and module:http_url() .. "/register" or nil;
				scopes_supported = usermanager.get_all_roles and array(it.keys(usermanager.get_all_roles(module.host)))
					or { "prosody:restricted"; "prosody:user"; "prosody:admin"; "prosody:operator" };
				response_types_supported = array(it.keys(response_type_handlers));
				authorization_response_iss_parameter_supported = true;
			};
		};
	};
});

module:shared("tokenauth/oauthbearer_config").oidc_discovery_url = module:http_url("oauth2-discovery", "/.well-known/oauth-authorization-server");
