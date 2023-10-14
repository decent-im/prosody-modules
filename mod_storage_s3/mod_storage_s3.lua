local http = require "prosody.net.http";
local array = require "prosody.util.array";
local async = require "prosody.util.async";
local hashes = require "prosody.util.hashes";
local httputil = require "prosody.util.http";
local it = require "prosody.util.iterators";
local jid = require "prosody.util.jid";
local json = require "prosody.util.json";
local st = require "prosody.util.stanza";
local xml = require "prosody.util.xml";
local url = require "socket.url";

local hmac_sha256 = hashes.hmac_sha256;
local sha256 = hashes.sha256;

local driver = {};

local bucket = module:get_option_string("s3_bucket", "prosody");
local base_uri = module:get_option_string("s3_base_uri", "http://localhost:9000");
local region = module:get_option_string("s3_region", "us-east-1");

local access_key = module:get_option_string("s3_access_key");
local secret_key = module:get_option_string("s3_secret_key");

function driver:open(store, typ)
	local mt = self[typ or "keyval"]
	if not mt then
		return nil, "unsupported-store";
	end
	return setmetatable({ store = store; bucket = bucket; type = typ }, mt);
end

local keyval = { };
driver.keyval = { __index = keyval; __name = module.name .. " keyval store" };

local aws4_format = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s";

local function new_request(method, path, query, payload)
	local request = url.parse(base_uri);
	request.path = path;

	local payload_type = nil;
	if st.is_stanza(payload) then
		payload_type = "application/xml";
		payload = tostring(payload);
	elseif payload ~= nil then
		payload_type = "application/json";
		payload = json.encode(payload);
	end

	local payload_hash = sha256(payload or "", true);

	local now = os.time();
	local aws_datetime = os.date("!%Y%m%dT%H%M%SZ", now);
	local aws_date = os.date("!%Y%m%d", now);

	local headers = {
		["Accept"] = "*/*";
		["Authorization"] = nil;
		["Content-Type"] = payload_type;
		["Host"] = request.authority;
		["User-Agent"] = "Prosody XMPP Server";
		["X-Amz-Content-Sha256"] = payload_hash;
		["X-Amz-Date"] = aws_datetime;
	};

	local canonical_uri = url.build({ path = request.path });
	local canonical_query = "";
	local canonical_headers = array();
	local signed_headers = array()

	if query then
		local sorted_query = array();
		for name, value in it.sorted_pairs(query) do
			sorted_query:push({ name = name; value = value });
		end
		sorted_query:sort(function (a,b) return a.name < b.name end)
		canonical_query = httputil.formencode(sorted_query):gsub("%%%x%x", string.upper);
		request.query = canonical_query;
	end

	for header_name, header_value in it.sorted_pairs(headers) do
		header_name = header_name:lower();
		canonical_headers:push(header_name .. ":" .. header_value .. "\n");
		signed_headers:push(header_name);
	end

	canonical_headers = canonical_headers:concat();
	signed_headers = signed_headers:concat(";");

	local scope = aws_date .. "/" .. region .. "/s3/aws4_request";

	local canonical_request = method .. "\n"
		.. canonical_uri .. "\n"
		.. canonical_query .. "\n"
		.. canonical_headers .. "\n"
		.. signed_headers .. "\n"
		.. payload_hash;

	local signature_payload = "AWS4-HMAC-SHA256" .. "\n" .. aws_datetime .. "\n" .. scope .. "\n" .. sha256(canonical_request, true);

	-- This can be cached?
	local date_key = hmac_sha256("AWS4" .. secret_key, aws_date);
	local date_region_key = hmac_sha256(date_key, region);
	local date_region_service_key = hmac_sha256(date_region_key, "s3");
	local signing_key = hmac_sha256(date_region_service_key, "aws4_request");

	local signature = hmac_sha256(signing_key, signature_payload, true);

	headers["Authorization"] = string.format(aws4_format, access_key, scope, signed_headers, signature);

	return http.request(url.build(request), { method = method; headers = headers; body = payload });
end

-- coerce result back into Prosody data type
local function on_result(response)
	local content_type = response.headers["content-type"];
	if content_type == "application/json" then
		return json.decode(response.body);
	elseif content_type == "application/xml" then
		return xml.parse(response.body);
	elseif content_type == "application/x-www-form-urlencoded" then
		return httputil.formdecode(response.body);
	else
		response.log("warn", "Unknown response data type %s", content_type);
		return response.body;
	end
end

function keyval:_path(key)
	return url.build_path({
		is_absolute = true;
		bucket;
		jid.escape(module.host);
		jid.escape(self.store);
		jid.escape(key or "");
	})
end

function keyval:get(user)
	return async.wait_for(new_request("GET", self:_path(user)):next(on_result));
end

function keyval:set(user, data)
	return async.wait_for(new_request("PUT", self:_path(user), data));
end

function keyval:users()
	return nil, "not-implemented";
end

module:provides("storage", driver);
