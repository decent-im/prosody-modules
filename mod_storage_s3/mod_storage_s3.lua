local http = require "prosody.net.http";
local array = require "prosody.util.array";
local async = require "prosody.util.async";
local dt = require "prosody.util.datetime";
local hashes = require "prosody.util.hashes";
local httputil = require "prosody.util.http";
local uuid = require "prosody.util.uuid";
local it = require "prosody.util.iterators";
local jid = require "prosody.util.jid";
local json = require "prosody.util.json";
local st = require "prosody.util.stanza";
local xml = require "prosody.util.xml";
local url = require "socket.url";

local new_uuid = uuid.v7 or uuid.generate;
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
	if response.code >= 400 then
		error(response.body);
	end
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

	if data == nil or (type(data) == "table" and next(data) == nil) then
		return async.wait_for(new_request("DELETE", self:_path(user)));
	end

	return async.wait_for(new_request("PUT", self:_path(user), nil, data));
end

function keyval:users()
	local bucket_path = url.build_path({ is_absolute = true; bucket; is_directory = true });
	local prefix = url.build_path({ jid.escape(module.host); jid.escape(self.store); is_directory = true });
	local list_result, err = async.wait_for(new_request("GET", bucket_path, { prefix = prefix }))
	if err or list_result.code ~= 200 then
		return nil, err;
	end
	local list_bucket_result = xml.parse(list_result.body);
	if list_bucket_result:get_child_text("IsTruncated") == "true" then
		local max_keys = list_bucket_result:get_child_text("MaxKeys");
		module:log("warn", "Paging truncated results not implemented, max %s %s returned", max_keys, self.store);
	end
	local keys = array();
	for content in list_bucket_result:childtags("Contents") do
		local key = url.parse_path(content:get_child_text("Key"));
		keys:push(jid.unescape(key[3]));
	end
	return function()
		return keys:pop();
	end
end

local archive = {};
driver.archive = { __index = archive };

archive.caps = {
};

function archive:_path(username, date, when, with, key)
	return url.build_path({
		is_absolute = true;
		bucket;
		jid.escape(module.host);
		jid.escape(self.store);
		jid.escape(username);
		jid.escape(jid.prep(with));
		date or dt.date(when);
		key;
	})
end


-- PUT .../with/when/id
function archive:append(username, key, value, when, with)
	local wrapper = st.stanza("wrapper");
	-- Minio had trouble with timestamps, probably the ':' characters, in paths.
	wrapper:tag("delay", { xmlns = "urn:xmpp:delay"; stamp = dt.datetime(when) }):up();
	wrapper:add_direct_child(value);
	key = key or new_uuid();
	return async.wait_for(new_request("PUT", self:_path(username, nil, when, with, key), nil, wrapper):next(function(r)
		if r.code == 200 then
			return key;
		else
			error(r.body);
		end
	end));
end

function archive:find(username, query)
	local bucket_path = url.build_path({ is_absolute = true; bucket; is_directory = true });
	local prefix = { jid.escape(module.host); jid.escape(self.store); is_directory = true };
	table.insert(prefix, jid.escape(username or "@"));
	if query["with"] then
		table.insert(prefix, sha256(jid.prep(query["with"]), true):sub(1,24));
		if query["start"] and query["end"] and dt.date(query["start"]) == dt.date(query["end"]) then
			table.insert(prefix, sha256(jid.prep(query["with"]), true):sub(1,24));
		end
	end

	prefix = url.build_path(prefix);
	local list_result, err = async.wait_for(new_request("GET", bucket_path, {
		prefix = prefix;
		["max-keys"] = query["max"] and tostring(query["max"]);
	}));
	if err or list_result.code ~= 200 then
		return nil, err;
	end
	local list_bucket_result = xml.parse(list_result.body);
	if list_bucket_result:get_child_text("IsTruncated") == "true" then
		local max_keys = list_bucket_result:get_child_text("MaxKeys");
		module:log("warn", "Paging truncated results not implemented, max %s %s returned", max_keys, self.store);
	end
	local keys = array();
	local iterwrap = function(...)
		return ...;
	end
	if query["reverse"] then
		query["before"], query["after"] = query["after"], query["before"];
		iterwrap = it.reverse;
	end
	local found = not query["after"];
	for content in iterwrap(list_bucket_result:childtags("Contents")) do
		local key = url.parse_path(content:get_child_text("Key"));
		if found and query["before"] == key[6] then
			break
		end
		if (not query["with"] or query["with"] == jid.unescape(key[5]))
		and (not query["start"] or dt.date(query["start"]) >= key[6])
		and (not query["end"] or dt.date(query["end"]) <= key[6])
		and found then
			keys:push({ key = key[6]; date = key[5]; with = jid.unescape(key[4]) });
		end
		if not found and key[6] == query["after"] then
			found = not found
		end
	end
	local i = 0;
	return function()
		i = i + 1;
		local item = keys[i];
		if item == nil then
			return nil;
		end
		-- luacheck: ignore 431/err
		local value, err = async.wait_for(new_request("GET", self:_path(username or "@", item.date, nil, item.with, item.key)):next(on_result));
		if not value then
			module:log("error", "%s", err);
			return nil;
		end
		local delay = value:get_child("delay", "urn:xmpp:delay");

		return item.key, value.tags[2], dt.parse(delay.attr.stamp), item.with;
	end
end

function archive:users()
	return it.unique(keyval.users(self));
end

--[[ TODO
function archive:delete(username, query)
	return nil, "not-implemented";
end
--]]

module:provides("storage", driver);
