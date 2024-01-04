local st = require "util.stanza";
local new_id = require"util.id".medium;
local dataform = require "util.dataforms".new;

local local_domain = module:get_host();
local service = module:get_option(module.name .. "_service") or "pubsub." .. local_domain;
local node = module:get_option(module.name .. "_node") or "serverinfo";
local actor = module.host .. "/modules/" .. module.name;
local publication_interval = module:get_option(module.name .. "_publication_interval") or 300;
local cache_ttl = module:get_option(module.name .. "_cache_ttl") or 3600;

local opt_in_reports

function module.load()
	discover_node():next(
		function(exists)
			if not exists then create_node() end
		end
	):catch(
		function(error)
			module:log("warn", "Error prevented discovery or creation of pub/sub node at %s: %s", service, error)
		end
	)

	module:add_feature("urn:xmpp:serverinfo:0");

	module:add_extension(dataform {
		{ name = "FORM_TYPE", type = "hidden", value = "http://jabber.org/network/serverinfo" },
		{ name = "serverinfo-pubsub-node", type = "text-single" },
	}:form({ ["serverinfo-pubsub-node"] = ("xmpp:%s?;node=%s"):format(service, node) }, "result"));

	module:add_timer(10, publish_serverinfo);
end

function module.unload()
	-- This removes all subscribers, which may or may not be desirable, depending on the reason for the unload.
	delete_node(); -- Should this block, to delay unload() until the node is deleted?
end

-- Returns a promise of a boolean
function discover_node()
    local request = st.iq({ type = "get", to = service, from = actor, id = new_id() })
    	:tag("query", { xmlns = "http://jabber.org/protocol/disco#items" })

	module:log("debug", "Sending request to discover existence of pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to service discovery items request at %s: %s", service, response.stanza)
				return false
			end

			local query = response.stanza:get_child("query", "http://jabber.org/protocol/disco#items")
			if query ~= nil then
				for item in query:childtags("item") do
					if item.attr.jid == service and item.attr.node == node then
						module:log("debug", "pub/sub node '%s' at %s does exists.", node, service)
						return true
					end
				end
			end
			module:log("debug", "pub/sub node '%s' at %s does not exist.", node, service)
			return false;
		end
	);
end

-- Returns a promise of a boolean
function create_node()
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("create", { node = node }):up()
			:tag("configure")
				:tag("x", { xmlns = "jabber:x:data", type = "submit" })
					:tag("field", { var = "FORM_TYPE", type = "hidden"})
						:text_tag("value", "http://jabber.org/protocol/pubsub#node_config")
						:up()
					:tag("field", { var = "pubsub#max_items" })
						:text_tag("value", "1")
						:up()
					:tag("field", { var = "pubsub#persist_items" })
						:text_tag("value", "0")

	module:log("debug", "Sending request to create pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to pub/sub node '%s' creation request at %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully created pub/sub node '%s' at %s", node, service)
				return true
			end
		end
	)
end

-- Returns a promise of a boolean
function delete_node()
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("delete", { node = node });

	module:log("debug", "Sending request to delete pub/sub node '%s' at %s", node, service)
	return module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to pub/sub node '%s' deletion request at %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully deleted pub/sub node '%s' at %s", node, service)
				return true
			end
		end
	)
end

function publish_serverinfo()
	-- Iterate over s2s sessions, adding them to a multimap, where the key is the local domain name,
	-- mapped to a collection of remote domain names. De-duplicate all remote domain names by using
	-- them as an index in a table.
	local domains_by_host = {}
	for session, _ in pairs(prosody.incoming_s2s) do
		if session ~= nil and session.from_host ~= nil and local_domain == session.to_host then
			local sessions = domains_by_host[session.to_host]
			if sessions == nil then sessions = {} end; -- instantiate a new entry if none existed
			sessions[session.from_host] = true
			domains_by_host[session.to_host] = sessions
		end
	end

	-- At an earlier stage, the code iterated voer all prosody.hosts - but that turned out to be to noisy.
	-- for host, data in pairs(prosody.hosts) do
	local host = local_domain
	local data = prosody.hosts[host]
	if data ~= nil then
		local sessions = domains_by_host[host]
		if sessions == nil then sessions = {} end; -- instantiate a new entry if none existed
		if data.s2sout ~= nil then
			for _, session in pairs(data.s2sout) do
				if session.to_host ~= nil then
					sessions[session.to_host] = true
					domains_by_host[host] = sessions
				end
			end
		end
	end

	-- Build the publication stanza.
	local request = st.iq({ type = "set", to = service, from = actor, id = new_id() })
		:tag("pubsub", { xmlns = "http://jabber.org/protocol/pubsub" })
			:tag("publish", { node = node, xmlns = "http://jabber.org/protocol/pubsub" })
				:tag("item", { id = "current", xmlns = "http://jabber.org/protocol/pubsub" })
					:tag("serverinfo", { xmlns = "urn:xmpp:serverinfo:0" })

	request:tag("domain", { name = local_domain })
		:tag("federation")

	local remotes = domains_by_host[host]

	if remotes ~= nil then
		for remote, _ in pairs(remotes) do
			-- include a domain name for remote domains, but only if they advertise support.
			if does_opt_in(remote) then
				request:tag("remote-domain", { name = remote }):up()
			else
				request:tag("remote-domain"):up()
			end
		end
	end

	request:up():up()

	module:send_iq(request):next(
		function(response)
			if response.stanza == nil or response.stanza.attr.type ~= "result" then
				module:log("warn", "Unexpected response to item publication at pub/sub node '%s' on %s: %s", node, service, response.stanza)
				return false
			else
				module:log("debug", "Successfully published item on pub/sub node '%s' at %s", node, service)
				return true
			end
		end,
		function(error)
			module:log("warn", "Error prevented publication of item on pub/sub node at %s: %s", service, error)
		end
	)

	return publication_interval;
end

local opt_in_cache = {}

function does_opt_in(remoteDomain)

	-- try to read answer from cache.
	local cached_value = opt_in_cache[remoteDomain]
	if cached_value ~= nil and os.difftime(cached_value.expires, os.time()) > 0 then
		return cached_value.opt_in;
	end

	-- TODO worry about not having multiple requests in flight to the same domain.cached_value

	-- Cache could not provide an answer. Perform service discovery.
    local discoRequest = st.iq({ type = "get", to = remoteDomain, from = actor, id = new_id() })
    	:tag("query", { xmlns = "http://jabber.org/protocol/disco#info" })

	module:send_iq(discoRequest):next(
		function(response)
			if response.stanza ~= nil and response.stanza.attr.type == "result" then
				local query = response.stanza:get_child("query", "http://jabber.org/protocol/disco#info")
				if query ~= nil then
					for feature in query:childtags("feature", "http://jabber.org/protocol/disco#info") do
						if feature.attr.var == 'urn:xmpp:serverinfo:0' then
							opt_in_cache[remoteDomain] = {
								opt_in = true;
								expires = os.time() + cache_ttl;
							}
							return; -- prevent 'false' to be cached, down below.
						end
					end
				end
			end
			opt_in_cache[remoteDomain] = {
				opt_in = false;
				expires = os.time() + cache_ttl;
			}
		end,
		function(response)
			opt_in_cache[remoteDomain] = {
				opt_in = false;
				expires = os.time() + cache_ttl;
			}
		end
	);

	-- return 'false' for now. Better luck next time...
	return false;

end
