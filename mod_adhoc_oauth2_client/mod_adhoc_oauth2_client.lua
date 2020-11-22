local adhoc = require "util.adhoc";
local dataforms = require "util.dataforms";
local errors = require "util.error";
local id = require "util.id";
local jid = require "util.jid";

local clients = module:open_store("oauth2_clients", "map");

local new_client = dataforms.new({
	title = "Create OAuth2 client";
	{var = "FORM_TYPE"; type = "hidden"; value = "urn:uuid:ff0d55ed-2187-4ee0-820a-ab633a911c14#create"};
	{name = "name"; type = "text-single"; label = "Client name"; required = true};
	{name = "description"; type = "text-multi"; label = "Description"};
	{name = "info_url"; type = "text-single"; label = "Informative URL"; desc = "Link to information about your client"};
	{name = "redirect_uri"; type = "text-single"; label = "Redirection URI"; desc = "Where to redirect the user after authorizing."; required = true};
})

local client_created = dataforms.new({
	title = "New OAuth2 client created";
	instructions = "Save these details, they will not be shown again";
	{var = "FORM_TYPE"; type = "hidden"; value = "urn:uuid:ff0d55ed-2187-4ee0-820a-ab633a911c14#created"};
	{name = "client_id"; type = "text-single"; label = "Client ID"};
	{name = "client_secret"; type = "text-single"; label = "Client secret"};
})

local function create_client(client, formerr, data)
	if formerr then
		local errmsg = {"Error in form:"};
		for field, err in pairs(formerr) do table.insert(errmsg, field .. ": " .. err); end
		return {status = "error"; error = {message = table.concat(errmsg, "\n")}};
	end

	local creator = jid.split(data.from);
	local client_id = id.short();

	client.client_id = jid.join(creator, module.host, client_id);
	client.client_secret = id.long();

	local ok, err = errors.coerce(clients:set(creator, client_id, client));
	module:log("info", "OAuth2 client %q created by %s", client_id, data.from);
	if not ok then return {status = "error"; error = {message = err}}; end

	return {status = "completed"; result = {layout = client_created; values = client}};
end

local handler = adhoc.new_simple_form(new_client, create_client);

module:provides("adhoc", module:require "adhoc".new(new_client.title, new_client[1].value, handler, "local_user"));

-- TODO list/manage/revoke clients
