-- XEP-0401: Easy User Onboarding
local dataforms = require "util.dataforms";
local datetime = require "util.datetime";
local split_jid = require "util.jid".split;

local new_adhoc = module:require("adhoc").new;

-- Whether local users can invite other users to create an account on this server
local allow_user_invites = module:get_option_boolean("allow_user_invites", false);
-- Who can see and use the contact invite command. It is strongly recommended to
-- keep this available to all local users. To allow/disallow invite-registration
-- on the server, use the option above instead.
local allow_contact_invites = module:get_option_boolean("allow_contact_invites", true);

local invites;
if prosody.shutdown then -- COMPAT hack to detect prosodyctl
	invites = module:depends("invites");
end

local invite_result_form = dataforms.new({
		title = "Your invite has been created",
		{
			name = "url" ;
			var = "landing-url";
			label = "Invite web page";
			desc = "Share this link";
		},
		{
			name = "uri";
			label = "Invite URI";
			desc = "This alternative link can be opened with some XMPP clients";
		},
		{
			name = "expire";
			label = "Invite valid until";
		},
	});

module:depends("adhoc");

-- This command is available to all local users, even if allow_user_invites = false
-- If allow_user_invites is false, creating an invite still works, but the invite will
-- not be valid for registration on the current server, only for establishing a roster
-- subscription.
module:provides("adhoc", new_adhoc("Create new contact invite", "urn:xmpp:invite#invite",
		function (_, data)
			local username = split_jid(data.from);
			local invite = invites.create_contact(username, allow_user_invites, {
				source = data.from
			});
			--TODO: check errors
			return {
				status = "completed";
				form = {
					layout = invite_result_form;
					values = {
						uri = invite.uri;
						url = invite.landing_page;
						expire = datetime.datetime(invite.expires);
					};
				};
			};
		end, allow_contact_invites and "local_user" or "admin"));

-- This is an admin-only command that creates a new invitation suitable for registering
-- a new account. It does not add the new user to the admin's roster.
module:provides("adhoc", new_adhoc("Create new account invite", "urn:xmpp:invite#create-account",
		function (_, data)
			local invite = invites.create_account(nil, {
				source = data.from
			});
			--TODO: check errors
			return {
				status = "completed";
				form = {
					layout = invite_result_form;
					values = {
						uri = invite.uri;
						url = invite.landing_page;
						expire = datetime.datetime(invite.expires);
					};
				};
			};
		end, "admin"));
