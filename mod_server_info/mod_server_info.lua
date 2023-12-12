-- XEP-0128: Service Discovery Extensions (manual config)
--
-- Copyright (C) 2023 Matthew Wild
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local dataforms = require "util.dataforms";

local config = module:get_option("server_info");

if not config or next(config) == nil then return; end -- Nothing to do

for _, form in ipairs(config) do
	module:add_extension(dataforms.new(form):form({}, "result"));
end

