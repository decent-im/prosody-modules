--% conflicts: mod_bookmarks
module:log("info", "mod_bookmarks has been deprecated, now loading mod_bookmarks2")
module:depends("bookmarks2")
