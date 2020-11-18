local html = [[
<meta property="og:title" content="Example 1">
<meta property=og:title content="Example 2">
<meta property="og:title" content="Example 3" >
<meta property="og:title" content="Example 4" />
<meta property="og:title" content="Example 5"/>
<meta property=og:title content=Example 6/>
<meta property="og:title" content= "Example 7" />
<meta property="og:title" itemprop="image primaryImageOfPage" content="Example 8" />
<meta content="Example 9" property="og:title" >
<meta content="Example 10" property="og:title">
<meta content="Example 11" property="og:title"/>
<meta content="Example 12" property="og:title" />
<meta content="Example 13" property=og:title >
<meta content=Example 14 property=og:title >
<meta content= "Example 15" property="og:title" />
<meta content="Example 16" itemprop="image primaryImageOfPage"  property="og:title" />
]]


local ogp_pattern = [[<meta property=["']?(og:.-)["']? content=%s*["']?(.-)["']?%s-/?>]]
local ogp_pattern2 = [[<meta content=%s*["']?(.-)["']? property=["']?(og:.-)["']?%s-/?>]]

for property, content in html:gmatch(ogp_pattern) do
    print("Pattern 1|", property, content, "|Pattern 1")
end
print('-------------------------------------------------------------')
for content, property in html:gmatch(ogp_pattern2) do
    print("Pattern 2|", property, content, "|Pattern 2")
end
