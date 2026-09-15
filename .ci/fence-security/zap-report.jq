(.site | type == "array") and
(.site | length > 0) and
any(.site[]; ."@name" == $target) and
all(.site[]; (.alerts | type == "array")) and
all(.site[].alerts[];
  (.riskcode | type == "string") and
  (.riskcode | test("^[0-3]$")) and
  ((.riskcode | tonumber) < 3)
)
