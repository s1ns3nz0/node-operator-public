# $documents is the canonical client-side rendered List; $database is live.
def objects: .[] | if .kind == "List" then .items[] else . end;
def claims: .spec.volumeClaimTemplates | map({name:.metadata.name,
  accessModes:.spec.accessModes, storageClassName:.spec.storageClassName,
  resources:.spec.resources, volumeMode:(.spec.volumeMode // "Filesystem")});
($documents | [objects]) as $items |
($items | map(select(.kind == "StatefulSet" and .metadata.name == ("validator-" + $set + "-slashing-db")))) as $db |
if ($db | length) != 1 or ($database | length) != 1 then error("exactly one slashing DB required")
elif ($db[0] | claims) != ($database[0] | claims) then error("slashing DB claim configuration differs")
elif $database[0].spec.persistentVolumeClaimRetentionPolicy != {whenDeleted:"Retain",whenScaled:"Retain"} then error("slashing DB retention must be Retain")
else {apiVersion:"v1",kind:"List",items:[$items[] |
  select(.kind != "Lease") |
  if .kind == "StatefulSet" and .metadata.name == ("validator-" + $set + "-slashing-db")
  then del(.spec.volumeClaimTemplates) else . end]}
end
