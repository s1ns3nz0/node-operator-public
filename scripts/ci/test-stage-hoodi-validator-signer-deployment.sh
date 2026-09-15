#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"; script="$root/scripts/ops/stage-hoodi-validator-signer-deployment.sh"
scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT; mkdir -p "$scratch/bin"
cat >"$scratch/desired.json" <<'JSON'
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"validator-hoodi-example-remote-signer","namespace":"validator-operations"},"spec":{"replicas":0,"selector":{"matchLabels":{"app":"signer","node-operator.io/validator-set":"hoodi-example"}},"template":{"metadata":{"labels":{"app":"signer","node-operator.io/validator-set":"hoodi-example"}},"spec":{"containers":[{"name":"web3signer","image":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}
JSON
cat >"$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"; state="${MOCK_STATE:-ok}"
[ "$state" = api ] && exit 1
if [[ "$args" == *" patch deployment "* ]]; then
  [[ "$args" != *"--dry-run=server"* ]] && echo "$args" >>"$MOCK_TRACE"
  [[ "$state" = patchfail || "$state" = rv ]] && exit 1
  if [[ "$args" == *"--dry-run=server"* ]]; then cat <<'JSON'
{"metadata":{"uid":"dep-uid","resourceVersion":"rv1"},"spec":{"replicas":0,"template":{"metadata":{"labels":{"app":"signer","node-operator.io/validator-set":"hoodi-example"}},"spec":{"containers":[{"name":"web3signer","image":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}
JSON
  fi
  exit 0
fi
if [[ "$args" == *" get deployment validator-hoodi-example-remote-signer "* ]]; then uid=dep-uid; rv=rv1; [ -e "$MOCK_TRACE" ] && rv=rv2; [ "$state" = stale ] && uid=other; [ "$state" = rv ] && rv=rv2; cat <<JSON
{"metadata":{"uid":"$uid","resourceVersion":"$rv","name":"validator-hoodi-example-remote-signer","namespace":"validator-operations"},"spec":{"replicas":0,"selector":{"matchLabels":{"app":"signer","node-operator.io/validator-set":"hoodi-example"}},"template":{"metadata":{"labels":{"app":"signer","node-operator.io/validator-set":"hoodi-example"}},"spec":{"containers":[{"name":"web3signer","image":"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}}
JSON
elif [[ "$args" == *" get deployments,statefulsets "* ]]; then
  if [ "$state" = malformed ]; then echo '{"items":null}'
  elif [ "$state" = controller ]; then echo '{"items":[{"metadata":{},"spec":{"replicas":1,"selector":{"matchLabels":{"node-operator.io/validator-set":"hoodi-example"}},"template":{"metadata":{"labels":{"node-operator.io/validator-set":"hoodi-example","app.kubernetes.io/component":"validator-remote-signer"}}}}}]}'
  elif [ "$state" = db ]; then echo '{"items":[{"metadata":{},"spec":{"replicas":1,"selector":{"matchLabels":{"node-operator.io/validator-set":"hoodi-example"}},"template":{"metadata":{"labels":{"node-operator.io/validator-set":"hoodi-example","app.kubernetes.io/component":"validator-slashing-db"}}}}}]}'
  else echo '{"items":[]}' ; fi
elif [[ "$args" == *" get pods "* ]]; then
  if [ "$state" = pods ]; then echo '{"items":[{"metadata":{"labels":{"node-operator.io/validator-set":"hoodi-example","app.kubernetes.io/component":"validator-remote-signer"}}}]}'
  elif [ "$state" = otherpods ]; then echo '{"items":[{"metadata":{"labels":{"node-operator.io/validator-set":"hoodi-example","app.kubernetes.io/component":"validator-slashing-db"}}},{"metadata":{"labels":{"app.kubernetes.io/component":"slashing-db-rehearsal"}}}]}'
  elif [ "$state" = malformedpods ]; then echo '{"items":null}'
  else echo '{"items":[]}' ; fi
elif [[ "$args" == *" get lease "* ]]; then [ "$state" = lease ] && echo '{"spec":{"holderIdentity":"held"}}' || echo '{"spec":{"holderIdentity":""}}'
elif [[ "$args" == *" get pvc "* ]]; then [ "$state" = pvc ] && echo '{"metadata":{"uid":"wrong"},"status":{"phase":"Lost"},"spec":{"volumeName":"pv-uid"}}' || echo '{"metadata":{"uid":"pvc-uid"},"status":{"phase":"Bound"},"spec":{"volumeName":"pv-uid"}}'
elif [[ "$args" == *"get pv pv-uid "* ]]; then [ "$state" = pv ] && echo '{"status":{"phase":"Bound"},"spec":{"claimRef":{"namespace":"validator-operations","name":"data-validator-hoodi-example-slashing-db-0","uid":"wrong"}}}' || echo '{"status":{"phase":"Bound"},"spec":{"claimRef":{"namespace":"validator-operations","name":"data-validator-hoodi-example-slashing-db-0","uid":"pvc-uid"}}}'
else exit 64; fi
EOF
chmod +x "$scratch/bin/kubectl"
run() { local state="$1"; shift; PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_STATE="$state" "$script" --validator-set hoodi-example --desired-deployment "$scratch/desired.json" --expected-deployment-uid dep-uid --expected-pvc-uid pvc-uid --maintenance-approval-id approved "$@"; }
cp "$script" "$scratch/stage-hoodi-validator-signer-deployment.sh"
cat >"$scratch/with-private-eks.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = -- ] && shift
[ "$1" = env ] && shift
[ "$1" = PRIVATE_EKS_SESSION=1 ] && shift
printf '%s\n' "$*" >"$MOCK_WRAPPER_TRACE"
export PRIVATE_EKS_SESSION=1
exec "$@"
EOF
chmod +x "$scratch/with-private-eks.sh" "$scratch/stage-hoodi-validator-signer-deployment.sh"
run_wrapped() { env -u PRIVATE_EKS_SESSION PATH="$scratch/bin:$PATH" MOCK_TRACE="$scratch/trace" MOCK_WRAPPER_TRACE="$scratch/wrapper-trace" MOCK_STATE=ok "$scratch/stage-hoodi-validator-signer-deployment.sh" --validator-set hoodi-example --desired-deployment "$scratch/desired.json" --expected-deployment-uid dep-uid --expected-pvc-uid pvc-uid --maintenance-approval-id approved --dry-run; }
run_wrapped >/dev/null; grep -Fq -- '--validator-set hoodi-example' "$scratch/wrapper-trace"; grep -Fq -- "--desired-deployment $scratch/desired.json" "$scratch/wrapper-trace"
run ok >/dev/null; grep -Fq '"/spec/template"' "$scratch/trace"; if grep -Fq '"op":"replace","path":"/spec/replicas"' "$scratch/trace" || grep -Fq ' patch lease ' "$scratch/trace"; then exit 1; fi
rm -f "$scratch/trace"; run db >/dev/null
rm -f "$scratch/trace"; run otherpods >/dev/null
rm -f "$scratch/trace"; run ok --dry-run >/dev/null; [ ! -e "$scratch/trace" ]
for state in pods stale rv lease pvc pv patchfail malformed malformedpods controller api; do rm -f "$scratch/trace"; if run "$state" >/dev/null 2>&1; then echo "expected refusal: $state" >&2; exit 1; fi; [ ! -e "$scratch/trace" ] || [ "$state" = patchfail ] || [ "$state" = rv ]; done
cp "$scratch/desired.json" "$scratch/bad.json"; sed -i.bak 's/"replicas":0/"replicas":1/' "$scratch/bad.json"; if PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" "$script" --validator-set hoodi-example --desired-deployment "$scratch/bad.json" --expected-deployment-uid dep-uid --expected-pvc-uid pvc-uid --maintenance-approval-id approved >/dev/null 2>&1; then exit 1; fi
jq '.spec.template.spec.containers[0].image |= sub("^123456789012"; "999999999999")' "$scratch/desired.json" >"$scratch/wrong-account.json"
jq '.spec.template.spec.containers[0].image |= sub("node-operator-baseline-validator-runtime-web3signer"; "web3signer")' "$scratch/desired.json" >"$scratch/wrong-repo.json"
jq '.spec.template.spec.containers += [{name:"unexpected",image:"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]' "$scratch/desired.json" >"$scratch/extra-container.json"
jq '.spec.template.spec.initContainers = [{name:"unexpected",image:"123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/node-operator-baseline-validator-runtime-web3signer@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]' "$scratch/desired.json" >"$scratch/init-container.json"
for rejected in wrong-account wrong-repo extra-container init-container; do if PRIVATE_EKS_SESSION=1 PATH="$scratch/bin:$PATH" "$script" --validator-set hoodi-example --desired-deployment "$scratch/$rejected.json" --expected-deployment-uid dep-uid --expected-pvc-uid pvc-uid --maintenance-approval-id approved >/dev/null 2>&1; then echo "expected desired refusal: $rejected" >&2; exit 1; fi; done
grep -Fq 'node-operator-baseline-validator-runtime-web3signer' "$script"; grep -Fq 'get deployments,statefulsets -o json' "$script"
