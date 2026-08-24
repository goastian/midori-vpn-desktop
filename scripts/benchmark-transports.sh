#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'Usage: %s --server-id UUID --protocol wireguard|wss|masque|smart_auto --throughput-url HTTPS_URL [--iterations N]\n' "$0" >&2
}

server_id=""
protocol=""
throughput_url=""
iterations=10
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-id) server_id="${2:-}"; shift 2 ;;
    --protocol) protocol="${2:-}"; shift 2 ;;
    --throughput-url) throughput_url="${2:-}"; shift 2 ;;
    --iterations) iterations="${2:-}"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

[[ "$server_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || { usage; exit 2; }
[[ "$protocol" == wireguard || "$protocol" == wss || "$protocol" == masque || "$protocol" == smart_auto ]] || { usage; exit 2; }
[[ "$throughput_url" == https://* ]] || { usage; exit 2; }
[[ "$iterations" =~ ^[0-9]+$ ]] && (( iterations >= 5 && iterations <= 100 )) || { printf 'iterations must be between 5 and 100\n' >&2; exit 2; }

for command_name in curl jq awk; do
  command -v "$command_name" >/dev/null 2>&1 || { printf '%s is required\n' "$command_name" >&2; exit 1; }
done

if [[ -r /etc/midorivpn/launcher.env ]]; then
  set -a
  # shellcheck source=/dev/null
  source /etc/midorivpn/launcher.env
  set +a
fi
: "${MIDORIVPN_AGENT_PORT:?MIDORIVPN_AGENT_PORT is required}"
: "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}"

token_file="$XDG_RUNTIME_DIR/midorivpn-agent.token"
[[ -s "$token_file" ]] || { printf 'MidoriVPN agent token is unavailable; start the client first\n' >&2; exit 1; }
agent_token="$(tr -d '\r\n' <"$token_file")"
agent_url="http://127.0.0.1:$MIDORIVPN_AGENT_PORT"

work_dir="$(mktemp -d /tmp/midorivpn-benchmark.XXXXXX)"
cleanup() {
  printf 'header = "X-Agent-Token: %s"\n' "$agent_token" | curl --config - --silent --max-time 15 --request POST "$agent_url/vpn/disconnect" >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM

agent_request() {
  local path="$1"
  shift
  printf 'header = "X-Agent-Token: %s"\nheader = "Content-Type: application/json"\n' "$agent_token" |
    curl --config - --fail-with-body --silent --show-error --max-time 45 "$@" "$agent_url$path"
}

printf 'Checking authenticated local agent...\n' >&2
agent_request /status | jq -e '.auth.logged_in == true' >/dev/null

for ((sample = 1; sample <= iterations; sample++)); do
  response="$(agent_request /vpn/connect --request POST --data "{\"server_id\":\"$server_id\",\"protocol\":\"$protocol\"}")"
  jq -e '.ok == true and (.connection_ms | type == "number")' <<<"$response" >/dev/null
  jq -r '.connection_ms' <<<"$response" >>"$work_dir/connection_ms"
  jq -r '.active_protocol' <<<"$response" >>"$work_dir/active_protocol"

  read -r bytes duration < <(curl --fail --silent --show-error --location --max-time 60 --output /dev/null --write-out '%{size_download} %{time_total}\n' "$throughput_url")
  awk -v bytes="$bytes" -v seconds="$duration" 'BEGIN { if (seconds <= 0) exit 1; printf "%.6f\n", (bytes * 8) / seconds / 1000000 }' >>"$work_dir/throughput_mbps"

  agent_request /vpn/disconnect --request POST --data '{}' >/dev/null
  sleep 1
done

numeric_stats() {
  jq -Rs '
    split("\n") | map(select(length > 0) | tonumber) | sort |
    def percentile(p): .[((length - 1) * p | floor)];
    {samples: ., p50: percentile(0.50), p95: percentile(0.95), min: .[0], max: .[-1]}
  ' "$1"
}

jq -n \
  --arg server_id "$server_id" \
  --arg requested_protocol "$protocol" \
  --argjson iterations "$iterations" \
  --argjson connection_ms "$(numeric_stats "$work_dir/connection_ms")" \
  --argjson throughput_mbps "$(numeric_stats "$work_dir/throughput_mbps")" \
  --argjson active_protocols "$(jq -Rs 'split("\n") | map(select(length > 0)) | group_by(.) | map({protocol: .[0], samples: length})' "$work_dir/active_protocol")" \
  '{server_id: $server_id, requested_protocol: $requested_protocol, iterations: $iterations, connection_ms: $connection_ms, throughput_mbps: $throughput_mbps, active_protocols: $active_protocols}'

trap - EXIT INT TERM
cleanup
