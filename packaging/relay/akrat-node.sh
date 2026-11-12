#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "$0")" && pwd)"
mode="${1:-both}"
shift || true
mailbox_config="${AKRAT_MAILBOX_CONFIG:-$root/akrat-mailbox.toml}"
relay_config="${AKRAT_RELAY_CONFIG:-$root/iroh-relay.toml}"
relay_url="${AKRAT_RELAY_URL:-}"
identity_key="${AKRAT_RELAY_IDENTITY_KEY:-${XDG_DATA_HOME:-$HOME/.local/share}/akrat/relay-identity.key}"
identity_bind="${AKRAT_RELAY_IDENTITY_BIND:-0.0.0.0:8090}"
mailbox_pid=""
relay_pid=""

stop_children() {
  for child in "$mailbox_pid" "$relay_pid"; do
    if [[ -n "$child" ]] && kill -0 "$child" 2>/dev/null; then
      kill "$child" 2>/dev/null || true
    fi
  done
  for child in "$mailbox_pid" "$relay_pid"; do
    if [[ -n "$child" ]]; then
      wait "$child" 2>/dev/null || true
    fi
  done
}

start_relay() {
  if [[ -z "$relay_url" ]]; then
    printf 'Set AKRAT_RELAY_URL to the public HTTPS URL of this relay.\n' >&2
    return 2
  fi
  mkdir -p "$(dirname -- "$identity_key")"
  "$root/akrat-relay" --config-path "$relay_config" --advertise-url "$relay_url" --identity-key "$identity_key" --identity-bind "$identity_bind"
}

trap stop_children EXIT INT TERM

case "$mode" in
  mailbox)
    exec "$root/akrat-mailbox" --config "$mailbox_config" serve
    ;;
  relay)
    if [[ -z "$relay_url" ]]; then
      printf 'Set AKRAT_RELAY_URL to the public HTTPS URL of this relay.\n' >&2
      exit 2
    fi
    exec "$root/akrat-relay" --config-path "$relay_config" --advertise-url "$relay_url" --identity-key "$identity_key" --identity-bind "$identity_bind"
    ;;
  both)
    "$root/akrat-mailbox" --config "$mailbox_config" serve &
    mailbox_pid=$!
    start_relay &
    relay_pid=$!
    set +e
    wait -n "$mailbox_pid" "$relay_pid"
    result=$?
    set -e
    exit "$result"
    ;;
  *)
    printf 'Usage: %s {mailbox|relay|both}\n' "$0" >&2
    exit 2
    ;;
esac
