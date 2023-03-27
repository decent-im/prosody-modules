#!/bin/bash -eu

# Copyright (c) Kim Alvefur
# This file is MIT/X11 licensed.

# Settings
HOST=""
DOMAIN=""

AUTH_METHOD="session-read-only"
AUTH_ID="rest"

if [ -f "${XDG_CONFIG_HOME:-$HOME/.config}/restrc" ]; then
	# Config file can contain the above settings
	source "${XDG_CONFIG_HOME:-$HOME/.config}/restrc"
fi
	
if [[ $# == 0 ]]; then
	echo "${0##*/} [-h HOST] [-u USER|--login] [/path] kind=(message|presence|iq) ...."
	# Last arguments are handed to HTTPie, so refer to its docs for further details
	exit 0
fi

if [[ "$1" == "-h" ]]; then
	HOST="$2"
	shift 2
elif [ -z "${HOST:-}" ]; then
	HOST="$(hostname)"
fi

if [[ "$HOST" != *.* ]]; then
	# Assumes subdomain of your DOMAIN
	if [ -z "${DOMAIN:-}" ]; then
		DOMAIN="$(hostname -d)"
	fi
	if [[ "$HOST" == *:* ]]; then
		HOST="${HOST%:*}.$DOMAIN:${HOST#*:}"
	else
		HOST="$HOST.$DOMAIN"
	fi
fi

if [[ "$1" == "-u" ]]; then
	# -u username
	AUTH_METHOD="auth"
	AUTH_ID="$2"
	shift 2
elif [[ "$1" == "-rw" ]]; then
	# To e.g. save Accept headers to the session
	AUTH_METHOD="session"
	shift 1
fi

if [[ "$1" == "--login" ]]; then
	shift 1

	# Check cache for OAuth client
	if [ -f "${XDG_CACHE_HOME:-$HOME/.cache}/rest/$HOST" ]; then
		source "${XDG_CACHE_HOME:-$HOME/.cache}/rest/$HOST" 
	fi

	OAUTH_META="$(http --check-status --json "https://$HOST/.well-known/oauth-authorization-server" Accept:application/json)"
	AUTHORIZATION_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.authorization_endpoint')"
	if [ -z "${OAUTH_CLIENT_INFO:-}" ]; then
		# Register a new OAuth client
		REGISTRATION_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.registration_endpoint')"
		OAUTH_CLIENT_INFO="$(http --check-status "$REGISTRATION_ENDPOINT" Content-Type:application/json Accept:application/json client_name=rest client_uri="https://www.zash.se/rest-script.html" redirect_uris:='["urn:ietf:wg:oauth:2.0:oob"]')"
		mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/rest/"
		typeset -p OAUTH_CLIENT_INFO >> "${XDG_CACHE_HOME:-$HOME/.cache}/rest/$HOST"
	fi

	CLIENT_ID="$(echo "$OAUTH_CLIENT_INFO" | jq -e -r '.client_id')"
	CLIENT_SECRET="$(echo "$OAUTH_CLIENT_INFO" | jq -e -r '.client_secret')"

	open "$AUTHORIZATION_ENDPOINT?response_type=code&client_id=$CLIENT_ID&scope=openid+prosody:user"
	read -p "Paste authorization code: " -s -r AUTHORIZATION_CODE

	TOKEN_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.token_endpoint')"
	TOKEN="$(http --check-status --form "$TOKEN_ENDPOINT" 'grant_type=authorization_code' "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET" "code=$AUTHORIZATION_CODE" | jq -e -r '.access_token')"

	USERINFO_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.userinfo_endpoint')"

	if [ -n "${COLORTERM:-}" ]; then
		echo -ne '\e[1K\e[G'
	else
		echo
	fi
	http --check-status -b --session rest "$USERINFO_ENDPOINT" "Authorization:Bearer $TOKEN" Accept:application/json >&2
	AUTH_METHOD="session-read-only"
	AUTH_ID="rest"
fi

if [[ $# == 0 ]]; then
	# Just login?
	exit 0
fi

# For e.g /disco/example.com and such GET queries
GET_PATH=""
if [[ "$1" == /* ]]; then
	GET_PATH="$1"
	shift 1
fi

http --check-status -p b "--$AUTH_METHOD" "$AUTH_ID" "https://$HOST/rest$GET_PATH" "$@"
