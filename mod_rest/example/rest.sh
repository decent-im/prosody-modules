#!/bin/bash -eu

# Copyright (c) Kim Alvefur
# This file is MIT/X11 licensed.

# Dependencies:
# - https://httpie.io/
# - https://github.com/stedolan/jq
# - some sort of XDG 'open' command

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
	TOKEN_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.token_endpoint')"

	if [ -z "${OAUTH_CLIENT_INFO:-}" ]; then
		# Register a new OAuth client
		REGISTRATION_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.registration_endpoint')"
		OAUTH_CLIENT_INFO="$(http --check-status "$REGISTRATION_ENDPOINT" Content-Type:application/json Accept:application/json client_name=rest.sh client_uri="https://modules.prosody.im/mod_rest" application_type=native software_id=0bdb0eb9-18e8-43af-a7f6-bd26613374c0 redirect_uris:='["urn:ietf:wg:oauth:2.0:oob"]')"
		mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/rest/"
		typeset -p OAUTH_CLIENT_INFO >> "${XDG_CACHE_HOME:-$HOME/.cache}/rest/$HOST"
	fi

	CLIENT_ID="$(echo "$OAUTH_CLIENT_INFO" | jq -e -r '.client_id')"
	CLIENT_SECRET="$(echo "$OAUTH_CLIENT_INFO" | jq -e -r '.client_secret')"

	if [ -n "${REFRESH_TOKEN:-}" ]; then
		TOKEN_RESPONSE="$(http --check-status --form "$TOKEN_ENDPOINT" 'grant_type=refresh_token' "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET" "refresh_token=$REFRESH_TOKEN")"
		ACCESS_TOKEN="$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')"
		if [ "$ACCESS_TOKEN" == "null" ]; then
			ACCESS_TOKEN=""
		fi
	fi

	if [ -z "${ACCESS_TOKEN:-}" ]; then
		CODE_CHALLENGE="$(head -c 33 /dev/urandom | base64 | tr /+ _-)"
		open "$AUTHORIZATION_ENDPOINT?response_type=code&client_id=$CLIENT_ID&code_challenge=$CODE_CHALLENGE&scope=${SCOPE:-openid+prosody:user}"
		read -p "Paste authorization code: " -s -r AUTHORIZATION_CODE

		TOKEN_RESPONSE="$(http --check-status --form "$TOKEN_ENDPOINT" 'grant_type=authorization_code' "client_id=$CLIENT_ID" "client_secret=$CLIENT_SECRET" "code=$AUTHORIZATION_CODE" code_verifier="$CODE_CHALLENGE")"
		ACCESS_TOKEN="$(echo "$TOKEN_RESPONSE" | jq -e -r '.access_token')"
		REFRESH_TOKEN="$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')"

		if [ "$REFRESH_TOKEN" != "null" ]; then
			# FIXME Better type check would be nice, but nobody should ever have the
			# string "null" as a legitimate refresh token...
			typeset -p REFRESH_TOKEN >> "${XDG_CACHE_HOME:-$HOME/.cache}/rest/$HOST"
		fi

		if [ -n "${COLORTERM:-}" ]; then
			echo -ne '\e[1K\e[G'
		else
			echo
		fi
	fi

	USERINFO_ENDPOINT="$(echo "$OAUTH_META" | jq -e -r '.userinfo_endpoint')"
	http --check-status -b --session rest "$USERINFO_ENDPOINT" "Authorization:Bearer $ACCESS_TOKEN" Accept:application/json >&2
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
