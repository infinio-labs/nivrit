#!/usr/bin/env bash
set -euo pipefail

# Full-stack feature test for Nivrit running under Docker Compose.
# This script starts the API + web + Postgres stack and exercises:
#   - registration / login
#   - org / project / environment creation
#   - client-side encrypted secret set / get / list / update / delete
#   - audit logging and ML-DSA-65 signature verification
#   - member invitation with hybrid-encapsulated project keys
#   - user key rotation
#   - login rate limiting

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE="docker compose --env-file ${ROOT_DIR}/.env.docker -f ${ROOT_DIR}/docker-compose.yml"
API_BASE="http://localhost:4000"

ALICE_HOME="/tmp/nivrit-e2e-alice"
BOB_HOME="/tmp/nivrit-e2e-bob"
ALICE_PASSWORD="AliceSecret123!"
BOB_PASSWORD="BobSecret123!"

# Use unique identifiers so the script can be re-run against the same database.
SUFFIX="$(date +%s)"
ALICE_EMAIL="alice-${SUFFIX}@example.com"
BOB_EMAIL="bob-${SUFFIX}@example.com"
ORG_NAME="AliceOrg"
ORG_SLUG="alice-org-${SUFFIX}"
PROJ_NAME="TestProject"
PROJ_SLUG="testproject-${SUFFIX}"
ENV_NAME="Prod"
ENV_SLUG="prod-${SUFFIX}"

info() { echo "===> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Run the Nivrit CLI inside the API container with a custom HOME so each user
# gets an isolated config file.
run_cli() {
  local home_dir="$1"
  shift
  ${COMPOSE} exec -T -e "HOME=${home_dir}" api nivrit "$@"
}

# Read a value from a CLI config JSON by key.
config_value() {
  local home_dir="$1"
  local key="$2"
  ${COMPOSE} exec -T -e "HOME=${home_dir}" api sh -c 'cat "$HOME/.nivrit/config.json"' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['${key}'])"
}

# Make an authenticated API call using a user's bearer token.
api_get() {
  local home_dir="$1"
  local path="$2"
  local token
  token="$(config_value "${home_dir}" token)"
  curl -sf -H "Authorization: Bearer ${token}" "${API_BASE}${path}"
}

api_post() {
  local home_dir="$1"
  local path="$2"
  local body="$3"
  local token
  token="$(config_value "${home_dir}" token)"
  curl -sf -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
    -d "${body}" "${API_BASE}${path}"
}

cd "${ROOT_DIR}"

info "starting Docker Compose stack"
${COMPOSE} up -d --wait

info "waiting for API health"
for _ in {1..30}; do
  if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -sf "${API_BASE}/health" | grep -q ok || fail "API did not become healthy"

# Start each run with clean CLI home directories so leftover project keys from
# previous runs cannot interfere with key rotation.
${COMPOSE} exec -T api rm -rf "${ALICE_HOME}" "${BOB_HOME}"

# -----------------------------------------------------------------------------
# Core secret lifecycle
# -----------------------------------------------------------------------------
info "registering Alice"
run_cli "${ALICE_HOME}" register --email "${ALICE_EMAIL}" --password "${ALICE_PASSWORD}" --name Alice

info "creating organization"
ORG_OUT="$(run_cli "${ALICE_HOME}" create-org --name "${ORG_NAME}" --slug "${ORG_SLUG}")"
ORG_ID="$(echo "${ORG_OUT}" | awk '{print $1}')"
[ -n "${ORG_ID}" ] || fail "failed to parse org id"

info "creating project"
PROJ_OUT="$(run_cli "${ALICE_HOME}" create-project --org-id "${ORG_ID}" --name "${PROJ_NAME}" --slug "${PROJ_SLUG}")"
PROJ_ID="$(echo "${PROJ_OUT}" | awk '{print $1}')"
[ -n "${PROJ_ID}" ] || fail "failed to parse project id"

info "creating environment"
ENV_OUT="$(run_cli "${ALICE_HOME}" create-environment --project-id "${PROJ_ID}" --name "${ENV_NAME}" --slug "${ENV_SLUG}")"
ENV_ID="$(echo "${ENV_OUT}" | awk '{print $1}')"
[ -n "${ENV_ID}" ] || fail "failed to parse environment id"

info "setting secret"
SET_OUT="$(run_cli "${ALICE_HOME}" set --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key API_KEY --value secretvalue123)"
echo "${SET_OUT}" | grep -q "API_KEY version 1" || fail "unexpected set output: ${SET_OUT}"

info "getting secret"
GET_OUT="$(run_cli "${ALICE_HOME}" get --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key API_KEY)"
[ "${GET_OUT}" = "API_KEY=secretvalue123" ] || fail "unexpected get output: ${GET_OUT}"

info "updating secret (versioning)"
SET_OUT2="$(run_cli "${ALICE_HOME}" set --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key API_KEY --value secretvalue456)"
echo "${SET_OUT2}" | grep -q "API_KEY version 2" || fail "expected version 2, got: ${SET_OUT2}"

info "listing secrets"
LIST_OUT="$(run_cli "${ALICE_HOME}" list-secrets --project-id "${PROJ_ID}" --environment-id "${ENV_ID}")"
echo "${LIST_OUT}" | grep -q "API_KEY=secretvalue456" || fail "list did not contain updated secret"

info "deleting secret"
DELETE_OUT="$(run_cli "${ALICE_HOME}" delete-secret --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key API_KEY)"
echo "${DELETE_OUT}" | grep -q "deleted API_KEY: true" || fail "unexpected delete output: ${DELETE_OUT}"

# -----------------------------------------------------------------------------
# Audit logs + PQ signature verification
# -----------------------------------------------------------------------------
info "fetching audit logs"
LOGS_JSON="$(api_get "${ALICE_HOME}" "/projects/${PROJ_ID}/audit-logs")"
WRITE_LOG_ID="$(echo "${LOGS_JSON}" | python3 -c "import json,sys; logs=json.load(sys.stdin); print(next(l['id'] for l in logs if l['action']=='write'))")"
READ_LOG_ID="$(echo "${LOGS_JSON}" | python3 -c "import json,sys; logs=json.load(sys.stdin); print(next(l['id'] for l in logs if l['action']=='read'))")"
DELETE_LOG_ID="$(echo "${LOGS_JSON}" | python3 -c "import json,sys; logs=json.load(sys.stdin); print(next(l['id'] for l in logs if l['action']=='delete'))")"

info "verifying audit-log ML-DSA-65 signatures"
for log_id in "${WRITE_LOG_ID}" "${READ_LOG_ID}" "${DELETE_LOG_ID}"; do
  VERIFY_JSON="$(api_get "${ALICE_HOME}" "/projects/${PROJ_ID}/audit-logs/${log_id}/verify")"
  echo "${VERIFY_JSON}" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['valid'], d" || fail "audit log ${log_id} did not verify"
done

# -----------------------------------------------------------------------------
# Member invitation (hybrid project-key sharing)
# -----------------------------------------------------------------------------
info "registering Bob"
run_cli "${BOB_HOME}" register --email "${BOB_EMAIL}" --password "${BOB_PASSWORD}" --name Bob

info "Alice invites Bob as member"
INVITE_OUT="$(run_cli "${ALICE_HOME}" invite --project-id "${PROJ_ID}" --email "${BOB_EMAIL}" --role member)"
echo "${INVITE_OUT}" | grep -q "invited" || fail "invitation failed: ${INVITE_OUT}"

info "Bob logs in and reads the shared project"
run_cli "${BOB_HOME}" login --email "${BOB_EMAIL}" --password "${BOB_PASSWORD}"

# Re-create a secret after the invitation so Bob's project key is populated.
info "Alice sets a secret after inviting Bob"
run_cli "${ALICE_HOME}" set --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key SHARED_KEY --value sharedvalue

info "Bob retrieves the shared secret"
BOB_GET="$(run_cli "${BOB_HOME}" get --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key SHARED_KEY)"
[ "${BOB_GET}" = "SHARED_KEY=sharedvalue" ] || fail "Bob could not read shared secret: ${BOB_GET}"

# -----------------------------------------------------------------------------
# Key rotation
# -----------------------------------------------------------------------------
info "Alice rotates her hybrid key pair"
ROTATE_OUT="$(run_cli "${ALICE_HOME}" rotate-key --password "${ALICE_PASSWORD}")"
echo "${ROTATE_OUT}" | grep -q "rotated key pair" || fail "key rotation failed: ${ROTATE_OUT}"

info "Alice sets a secret after key rotation"
run_cli "${ALICE_HOME}" set --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key ROTATED_KEY --value rotatedvalue
GET_ROTATED="$(run_cli "${ALICE_HOME}" get --project-id "${PROJ_ID}" --environment-id "${ENV_ID}" --key ROTATED_KEY)"
[ "${GET_ROTATED}" = "ROTATED_KEY=rotatedvalue" ] || fail "secret after rotation mismatch: ${GET_ROTATED}"

# -----------------------------------------------------------------------------
# Login rate limiting
# -----------------------------------------------------------------------------
info "testing login rate limiting"
RATE_HOME="/tmp/nivrit-e2e-rate"
# Register a victim account.
RATE_EMAIL="rate-${SUFFIX}@example.com"
run_cli "${RATE_HOME}" register --email "${RATE_EMAIL}" --password RateLimit123! --name Rate
for i in {1..5}; do
  run_cli "${RATE_HOME}" login --email "${RATE_EMAIL}" --password wrongpassword || true
done
# Sixth attempt should be rate limited (HTTP 403).
set +e
run_cli "${RATE_HOME}" login --email "${RATE_EMAIL}" --password RateLimit123! >/dev/null 2>&1
RC=$?
set -e
[ "${RC}" -ne 0 ] || fail "sixth login should have been rate limited"

info "all stack tests passed"
