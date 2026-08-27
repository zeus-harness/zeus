#!/usr/bin/env bash

set -Eeuo pipefail
# An inherited SHELLOPTS=xtrace or an explicit `bash -x` must not expose the
# generated owner password, bootstrap token, cookies, or CSRF token.
set +x
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
COMPOSE_FILE="${REPO_ROOT}/compose.linux-acceptance.yaml"
EVIDENCE_ROOT="${REPO_ROOT}/.zeus-linux-acceptance"

PROFILE="${ZEUS_LINUX_ACCEPTANCE_PROFILE:-normal}"
if [[ -n "${ZEUS_LINUX_ACCEPTANCE_PROJECT:-}" ]]; then
	PROJECT="${ZEUS_LINUX_ACCEPTANCE_PROJECT}"
elif [[ -n "${GITHUB_RUN_ID:-}" ]]; then
	PROJECT="zeus-linux-acceptance-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}-${PROFILE}"
else
	PROJECT="zeus-linux-acceptance-$(date -u +%Y%m%d%H%M%S)-$$-${RANDOM}"
fi

IMAGE_PREFIX="${ZEUS_LINUX_ACCEPTANCE_IMAGE_PREFIX:-${PROJECT}}"
API_IMAGE="${ZEUS_LINUX_ACCEPTANCE_API_IMAGE:-${IMAGE_PREFIX}-api:local}"
WEB_IMAGE="${ZEUS_LINUX_ACCEPTANCE_WEB_IMAGE:-${IMAGE_PREFIX}-web:local}"
GATEWAY_IMAGE="${ZEUS_LINUX_ACCEPTANCE_GATEWAY_IMAGE:-${IMAGE_PREFIX}-gateway:local}"

if [[ "${PROFILE}" == 'low-memory' ]]; then
	DEFAULT_API_CPUS='1.0'
	DEFAULT_API_MEMORY='256m'
	DEFAULT_API_PIDS='64'
	DEFAULT_WEB_CPUS='0.5'
	DEFAULT_WEB_MEMORY='256m'
	DEFAULT_WEB_PIDS='64'
	DEFAULT_GATEWAY_CPUS='0.25'
	DEFAULT_GATEWAY_MEMORY='64m'
	DEFAULT_GATEWAY_PIDS='32'
	DEFAULT_PRESSURE_REQUESTS='3000'
	DEFAULT_PRESSURE_CONCURRENCY='32'
else
	DEFAULT_API_CPUS='2.0'
	DEFAULT_API_MEMORY='1g'
	DEFAULT_API_PIDS='128'
	DEFAULT_WEB_CPUS='1.0'
	DEFAULT_WEB_MEMORY='512m'
	DEFAULT_WEB_PIDS='128'
	DEFAULT_GATEWAY_CPUS='0.5'
	DEFAULT_GATEWAY_MEMORY='128m'
	DEFAULT_GATEWAY_PIDS='64'
	DEFAULT_PRESSURE_REQUESTS='10000'
	DEFAULT_PRESSURE_CONCURRENCY='64'
fi

API_CPUS="${ZEUS_LINUX_ACCEPTANCE_API_CPUS:-${DEFAULT_API_CPUS}}"
API_MEMORY="${ZEUS_LINUX_ACCEPTANCE_API_MEMORY:-${DEFAULT_API_MEMORY}}"
API_PIDS="${ZEUS_LINUX_ACCEPTANCE_API_PIDS:-${DEFAULT_API_PIDS}}"
WEB_CPUS="${ZEUS_LINUX_ACCEPTANCE_WEB_CPUS:-${DEFAULT_WEB_CPUS}}"
WEB_MEMORY="${ZEUS_LINUX_ACCEPTANCE_WEB_MEMORY:-${DEFAULT_WEB_MEMORY}}"
WEB_PIDS="${ZEUS_LINUX_ACCEPTANCE_WEB_PIDS:-${DEFAULT_WEB_PIDS}}"
GATEWAY_CPUS="${ZEUS_LINUX_ACCEPTANCE_GATEWAY_CPUS:-${DEFAULT_GATEWAY_CPUS}}"
GATEWAY_MEMORY="${ZEUS_LINUX_ACCEPTANCE_GATEWAY_MEMORY:-${DEFAULT_GATEWAY_MEMORY}}"
GATEWAY_PIDS="${ZEUS_LINUX_ACCEPTANCE_GATEWAY_PIDS:-${DEFAULT_GATEWAY_PIDS}}"

PRESSURE_REQUESTS="${ZEUS_LINUX_ACCEPTANCE_PRESSURE_REQUESTS:-${DEFAULT_PRESSURE_REQUESTS}}"
PRESSURE_CONCURRENCY="${ZEUS_LINUX_ACCEPTANCE_PRESSURE_CONCURRENCY:-${DEFAULT_PRESSURE_CONCURRENCY}}"
REUSE_IMAGES="${ZEUS_LINUX_ACCEPTANCE_REUSE_IMAGES:-0}"

export ZEUS_LINUX_ACCEPTANCE_PROJECT="${PROJECT}"
export ZEUS_LINUX_ACCEPTANCE_API_IMAGE="${API_IMAGE}"
export ZEUS_LINUX_ACCEPTANCE_WEB_IMAGE="${WEB_IMAGE}"
export ZEUS_LINUX_ACCEPTANCE_GATEWAY_IMAGE="${GATEWAY_IMAGE}"
export ZEUS_LINUX_ACCEPTANCE_API_CPUS="${API_CPUS}"
export ZEUS_LINUX_ACCEPTANCE_API_MEMORY="${API_MEMORY}"
export ZEUS_LINUX_ACCEPTANCE_API_PIDS="${API_PIDS}"
export ZEUS_LINUX_ACCEPTANCE_WEB_CPUS="${WEB_CPUS}"
export ZEUS_LINUX_ACCEPTANCE_WEB_MEMORY="${WEB_MEMORY}"
export ZEUS_LINUX_ACCEPTANCE_WEB_PIDS="${WEB_PIDS}"
export ZEUS_LINUX_ACCEPTANCE_GATEWAY_CPUS="${GATEWAY_CPUS}"
export ZEUS_LINUX_ACCEPTANCE_GATEWAY_MEMORY="${GATEWAY_MEMORY}"
export ZEUS_LINUX_ACCEPTANCE_GATEWAY_PIDS="${GATEWAY_PIDS}"

STACK_TOUCHED=0
TEMP_ROOT=""
EVIDENCE_DIR=""
BASE_URL=""
API_CONTAINER=""
WEB_CONTAINER=""
GATEWAY_CONTAINER=""
OWNER_PASSWORD=""
OWNER_COOKIE_JAR=""
SECRET_PATTERN_FILE=""
SOURCE_COMMIT=""
SOURCE_TREE=""
LOGGING_ACTIVE=0
TEE_PID=""

log() {
	printf '[zeus-linux-acceptance] %s\n' "$*"
}

die() {
	printf '[zeus-linux-acceptance] error: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

compose() {
	docker compose --env-file /dev/null --project-name "${PROJECT}" --file "${COMPOSE_FILE}" "$@"
}

validate_positive_integer() {
	local name="$1"
	local value="$2"
	[[ "${value}" =~ ^[1-9][0-9]*$ ]] || die "${name} must be a positive integer, got ${value}"
}

validate_positive_cpu() {
	local name="$1"
	local value="$2"
	jq -en --arg value "${value}" '
		($value | tonumber) as $number
		| ($number > 0 and $number <= 64)
	' >/dev/null || die "${name} must be a positive CPU value no greater than 64, got ${value}"
}

memory_bytes() {
	local value
	local amount multiplier
	value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	case "${value}" in
		*[g]) amount="${value%g}"; multiplier=$((1024 * 1024 * 1024)) ;;
		*[m]) amount="${value%m}"; multiplier=$((1024 * 1024)) ;;
		*[k]) amount="${value%k}"; multiplier=1024 ;;
		*) amount="${value}"; multiplier=1 ;;
	esac
	[[ "${amount}" =~ ^[1-9][0-9]*$ ]] || die "invalid positive memory limit: $1"
	((amount <= 9223372036854775807 / multiplier)) || die "memory limit overflows: $1"
	printf '%s\n' "$((amount * multiplier))"
}

validate_configuration() {
	[[ "${PROJECT}" =~ ^zeus-linux-acceptance-[a-z0-9][a-z0-9_-]*$ ]] \
		|| die "project must start with zeus-linux-acceptance- and contain only letters, digits, '_' or '-': ${PROJECT}"
	((${#PROJECT} <= 63)) || die "project name is too long: ${PROJECT}"
	case "${PROFILE}" in
		normal | low-memory) ;;
		*) die "profile must be normal or low-memory, got ${PROFILE}" ;;
	esac
	case "${REUSE_IMAGES}" in
		0 | 1) ;;
		*) die "ZEUS_LINUX_ACCEPTANCE_REUSE_IMAGES must be 0 or 1" ;;
	esac
	validate_positive_cpu ZEUS_LINUX_ACCEPTANCE_API_CPUS "${API_CPUS}"
	validate_positive_cpu ZEUS_LINUX_ACCEPTANCE_WEB_CPUS "${WEB_CPUS}"
	validate_positive_cpu ZEUS_LINUX_ACCEPTANCE_GATEWAY_CPUS "${GATEWAY_CPUS}"
	memory_bytes "${API_MEMORY}" >/dev/null
	memory_bytes "${WEB_MEMORY}" >/dev/null
	memory_bytes "${GATEWAY_MEMORY}" >/dev/null
	validate_positive_integer ZEUS_LINUX_ACCEPTANCE_API_PIDS "${API_PIDS}"
	validate_positive_integer ZEUS_LINUX_ACCEPTANCE_WEB_PIDS "${WEB_PIDS}"
	validate_positive_integer ZEUS_LINUX_ACCEPTANCE_GATEWAY_PIDS "${GATEWAY_PIDS}"
	validate_positive_integer ZEUS_LINUX_ACCEPTANCE_PRESSURE_REQUESTS "${PRESSURE_REQUESTS}"
	validate_positive_integer ZEUS_LINUX_ACCEPTANCE_PRESSURE_CONCURRENCY "${PRESSURE_CONCURRENCY}"
	((PRESSURE_CONCURRENCY <= PRESSURE_REQUESTS)) \
		|| die "pressure concurrency cannot exceed request count"
	local expected_api_cpus expected_api_memory expected_api_pids
	local expected_web_cpus expected_web_memory expected_web_pids
	local expected_gateway_cpus expected_gateway_memory expected_gateway_pids
	local expected_pressure_requests expected_pressure_concurrency
	expected_api_cpus="${DEFAULT_API_CPUS}"
	expected_api_memory="${DEFAULT_API_MEMORY}"
	expected_api_pids="${DEFAULT_API_PIDS}"
	expected_web_cpus="${DEFAULT_WEB_CPUS}"
	expected_web_memory="${DEFAULT_WEB_MEMORY}"
	expected_web_pids="${DEFAULT_WEB_PIDS}"
	expected_gateway_cpus="${DEFAULT_GATEWAY_CPUS}"
	expected_gateway_memory="${DEFAULT_GATEWAY_MEMORY}"
	expected_gateway_pids="${DEFAULT_GATEWAY_PIDS}"
	expected_pressure_requests="${DEFAULT_PRESSURE_REQUESTS}"
	expected_pressure_concurrency="${DEFAULT_PRESSURE_CONCURRENCY}"
	[[ "${API_CPUS}" == "${expected_api_cpus}" \
		&& "${API_MEMORY}" == "${expected_api_memory}" \
		&& "${API_PIDS}" == "${expected_api_pids}" \
		&& "${WEB_CPUS}" == "${expected_web_cpus}" \
		&& "${WEB_MEMORY}" == "${expected_web_memory}" \
		&& "${WEB_PIDS}" == "${expected_web_pids}" \
		&& "${GATEWAY_CPUS}" == "${expected_gateway_cpus}" \
		&& "${GATEWAY_MEMORY}" == "${expected_gateway_memory}" \
		&& "${GATEWAY_PIDS}" == "${expected_gateway_pids}" \
		&& "${PRESSURE_REQUESTS}" == "${expected_pressure_requests}" \
		&& "${PRESSURE_CONCURRENCY}" == "${expected_pressure_concurrency}" ]] \
		|| die "${PROFILE} is a fixed authoritative contract; resource or pressure overrides do not match the profile"
}

ensure_xtrace_disabled() {
	set +x
	[[ "$-" != *x* ]] || die 'xtrace must be disabled before handling acceptance secrets'
}

prepare_source_identity() {
	require_command git
	SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD)" \
		|| die 'could not resolve the source commit'
	SOURCE_TREE="$(git -C "${REPO_ROOT}" rev-parse --verify 'HEAD^{tree}')" \
		|| die 'could not resolve the source tree'
	local dirty
	dirty="$(git -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)" \
		|| die 'could not inspect the source worktree'
	[[ -z "${dirty}" ]] \
		|| die 'authoritative normal/low-memory acceptance requires a clean worktree'
	export ZEUS_LINUX_ACCEPTANCE_SOURCE_COMMIT="${SOURCE_COMMIT}"
	export ZEUS_LINUX_ACCEPTANCE_SOURCE_TREE="${SOURCE_TREE}"
}

preflight() {
	require_command docker
	require_command curl
	require_command jq
	require_command od
	require_command sha256sum
	docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 is required'
	docker info >/dev/null 2>&1 || die 'the Docker daemon is unavailable'
	[[ "$(docker info --format '{{.OSType}}')" == 'linux' ]] \
		|| die 'Linux Docker Engine is required'
	[[ "$(docker info --format '{{.CgroupVersion}}')" == '2' ]] \
		|| die 'Docker must use cgroup v2'
	[[ -f "${COMPOSE_FILE}" ]] || die "missing Compose file: ${COMPOSE_FILE}"
}

assert_project_unused() {
	local containers volumes networks container_names volume_names network_names name
	containers="$(docker container ls --all --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" \
		|| die 'could not query existing project containers'
	volumes="$(docker volume ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" \
		|| die 'could not query existing project volumes'
	networks="$(docker network ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" \
		|| die 'could not query existing project networks'
	[[ -z "${containers}${volumes}${networks}" ]] || die \
		"refusing to reuse an existing Compose project; choose a fresh ZEUS_LINUX_ACCEPTANCE_PROJECT"
	container_names="$(docker container ls --all --format '{{.Names}}')" \
		|| die 'could not query exact container names'
	volume_names="$(docker volume ls --format '{{.Name}}')" \
		|| die 'could not query exact volume names'
	network_names="$(docker network ls --format '{{.Name}}')" \
		|| die 'could not query exact network names'
	name="${PROJECT}-data"
	line_list_contains "${name}" "${volume_names}" \
		&& die "refusing an exact-name collision with foreign or stale volume: ${name}"
	for name in "${PROJECT}-api-network" "${PROJECT}-web-network"; do
		line_list_contains "${name}" "${network_names}" \
			&& die "refusing an exact-name collision with foreign or stale network: ${name}"
	done
	for name in \
		"${PROJECT}-api-1" "${PROJECT}-web-1" "${PROJECT}-gateway-1" \
		"${PROJECT}_api_1" "${PROJECT}_web_1" "${PROJECT}_gateway_1"; do
		line_list_contains "${name}" "${container_names}" \
			&& die "refusing an exact-name collision with foreign or stale container: ${name}"
	done
	return 0
}

line_list_contains() {
	local needle="$1"
	local lines="$2"
	local line
	while IFS= read -r line; do
		[[ "${line}" == "${needle}" ]] && return 0
	done <<<"${lines}"
	return 1
}

cleanup_resources_are_owned() {
	local container_ids volume_ids network_ids container_names volume_names network_names id name
	docker info >/dev/null 2>&1 || return 1
	container_ids="$(docker container ls --all --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	volume_ids="$(docker volume ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	network_ids="$(docker network ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	container_names="$(docker container ls --all --format '{{.Names}}')" || return 1
	volume_names="$(docker volume ls --format '{{.Name}}')" || return 1
	network_names="$(docker network ls --format '{{.Name}}')" || return 1
	while IFS= read -r id; do
		[[ -n "${id}" ]] || continue
		docker inspect "${id}" | jq -e --arg project "${PROJECT}" '
			.[0] as $container
			| ($container.Name | ltrimstr("/")) as $name
			| $container.Config.Labels["com.docker.compose.project"] == $project
			and ($container.Config.Labels["com.docker.compose.service"] as $service
				| ($service == "api" or $service == "web" or $service == "gateway")
				and ($name == ($project + "-" + $service + "-1")
					or $name == ($project + "_" + $service + "_1")))
		' >/dev/null || return 1
	done <<<"${container_ids}"
	while IFS= read -r id; do
		[[ -n "${id}" ]] || continue
		[[ "${id}" == "${PROJECT}-data" ]] || return 1
		docker volume inspect "${id}" | jq -e --arg project "${PROJECT}" \
			'.[0].Labels["com.docker.compose.project"] == $project' >/dev/null \
			|| return 1
	done <<<"${volume_ids}"
	while IFS= read -r id; do
		[[ -n "${id}" ]] || continue
		name="$(docker network inspect "${id}" --format '{{.Name}}')" || return 1
		[[ "${name}" == "${PROJECT}-api-network" || "${name}" == "${PROJECT}-web-network" ]] \
			|| return 1
		docker network inspect "${id}" | jq -e --arg project "${PROJECT}" \
			'.[0].Labels["com.docker.compose.project"] == $project' >/dev/null \
			|| return 1
	done <<<"${network_ids}"
	name="${PROJECT}-data"
	if line_list_contains "${name}" "${volume_names}"; then
		docker volume inspect "${name}" | jq -e --arg project "${PROJECT}" \
			'.[0].Labels["com.docker.compose.project"] == $project' >/dev/null \
			|| return 1
	fi
	for name in "${PROJECT}-api-network" "${PROJECT}-web-network"; do
		if line_list_contains "${name}" "${network_names}"; then
			docker network inspect "${name}" | jq -e --arg project "${PROJECT}" \
				'.[0].Labels["com.docker.compose.project"] == $project' >/dev/null \
				|| return 1
		fi
	done
	for name in \
		"${PROJECT}-api-1" "${PROJECT}-web-1" "${PROJECT}-gateway-1" \
		"${PROJECT}_api_1" "${PROJECT}_web_1" "${PROJECT}_gateway_1"; do
		if line_list_contains "${name}" "${container_names}"; then
			docker container inspect "${name}" | jq -e --arg project "${PROJECT}" \
				'.[0].Config.Labels["com.docker.compose.project"] == $project' >/dev/null \
				|| return 1
		fi
	done
	return 0
}

verify_project_removed() {
	local container_ids volume_ids network_ids volume_names network_names container_names name
	docker info >/dev/null 2>&1 || return 1
	container_ids="$(docker container ls --all --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	volume_ids="$(docker volume ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	network_ids="$(docker network ls --quiet \
		--filter "label=com.docker.compose.project=${PROJECT}")" || return 1
	[[ -z "${container_ids}${volume_ids}${network_ids}" ]] || return 1
	container_names="$(docker container ls --all --format '{{.Names}}')" || return 1
	volume_names="$(docker volume ls --format '{{.Name}}')" || return 1
	network_names="$(docker network ls --format '{{.Name}}')" || return 1
	line_list_contains "${PROJECT}-data" "${volume_names}" && return 1
	for name in "${PROJECT}-api-network" "${PROJECT}-web-network"; do
		line_list_contains "${name}" "${network_names}" && return 1
	done
	for name in \
		"${PROJECT}-api-1" "${PROJECT}-web-1" "${PROJECT}-gateway-1" \
		"${PROJECT}_api_1" "${PROJECT}_web_1" "${PROJECT}_gateway_1"; do
		line_list_contains "${name}" "${container_names}" && return 1
	done
	return 0
}

sanitize_logs() {
	sed -E 's/(Zeus owner setup token \(expires [^)]*\):).*/\1 [REDACTED]/'
}

collect_logs() {
	local label="$1"
	local failed=0
	[[ "${STACK_TOUCHED}" == '1' && -n "${EVIDENCE_DIR}" ]] || return 0
	# The API log contains the one-time bootstrap secret on a fresh start. Keep
	# only a bounded, scrubbed diagnostic tail; never persist a complete log.
	compose logs --no-color --timestamps --tail 200 api 2>&1 \
		| sanitize_logs >"${EVIDENCE_DIR}/api-${label}.tail.log" || failed=1
	compose logs --no-color --timestamps --tail 200 web gateway \
		>"${EVIDENCE_DIR}/frontend-${label}.tail.log" 2>&1 || failed=1
	return "${failed}"
}

stop_run_logging() {
	[[ "${LOGGING_ACTIVE}" == '1' ]] || return 0
	exec 1>&3 2>&4
	LOGGING_ACTIVE=0
	[[ -n "${TEE_PID}" ]] || return 1
	wait "${TEE_PID}"
}

register_secret() {
	local secret="$1"
	ensure_xtrace_disabled
	[[ -n "${secret}" && "${secret}" != *$'\n'* ]] || return 1
	printf '%s\n' "${secret}" >>"${SECRET_PATTERN_FILE}"
}

register_cookie_secrets() {
	local cookie_jar="$1"
	[[ -f "${cookie_jar}" ]] || return 1
	awk -F '\t' 'NF >= 7 && length($7) > 0 { print $7 }' "${cookie_jar}" \
		>>"${SECRET_PATTERN_FILE}"
}

evidence_has_no_registered_secrets() {
	[[ -n "${SECRET_PATTERN_FILE}" && -f "${SECRET_PATTERN_FILE}" ]] || return 1
	[[ -s "${SECRET_PATTERN_FILE}" ]] || return 0
	grep -R -F -f "${SECRET_PATTERN_FILE}" -- "${EVIDENCE_DIR}" >/dev/null 2>&1
	local grep_status=$?
	case "${grep_status}" in
		0) return 1 ;;
		1) return 0 ;;
		*) return 1 ;;
	esac
}

reset_evidence_after_secret_scan_failure() {
	# Never leave a secret-bearing bundle under the directory uploaded by CI.
	# The path equality check makes the destructive target the exact one-run
	# evidence directory created by prepare_run, never its parent.
	[[ -n "${EVIDENCE_DIR}" \
		&& "${EVIDENCE_DIR}" == "${EVIDENCE_ROOT}/${PROJECT}" \
		&& -d "${EVIDENCE_DIR}" ]] || return 1
	if ! rm -rf -- "${EVIDENCE_DIR}"; then
		chmod -R 000 "${EVIDENCE_DIR}" >/dev/null 2>&1 || true
		return 1
	fi
	mkdir "${EVIDENCE_DIR}" || return 1
	jq -n '{status:"failed",reason:"registered_secret_detected",original_bundle_removed:true}' \
		>"${EVIDENCE_DIR}/secret-scan.json"
}

write_outcome() {
	local status="$1"
	local outcome
	if ((status == 0)); then
		outcome='passed'
	else
		outcome='failed'
	fi
	jq -n \
		--arg project "${PROJECT}" \
		--arg profile "${PROFILE}" \
		--arg status "${outcome}" \
		--argjson exit_code "${status}" \
		'{project:$project,profile:$profile,status:$status,exit_code:$exit_code}' \
		>"${EVIDENCE_DIR}/outcome.json"
}

write_evidence_manifest() {
	local files file temporary_manifest
	temporary_manifest="${EVIDENCE_DIR}/.SHA256SUMS.tmp"
	files="$(
		cd "${EVIDENCE_DIR}"
		find . -type f ! -name SHA256SUMS ! -name .SHA256SUMS.tmp -print | LC_ALL=C sort
	)" || return 1
	: >"${temporary_manifest}" || return 1
	while IFS= read -r file; do
		[[ -n "${file}" ]] || continue
		(cd "${EVIDENCE_DIR}" && sha256sum "${file}") >>"${temporary_manifest}" \
			|| return 1
	done <<<"${files}"
	mv "${temporary_manifest}" "${EVIDENCE_DIR}/SHA256SUMS"
}

cleanup_on_exit() {
	local status=$?
	local finalization_failed=0
	trap - EXIT INT TERM
	set +e
	set +x
	if [[ "${STACK_TOUCHED}" == '1' ]]; then
		collect_logs final || finalization_failed=1
		if cleanup_resources_are_owned; then
			log "removing only Compose project ${PROJECT}, including its acceptance volume"
			if ! compose down --volumes --remove-orphans --timeout 10 \
				>"${EVIDENCE_DIR}/cleanup.log" 2>&1; then
				log 'Compose teardown failed'
				finalization_failed=1
			fi
			if ! verify_project_removed; then
				log 'post-cleanup resource verification failed'
				finalization_failed=1
			fi
		else
			log "refusing cleanup because Docker inventory failed or an exact-name resource is not labeled for ${PROJECT}"
			finalization_failed=1
		fi
	fi
	((finalization_failed == 0)) || status=1
	if ! stop_run_logging; then
		printf '[zeus-linux-acceptance] error: could not finalize run.log\n' >&2
		status=1
	fi
	if [[ -n "${EVIDENCE_DIR}" && -d "${EVIDENCE_DIR}" ]]; then
		if ! evidence_has_no_registered_secrets; then
			printf '[zeus-linux-acceptance] error: evidence secret scan failed; removing the uploadable bundle\n' >&2
			status=1
			if ! reset_evidence_after_secret_scan_failure; then
				printf '[zeus-linux-acceptance] error: could not remove the secret-bearing evidence bundle\n' >&2
			fi
		fi
	fi
	if [[ -n "${TEMP_ROOT}" && -d "${TEMP_ROOT}" ]]; then
		if ! rm -rf -- "${TEMP_ROOT}"; then
			printf '[zeus-linux-acceptance] error: could not remove secret temporary directory\n' >&2
			status=1
		fi
	fi
	if [[ -n "${EVIDENCE_DIR}" && -d "${EVIDENCE_DIR}" ]]; then
		if ! write_outcome "${status}"; then
			printf '[zeus-linux-acceptance] error: could not write outcome evidence\n' >&2
			status=1
		fi
		if ! write_evidence_manifest; then
			printf '[zeus-linux-acceptance] error: could not write complete evidence manifest\n' >&2
			status=1
			write_outcome 1 >/dev/null 2>&1
		fi
	fi
	exit "${status}"
}

prepare_run() {
	local random_hex
	ensure_xtrace_disabled
	mkdir -p "${EVIDENCE_ROOT}"
	EVIDENCE_DIR="${EVIDENCE_ROOT}/${PROJECT}"
	[[ ! -e "${EVIDENCE_DIR}" ]] || die "evidence directory already exists: ${EVIDENCE_DIR}"
	mkdir "${EVIDENCE_DIR}"
	TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zeus-linux-acceptance.XXXXXX")"
	SECRET_PATTERN_FILE="${TEMP_ROOT}/registered-secrets.txt"
	: >"${SECRET_PATTERN_FILE}"
	trap cleanup_on_exit EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	random_hex="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
	[[ "${random_hex}" =~ ^[0-9a-f]{48}$ ]] || die 'could not generate an ephemeral owner password'
	OWNER_PASSWORD="Linux-${random_hex}-aA1!"
	OWNER_COOKIE_JAR="${TEMP_ROOT}/owner.cookies"
	register_secret "${OWNER_PASSWORD}"
	exec 3>&1 4>&2
	exec > >(tee -a "${EVIDENCE_DIR}/run.log" >&3) 2>&1
	TEE_PID=$!
	LOGGING_ACTIVE=1
}

render_config() {
	compose config
}

build_or_reuse_images() {
	if [[ "${REUSE_IMAGES}" == '1' ]]; then
		local image
		for image in "${API_IMAGE}" "${WEB_IMAGE}" "${GATEWAY_IMAGE}"; do
			docker image inspect "${image}" >/dev/null 2>&1 \
				|| die "reuse requested but image is missing: ${image}"
		done
		log 'reusing previously built release-runtime images'
		validate_image_provenance
		return
	fi
	log 'building API and Web runtime targets plus the Caddy gateway image'
	compose build --pull 2>&1 | tee "${EVIDENCE_DIR}/build.log"
	validate_image_provenance
}

validate_image_provenance() {
	local image role
	for role in api web gateway; do
		case "${role}" in
			api) image="${API_IMAGE}" ;;
			web) image="${WEB_IMAGE}" ;;
			gateway) image="${GATEWAY_IMAGE}" ;;
		esac
		docker image inspect "${image}" | jq -e \
			--arg commit "${SOURCE_COMMIT}" \
			--arg tree "${SOURCE_TREE}" \
			--arg role "${role}" '
			.[0].Config.Labels["dev.zeus-harness.source-commit"] == $commit
			and .[0].Config.Labels["dev.zeus-harness.source-tree"] == $tree
			and .[0].Config.Labels["dev.zeus-harness.acceptance-image"] == $role
		' >/dev/null || die "image provenance does not match clean source ${SOURCE_COMMIT}: ${image}"
	done
	log "verified image provenance for clean source ${SOURCE_COMMIT}"
}

write_environment_metadata() {
	local docker_server compose_version kernel api_image_id web_image_id gateway_image_id
	docker_server="$(docker version --format '{{.Server.Version}}')"
	compose_version="$(docker compose version)"
	kernel="$(uname -a)"
	api_image_id="$(docker image inspect "${API_IMAGE}" --format '{{.Id}}')"
	web_image_id="$(docker image inspect "${WEB_IMAGE}" --format '{{.Id}}')"
	gateway_image_id="$(docker image inspect "${GATEWAY_IMAGE}" --format '{{.Id}}')"
	jq -n \
		--arg project "${PROJECT}" \
		--arg profile "${PROFILE}" \
		--arg commit "${SOURCE_COMMIT}" \
		--arg tree "${SOURCE_TREE}" \
		--arg docker_server "${docker_server}" \
		--arg compose_version "${compose_version}" \
		--arg kernel "${kernel}" \
		--arg cgroup_driver "$(docker info --format '{{.CgroupDriver}}')" \
		--arg api_image "${API_IMAGE}" --arg api_image_id "${api_image_id}" \
		--arg web_image "${WEB_IMAGE}" --arg web_image_id "${web_image_id}" \
		--arg gateway_image "${GATEWAY_IMAGE}" --arg gateway_image_id "${gateway_image_id}" \
		--argjson api_cpus "${API_CPUS}" --arg api_memory "${API_MEMORY}" --argjson api_pids "${API_PIDS}" \
		--argjson web_cpus "${WEB_CPUS}" --arg web_memory "${WEB_MEMORY}" --argjson web_pids "${WEB_PIDS}" \
		--argjson gateway_cpus "${GATEWAY_CPUS}" --arg gateway_memory "${GATEWAY_MEMORY}" --argjson gateway_pids "${GATEWAY_PIDS}" \
		--argjson pressure_requests "${PRESSURE_REQUESTS}" --argjson pressure_concurrency "${PRESSURE_CONCURRENCY}" \
		'{project:$project,profile:$profile,source:{commit:$commit,tree:$tree,clean:true},runtime:{os_type:"linux",cgroup_version:2,cgroup_driver:$cgroup_driver,kernel:$kernel,docker_server:$docker_server,compose:$compose_version},build_toolchains:{rust:"1.97.1",node:"24.18.0",pnpm:"10.33.0"},images:{api:{name:$api_image,id:$api_image_id},web:{name:$web_image,id:$web_image_id},gateway:{name:$gateway_image,id:$gateway_image_id}},limits:{api:{cpus:$api_cpus,memory:$api_memory,pids:$api_pids},web:{cpus:$web_cpus,memory:$web_memory,pids:$web_pids},gateway:{cpus:$gateway_cpus,memory:$gateway_memory,pids:$gateway_pids}},operation_capacity:{max_concurrent_operations:2,reserved_progress_operations:1,acquire_timeout_ms:1},pressure:{requests:$pressure_requests,concurrency:$pressure_concurrency,request_pacing_ms:100}}' \
		>"${EVIDENCE_DIR}/environment.json"
}

wait_for_stack() {
	local attempt mapping port
	for ((attempt = 1; attempt <= 180; attempt += 1)); do
		mapping="$(compose port gateway 8080 2>/dev/null | tail -n 1 || true)"
		port="${mapping##*:}"
		if [[ "${mapping}" == 127.0.0.1:* && "${port}" =~ ^[1-9][0-9]*$ ]]; then
			BASE_URL="http://127.0.0.1:${port}"
			if curl --noproxy '*' --fail --silent --show-error \
				--connect-timeout 2 --max-time 3 "${BASE_URL}/health/ready" >/dev/null 2>&1 \
				&& curl --noproxy '*' --fail --silent --show-error \
					--connect-timeout 2 --max-time 3 "${BASE_URL}/" >/dev/null 2>&1; then
				log "stack is ready through loopback gateway ${BASE_URL}"
				return
			fi
		fi
		sleep 1
	done
	compose ps >&2 || true
	die 'the release-runtime stack did not become ready'
}

wait_for_readiness_recovery() {
	local attempt
	for ((attempt = 1; attempt <= 60; attempt += 1)); do
		if curl --noproxy '*' --fail --silent --show-error \
			--connect-timeout 2 --max-time 3 "${BASE_URL}/health/ready" >/dev/null 2>&1; then
			log 'readiness recovered to HTTP 200 after pressure'
			return
		fi
		sleep 0.25
	done
	die 'readiness did not recover to HTTP 200 after pressure'
}

container_id() {
	local service="$1"
	local id
	id="$(compose ps --quiet "${service}")"
	[[ -n "${id}" ]] || die "missing running container for service ${service}"
	printf '%s\n' "${id}"
}

assert_container_envelope() {
	local service="$1"
	local id="$2"
	local cpus="$3"
	local memory="$4"
	local pids="$5"
	local memory_limit uid cap_eff no_new_privs
	memory_limit="$(memory_bytes "${memory}")"

	docker inspect "${id}" | jq -e \
		--arg service "${service}" \
		--arg project "${PROJECT}" \
		--argjson cpus "${cpus}" \
		--argjson memory "${memory_limit}" \
		--argjson pids "${pids}" '
		.[0] as $container
		| $container.Config.Labels["com.docker.compose.service"] == $service
		and $container.Config.Labels["com.docker.compose.project"] == $project
		and $container.State.Status == "running"
		and $container.State.Running == true
		and $container.State.OOMKilled == false
		and $container.RestartCount == 0
		and $container.HostConfig.RestartPolicy.Name == "no"
		and $container.HostConfig.NanoCpus == ($cpus * 1000000000)
		and $container.HostConfig.Memory == $memory
		and $container.HostConfig.MemorySwap == $memory
		and $container.HostConfig.PidsLimit == $pids
		and $container.HostConfig.ReadonlyRootfs == true
		and ($container.HostConfig.CapDrop == ["ALL"])
		and (($container.HostConfig.SecurityOpt // [])
			| any(. == "no-new-privileges:true" or . == "no-new-privileges"))
		and ($container.Config.User | length > 0)
		and ($container.Config.User != "root")
		and ($container.Config.User != "0")
		and ($container.Config.User != "0:0")
	' >/dev/null || {
			docker inspect "${id}" | jq '.[0] | {
			service:.Config.Labels["com.docker.compose.service"],
			project:.Config.Labels["com.docker.compose.project"],
			state:.State,
			restart_count:.RestartCount,
			restart_policy:.HostConfig.RestartPolicy,
			user:.Config.User,
			cpus:.HostConfig.NanoCpus,
			memory:.HostConfig.Memory,
			memory_swap:.HostConfig.MemorySwap,
			pids:.HostConfig.PidsLimit,
			readonly:.HostConfig.ReadonlyRootfs,
			cap_drop:.HostConfig.CapDrop,
			security_opt:.HostConfig.SecurityOpt
		}' >&2
		die "${service} inspect envelope does not match the requested limits"
	}

	uid="$(docker exec "${id}" sh -eu -c 'id -u')"
	[[ "${uid}" =~ ^[1-9][0-9]*$ ]] || die "${service} is effectively running as root"
	cap_eff="$(docker exec "${id}" sh -eu -c "awk '/^CapEff:/{print \$2}' /proc/self/status")"
	[[ "${cap_eff}" == '0000000000000000' ]] || die "${service} retained effective capabilities: ${cap_eff}"
	no_new_privs="$(docker exec "${id}" sh -eu -c "awk '/^NoNewPrivs:/{print \$2}' /proc/self/status")"
	[[ "${no_new_privs}" == '1' ]] || die "${service} is missing no-new-privileges at runtime"

	docker exec "${id}" sh -eu -c \
		'test -r /sys/fs/cgroup/cgroup.controllers
		 controllers="$(cat /sys/fs/cgroup/cgroup.controllers)"
		 case " $controllers " in *" cpu "*) ;; *) exit 20;; esac
		 case " $controllers " in *" memory "*) ;; *) exit 21;; esac
		 case " $controllers " in *" pids "*) ;; *) exit 22;; esac' \
		|| die "${service} is not running with required cgroup v2 controllers"

	local cpu_max quota period memory_max swap_max pids_max expected_nanos
	cpu_max="$(docker exec "${id}" cat /sys/fs/cgroup/cpu.max)"
	read -r quota period <<<"${cpu_max}"
	[[ "${quota}" =~ ^[1-9][0-9]*$ && "${period}" =~ ^[1-9][0-9]*$ ]] \
		|| die "${service} does not have a finite cgroup v2 CPU limit: ${cpu_max}"
	expected_nanos="$(jq -nr --arg cpus "${cpus}" '$cpus|tonumber*1000000000|floor')"
	((quota * 1000000000 == expected_nanos * period)) \
		|| die "${service} cgroup CPU limit ${cpu_max} does not match ${cpus} CPUs"
	memory_max="$(docker exec "${id}" cat /sys/fs/cgroup/memory.max)"
	swap_max="$(docker exec "${id}" cat /sys/fs/cgroup/memory.swap.max)"
	local swap_current
	swap_current="$(docker exec "${id}" cat /sys/fs/cgroup/memory.swap.current)"
	pids_max="$(docker exec "${id}" cat /sys/fs/cgroup/pids.max)"
	[[ "${memory_max}" == "${memory_limit}" ]] \
		|| die "${service} cgroup memory.max ${memory_max} != ${memory_limit}"
	[[ "${swap_max}" == '0' ]] \
		|| die "${service} cgroup swap allowance is not zero: ${swap_max}"
	[[ "${swap_current}" == '0' ]] \
		|| die "${service} is consuming swap despite a zero-swap envelope: ${swap_current}"
	[[ "${pids_max}" == "${pids}" ]] \
		|| die "${service} cgroup pids.max ${pids_max} != ${pids}"
	log "verified ${service}: non-root, read-only, cap-drop, no-new-privileges, ${cpus} CPU/${memory}/no-swap/${pids} PID"
}

verify_topology_and_resources() {
	local evidence_label="${1:-current}"
	API_CONTAINER="$(container_id api)"
	WEB_CONTAINER="$(container_id web)"
	GATEWAY_CONTAINER="$(container_id gateway)"

	assert_container_envelope api "${API_CONTAINER}" "${API_CPUS}" "${API_MEMORY}" "${API_PIDS}"
	assert_container_envelope web "${WEB_CONTAINER}" "${WEB_CPUS}" "${WEB_MEMORY}" "${WEB_PIDS}"
	assert_container_envelope gateway "${GATEWAY_CONTAINER}" "${GATEWAY_CPUS}" "${GATEWAY_MEMORY}" "${GATEWAY_PIDS}"

	docker inspect "${API_CONTAINER}" | jq -e \
		--arg volume "${PROJECT}-data" \
		--arg network "${PROJECT}-api-network" '
		.[0] as $container
		| ([ $container.Mounts[]
			| select(.Type == "volume" and .Name == $volume and .Destination == "/var/lib/zeus" and .RW == true) ] | length == 1)
		and ([ $container.Mounts[] | select(.Type == "volume") ] | length == 1)
		and (($container.NetworkSettings.Networks | keys) == [$network])
		and (($container.HostConfig.PortBindings // {}) | length == 0)
	' >/dev/null || die 'API is not isolated to the single named SQLite volume and private network'
	docker inspect "${WEB_CONTAINER}" | jq -e \
		--arg network "${PROJECT}-web-network" '
		.[0] | ((.NetworkSettings.Networks | keys) == [$network])
		and ((.HostConfig.PortBindings // {}) | length == 0)
	' >/dev/null || die 'Web unexpectedly publishes a host port or joins another network'
	docker inspect "${GATEWAY_CONTAINER}" | jq -e \
		--arg api_network "${PROJECT}-api-network" \
		--arg web_network "${PROJECT}-web-network" '
		.[0] | ((.NetworkSettings.Networks | keys | sort) == ([$api_network, $web_network] | sort))
		and (.Config.User == "65532:65532")
		and (.HostConfig.PortBindings["8080/tcp"] | length == 1)
		and (.HostConfig.PortBindings["8080/tcp"][0].HostIp == "127.0.0.1")
		and (.HostConfig.PortBindings["8080/tcp"][0].HostPort | length > 0)
	' >/dev/null || die 'gateway is not an explicit non-root, loopback-only publisher'
	docker volume inspect "${PROJECT}-data" | jq -e \
		--arg project "${PROJECT}" '.[0].Labels["com.docker.compose.project"] == $project' >/dev/null \
		|| die 'SQLite volume does not belong to this Compose project'
	local network
	for network in "${PROJECT}-api-network" "${PROJECT}-web-network"; do
		docker network inspect "${network}" | jq -e \
			--arg project "${PROJECT}" '
			.[0].Labels["com.docker.compose.project"] == $project
			and .[0].Internal == true
		' >/dev/null || die "internal acceptance network does not belong to this Compose project: ${network}"
	done

	jq -n \
		--arg project "${PROJECT}" \
		--arg api "${API_CONTAINER}" \
		--arg web "${WEB_CONTAINER}" \
		--arg gateway "${GATEWAY_CONTAINER}" \
		--arg base_url "${BASE_URL}" \
		'{project:$project,containers:{api:$api,web:$web,gateway:$gateway},gateway:$base_url}' \
		>"${EVIDENCE_DIR}/topology-${evidence_label}.json"
	docker inspect "${API_CONTAINER}" "${WEB_CONTAINER}" "${GATEWAY_CONTAINER}" | jq '[.[] | {
		service:.Config.Labels["com.docker.compose.service"],
		project:.Config.Labels["com.docker.compose.project"],
		image:.Image,
		user:.Config.User,
		state:{status:.State.Status,running:.State.Running,oom_killed:.State.OOMKilled},
		restart_count:.RestartCount,
		restart_policy:.HostConfig.RestartPolicy.Name,
		resources:{nano_cpus:.HostConfig.NanoCpus,memory:.HostConfig.Memory,memory_swap:.HostConfig.MemorySwap,pids_limit:.HostConfig.PidsLimit},
		security:{read_only:.HostConfig.ReadonlyRootfs,cap_drop:.HostConfig.CapDrop,security_opt:.HostConfig.SecurityOpt},
		mounts:[.Mounts[] | {type:.Type,name:.Name,destination:.Destination,rw:.RW}],
		networks:(.NetworkSettings.Networks | keys),
		port_bindings:.HostConfig.PortBindings
	}]' >"${EVIDENCE_DIR}/container-envelopes-${evidence_label}.json"
}

sample_service_resources() {
	local service="$1"
	local id="$2"
	local phase="$3"
	local raw timestamp memory_current memory_peak swap_current swap_max oom oom_kill pids_current pids_max pids_events_max
	local cpu_usage_usec cpu_nr_throttled cpu_throttled_usec docker_stats
	raw="$(docker exec "${id}" sh -eu -c '
		counter() { awk -v key="$1" '\''$1 == key { print $2; found=1 } END { if (!found) exit 1 }'\'' "$2"; }
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
			"$(cat /sys/fs/cgroup/memory.current)" \
			"$(cat /sys/fs/cgroup/memory.peak)" \
			"$(cat /sys/fs/cgroup/memory.swap.current)" \
			"$(cat /sys/fs/cgroup/memory.swap.max)" \
			"$(counter oom /sys/fs/cgroup/memory.events)" \
			"$(counter oom_kill /sys/fs/cgroup/memory.events)" \
			"$(cat /sys/fs/cgroup/pids.current)" \
			"$(cat /sys/fs/cgroup/pids.max)" \
			"$(counter max /sys/fs/cgroup/pids.events)" \
			"$(counter usage_usec /sys/fs/cgroup/cpu.stat)" \
			"$(counter nr_throttled /sys/fs/cgroup/cpu.stat)" \
			"$(counter throttled_usec /sys/fs/cgroup/cpu.stat)"
	')"
	IFS=$'\t' read -r memory_current memory_peak swap_current swap_max oom oom_kill pids_current pids_max pids_events_max cpu_usage_usec cpu_nr_throttled cpu_throttled_usec <<<"${raw}"
	[[ "${swap_current}" == '0' ]] || die "${service} used swap during ${phase}: ${swap_current} bytes"
	docker_stats="$(docker stats --no-stream --format '{{json .}}' "${id}")"
	jq -e 'type == "object"' <<<"${docker_stats}" >/dev/null \
		|| die "docker stats did not return JSON for ${service} during ${phase}"
	timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
	jq -cn \
		--arg timestamp "${timestamp}" \
		--arg phase "${phase}" \
		--arg service "${service}" \
		--arg container_id "${id}" \
		--argjson memory_current "${memory_current}" \
		--argjson memory_peak "${memory_peak}" \
		--argjson swap_current "${swap_current}" \
		--argjson swap_max "${swap_max}" \
		--argjson oom "${oom}" \
		--argjson oom_kill "${oom_kill}" \
		--argjson pids_current "${pids_current}" \
		--argjson pids_max "${pids_max}" \
		--argjson pids_events_max "${pids_events_max}" \
		--argjson cpu_usage_usec "${cpu_usage_usec}" \
		--argjson cpu_nr_throttled "${cpu_nr_throttled}" \
		--argjson cpu_throttled_usec "${cpu_throttled_usec}" \
		--argjson docker_stats "${docker_stats}" \
		'{timestamp:$timestamp,phase:$phase,service:$service,container_id:$container_id,memory_current:$memory_current,memory_peak:$memory_peak,swap_current:$swap_current,swap_max:$swap_max,oom:$oom,oom_kill:$oom_kill,pids_current:$pids_current,pids_max:$pids_max,pids_events_max:$pids_events_max,cpu_stat:{usage_usec:$cpu_usage_usec,nr_throttled:$cpu_nr_throttled,throttled_usec:$cpu_throttled_usec},docker_stats:$docker_stats}' \
		>>"${EVIDENCE_DIR}/resource-timeseries.jsonl"
}

sample_all_resources() {
	local phase="$1"
	[[ -n "${API_CONTAINER}" ]] || API_CONTAINER="$(container_id api)"
	[[ -n "${WEB_CONTAINER}" ]] || WEB_CONTAINER="$(container_id web)"
	[[ -n "${GATEWAY_CONTAINER}" ]] || GATEWAY_CONTAINER="$(container_id gateway)"
	sample_service_resources api "${API_CONTAINER}" "${phase}"
	sample_service_resources web "${WEB_CONTAINER}" "${phase}"
	sample_service_resources gateway "${GATEWAY_CONTAINER}" "${phase}"
}

assert_resource_phase_zero() {
	local phase="$1"
	jq -se --arg phase "${phase}" '
		[.[] | select(.phase == $phase)] as $samples
		| ($samples | length) == 3
		and (($samples | map(.service) | sort) == ["api", "gateway", "web"])
		and all($samples[];
			.oom == 0
			and .oom_kill == 0
			and .pids_events_max == 0
			and .swap_current == 0)
	' "${EVIDENCE_DIR}/resource-timeseries.jsonl" >/dev/null || {
		jq -s --arg phase "${phase}" '[.[] | select(.phase == $phase)]' \
			"${EVIDENCE_DIR}/resource-timeseries.jsonl" >&2 || true
		die "${phase} did not contain zero fresh counters for all three services"
	}
	jq -cn --arg phase "${phase}" \
		'{assertion:"fresh_cgroup_counters_zero",phase:$phase,services:["api","web","gateway"],oom:0,oom_kill:0,pids_events_max:0,swap_current:0}' \
		>>"${EVIDENCE_DIR}/resource-counter-assertions.jsonl"
	log "verified ${phase}: all three services started with zero OOM, OOM-kill, PID-max, and swap-current counters"
}

assert_resource_phase_stable() {
	local before_phase="$1"
	local after_phase="$2"
	local summary
	summary="$(jq -cse --arg before "${before_phase}" --arg after "${after_phase}" '
		def samples($phase): [.[] | select(.phase == $phase)] | sort_by(.service);
		samples($before) as $before_samples
		| samples($after) as $after_samples
		| select(($before_samples | length) == 3 and ($after_samples | length) == 3)
		| select(($before_samples | map(.service)) == ["api", "gateway", "web"])
		| select(($after_samples | map(.service)) == ["api", "gateway", "web"])
		| [range(0; 3) as $index
			| {
				service:$before_samples[$index].service,
				oom:{before:$before_samples[$index].oom,after:$after_samples[$index].oom},
				oom_kill:{before:$before_samples[$index].oom_kill,after:$after_samples[$index].oom_kill},
				pids_events_max:{before:$before_samples[$index].pids_events_max,after:$after_samples[$index].pids_events_max},
				swap_current:{before:$before_samples[$index].swap_current,after:$after_samples[$index].swap_current},
				stable:(
					$before_samples[$index].oom == $after_samples[$index].oom
					and $before_samples[$index].oom_kill == $after_samples[$index].oom_kill
					and $before_samples[$index].pids_events_max == $after_samples[$index].pids_events_max
					and $before_samples[$index].swap_current == 0
					and $after_samples[$index].swap_current == 0)
			}
		] as $services
		| {assertion:"no_counter_growth",before_phase:$before,after_phase:$after,services:$services}
		| select(all(.services[]; .stable == true))
	' "${EVIDENCE_DIR}/resource-timeseries.jsonl")" \
		|| die "resource counters grew or samples were incomplete from ${before_phase} to ${after_phase}"
	printf '%s\n' "${summary}" >>"${EVIDENCE_DIR}/resource-counter-assertions.jsonl"
	log "verified all three services had no OOM, OOM-kill, PID-max, or swap growth from ${before_phase} to ${after_phase}"
}

assert_during_pressure_samples() {
	local summary
	summary="$(jq -cse '
		[.[] | select(.phase == "during-pressure")]
		| group_by(.service)
		| map({service:.[0].service,samples:length})
		| sort_by(.service)
		| select(map(.service) == ["api", "gateway", "web"])
		| select(all(.[]; .samples >= 2))
		| {assertion:"during_pressure_samples_present",services:.}
	' "${EVIDENCE_DIR}/resource-timeseries.jsonl")" \
		|| die 'fewer than two during-pressure resource samples were captured for one or more services'
	printf '%s\n' "${summary}" >>"${EVIDENCE_DIR}/resource-counter-assertions.jsonl"
}

extract_bootstrap_token() {
	local token
	for _ in {1..30}; do
		token="$(compose logs --no-color api 2>/dev/null \
			| sed -nE 's/.*Zeus owner setup token \(expires [^)]*\): ([^[:space:]]+).*/\1/p' \
			| tail -n 1)"
		if [[ -n "${token}" ]]; then
			printf '%s\n' "${token}"
			return
		fi
		sleep 1
	done
	die 'fresh API did not emit a bootstrap token'
}

curl_json_status() {
	local method="$1"
	local url="$2"
	local request_file="$3"
	local response_file="$4"
	shift 4
	curl --noproxy '*' --silent --show-error \
		--connect-timeout 3 --max-time 30 \
		--request "${method}" \
		--header 'Accept: application/json' \
		--header 'Content-Type: application/json' \
		--header "Origin: ${BASE_URL}" \
		--data-binary "@${request_file}" \
		--output "${response_file}" \
		--write-out '%{http_code}' \
		"$@" "${url}"
}

verify_fresh_anonymous_boundary() {
	local auth_response overview_response auth_status overview_status
	auth_response="${TEMP_ROOT}/fresh-auth-status.json"
	overview_response="${TEMP_ROOT}/fresh-overview.json"
	auth_status="$(curl --noproxy '*' --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		--header 'Accept: application/json' \
		--output "${auth_response}" --write-out '%{http_code}' \
		"${BASE_URL}/api/v1/auth/status")"
	[[ "${auth_status}" == '200' ]] || die "fresh anonymous auth status returned ${auth_status}"
	jq -e '
		.configured == false
		and .authenticated == false
		and (.user == null)
		and (.preferences == null)
	' "${auth_response}" >/dev/null || die 'fresh anonymous auth status did not prove an unconfigured instance'
	overview_status="$(curl --noproxy '*' --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		--header 'Accept: application/json' \
		--output "${overview_response}" --write-out '%{http_code}' \
		"${BASE_URL}/api/v1/overview")"
	[[ "${overview_status}" == '401' ]] || die "fresh anonymous overview returned ${overview_status}"
	jq -e '.code == "authentication_required"' "${overview_response}" >/dev/null \
		|| die 'fresh protected overview did not return the authentication_required surface'
	jq -n '{auth_status:200,configured:false,authenticated:false,protected_overview_status:401,problem_code:"authentication_required"}' \
		>"${EVIDENCE_DIR}/fresh-anonymous-boundary.json"
	log 'verified fresh unconfigured auth status and protected anonymous 401 boundary'
}

bootstrap_and_verify_reply() {
	local bootstrap_token bootstrap_request bootstrap_response cookie_jar status csrf csrf_header session_request session_response turn_request turn_response detail
	ensure_xtrace_disabled
	bootstrap_token="$(extract_bootstrap_token)"
	register_secret "${bootstrap_token}"
	bootstrap_request="${TEMP_ROOT}/bootstrap-request.json"
	bootstrap_response="${TEMP_ROOT}/bootstrap-response.json"
	cookie_jar="${OWNER_COOKIE_JAR}"
	printf '%s\0%s\0' "${bootstrap_token}" "${OWNER_PASSWORD}" \
		| jq -Rs 'split("\u0000") | {bootstrap_token:.[0],username:"owner",password:.[1]}' \
		>"${bootstrap_request}"
	bootstrap_token=''
	status="$(curl_json_status POST "${BASE_URL}/api/v1/auth/bootstrap" \
		"${bootstrap_request}" "${bootstrap_response}" --cookie-jar "${cookie_jar}")"
	[[ "${status}" == '200' ]] || die "owner bootstrap returned ${status}"
	csrf="$(jq -er '.csrf_token | select(length > 20)' "${bootstrap_response}")"
	register_secret "${csrf}"
	register_cookie_secrets "${cookie_jar}"
	csrf_header="${TEMP_ROOT}/csrf.header"
	printf 'X-CSRF-Token: %s\n' "${csrf}" >"${csrf_header}"

	session_request="${TEMP_ROOT}/session-request.json"
	session_response="${TEMP_ROOT}/session-response.json"
	jq -n '{id:"session-linux-acceptance",title:"Linux container acceptance"}' >"${session_request}"
	status="$(curl_json_status POST "${BASE_URL}/api/v1/sessions" \
		"${session_request}" "${session_response}" \
		--cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
		--header "@${csrf_header}" \
		--header 'Idempotency-Key: linux-acceptance-create-session')"
	[[ "${status}" == '201' ]] || die "Session creation returned ${status}"
	jq -e '.session.id == "session-linux-acceptance" and .session.sequence == 1' \
		"${session_response}" >/dev/null || die 'Session creation response was malformed'

	turn_request="${TEMP_ROOT}/turn-request.json"
	turn_response="${TEMP_ROOT}/turn-response.json"
	jq -n '{turn_id:"turn-linux-acceptance",user_message:"Confirm Linux release-runtime acceptance.",expected_sequence:1}' >"${turn_request}"
	status="$(curl_json_status POST "${BASE_URL}/api/v1/sessions/session-linux-acceptance/turns" \
		"${turn_request}" "${turn_response}" \
		--cookie "${cookie_jar}" --cookie-jar "${cookie_jar}" \
		--header "@${csrf_header}" \
		--header 'Idempotency-Key: linux-acceptance-start-turn')"
	[[ "${status}" == '202' ]] || die "turn enqueue returned ${status}"

	detail="${TEMP_ROOT}/session-detail.json"
	local attempt
	for ((attempt = 1; attempt <= 120; attempt += 1)); do
		status="$(curl --noproxy '*' --silent --show-error \
			--connect-timeout 2 --max-time 5 \
			--cookie "${cookie_jar}" \
			--header 'Accept: application/json' \
			--output "${detail}" --write-out '%{http_code}' \
			"${BASE_URL}/api/v1/sessions/session-linux-acceptance")"
		if [[ "${status}" == '200' ]] && jq -e '
			.session.status == "ready"
			and .session.sequence == 4
			and ([.events[].sequence] == [1, 2, 3, 4])
			and any(.turns[];
				.id == "turn-linux-acceptance"
				and .status == "flushed"
			and .assistant_message == "Your message was saved, but no model provider is configured.")
		' "${detail}" >/dev/null; then
			register_cookie_secrets "${cookie_jar}"
			jq '{session_id:.session.id,status:.session.status,sequence:.session.sequence,
				turn:(.turns[] | select(.id == "turn-linux-acceptance") | {id,status,assistant_message})}' \
				"${detail}" >"${EVIDENCE_DIR}/functional-reply.json"
			log 'verified owner bootstrap, durable Session/turn, and local-fallback settlement'
			return
		fi
		sleep 0.25
	done
	die 'local-fallback turn did not settle to ready'
}

verify_two_concurrent_invalid_logins() {
	local index status pid
	local pids=()
	for index in 1 2; do
		jq -n \
			--arg username "missing-linux-${index}" \
			--arg password 'Wrong-linux-password-2026!' \
			'{username:$username,password:$password}' >"${TEMP_ROOT}/invalid-login-${index}.request.json"
		(
			curl_json_status POST "${BASE_URL}/api/v1/auth/login" \
				"${TEMP_ROOT}/invalid-login-${index}.request.json" \
				"${TEMP_ROOT}/invalid-login-${index}.response.json" \
				>"${TEMP_ROOT}/invalid-login-${index}.status"
		) &
		pids+=("$!")
	done
	for pid in "${pids[@]}"; do
		wait "${pid}"
	done
	for index in 1 2; do
		status="$(<"${TEMP_ROOT}/invalid-login-${index}.status")"
		[[ "${status}" == '401' ]] || die "concurrent invalid login ${index} returned ${status}"
		jq -e '.code == "invalid_credentials"' \
			"${TEMP_ROOT}/invalid-login-${index}.response.json" >/dev/null \
			|| die "concurrent invalid login ${index} did not preserve the indistinguishable 401 surface"
	done
	jq -n '{concurrency:2,responses:[401,401],problem_code:"invalid_credentials"}' \
		>"${EVIDENCE_DIR}/argon-invalid-login.json"
	log 'verified two concurrent invalid Argon2 login paths under the configured memory ceiling'
}

pressure_worker() {
	local worker="$1"
	local result_file="${TEMP_ROOT}/pressure-${worker}.results"
	local body_file="${TEMP_ROOT}/pressure-${worker}.body"
	local request code curl_status compact
	: >"${result_file}"
	for ((request = worker; request <= PRESSURE_REQUESTS; request += PRESSURE_CONCURRENCY)); do
		set +e
		code="$(curl --noproxy '*' --silent --show-error \
			--connect-timeout 2 --max-time 10 \
			--header 'Accept: application/json' \
			--output "${body_file}" --write-out '%{http_code}' \
			"${BASE_URL}/health/ready" 2>/dev/null)"
		curl_status=$?
		set -e
		if ((curl_status != 0)); then
			printf 'transport\n' >>"${result_file}"
		elif [[ "${code}" == '200' ]]; then
			printf '200\n' >>"${result_file}"
		elif [[ "${code}" == '503' ]] \
			&& jq -e '.code == "sqlite_operation_capacity_exceeded"' "${body_file}" >/dev/null 2>&1; then
			printf '503_capacity\n' >>"${result_file}"
		else
			compact="$(jq -c . "${body_file}" 2>/dev/null || tr '\n' ' ' <"${body_file}" | cut -c 1-300)"
			printf 'unexpected|%s|%s\n' "${code:-none}" "${compact}" >>"${result_file}"
		fi
		# Keep the fixed request stream observable long enough for multiple
		# three-service cgroup snapshots without reducing request concurrency.
		sleep 0.1
	done
}

run_readiness_pressure() {
	local worker pid started_at ended_at started_ns ended_ns duration_ms
	local pids=()
	started_at="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
	started_ns="$(date +%s%N)"
	for ((worker = 1; worker <= PRESSURE_CONCURRENCY; worker += 1)); do
		pressure_worker "${worker}" &
		pids+=("$!")
	done
	: >"${TEMP_ROOT}/pressure.started"
	for pid in "${pids[@]}"; do
		wait "${pid}"
	done
	: >"${TEMP_ROOT}/pressure.finished"
	ended_ns="$(date +%s%N)"
	ended_at="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
	duration_ms="$(((ended_ns - started_ns) / 1000000))"
	cat "${TEMP_ROOT}"/pressure-*.results >"${TEMP_ROOT}/pressure.results"

	local ok capacity transport unexpected total
	ok="$(grep -c '^200$' "${TEMP_ROOT}/pressure.results" || true)"
	capacity="$(grep -c '^503_capacity$' "${TEMP_ROOT}/pressure.results" || true)"
	transport="$(grep -c '^transport$' "${TEMP_ROOT}/pressure.results" || true)"
	unexpected="$(grep -c '^unexpected|' "${TEMP_ROOT}/pressure.results" || true)"
	total="$((ok + capacity + transport + unexpected))"
	jq -n \
		--argjson requested "${PRESSURE_REQUESTS}" \
		--argjson concurrency "${PRESSURE_CONCURRENCY}" \
		--argjson total "${total}" \
		--argjson ok "${ok}" \
		--argjson capacity "${capacity}" \
		--argjson transport "${transport}" \
		--argjson unexpected "${unexpected}" \
		--argjson request_pacing_ms 100 \
		--arg started_at "${started_at}" \
		--arg ended_at "${ended_at}" \
		--argjson duration_ms "${duration_ms}" \
		'{requested:$requested,concurrency:$concurrency,request_pacing_ms:$request_pacing_ms,started_at:$started_at,ended_at:$ended_at,duration_ms:$duration_ms,total:$total,http_200:$ok,sqlite_capacity_503:$capacity,transport_errors:$transport,unexpected:$unexpected}' \
		>"${EVIDENCE_DIR}/readiness-pressure.json"
	[[ "${total}" == "${PRESSURE_REQUESTS}" ]] || die "pressure result count ${total} != ${PRESSURE_REQUESTS}"
	((transport == 0)) || die "readiness pressure had ${transport} transport errors"
	((unexpected == 0)) || {
		grep '^unexpected|' "${TEMP_ROOT}/pressure.results" | head -n 10 >&2 || true
		die "readiness pressure had ${unexpected} unexpected responses"
	}
	((ok > 0)) || die 'readiness pressure produced no successful 200 response'
	((capacity > 0)) || die 'readiness pressure did not exercise sqlite_operation_capacity_exceeded'
	log "readiness pressure passed: ${ok} HTTP 200 and ${capacity} expected capacity 503 responses"
}

verify_pressure_resource_stability() {
	assert_resource_phase_stable fresh-baseline before-pressure
	assert_resource_phase_stable before-pressure after-pressure
}

verify_volume_restart() {
	local configured login_request login_response restart_cookie status restart_csrf detail volume_before volume_after old_auth
	volume_before="$(docker volume inspect "${PROJECT}-data" --format '{{.Name}}')"
	collect_logs before-restart
	compose down --remove-orphans --timeout 10
	[[ "$(docker volume inspect "${PROJECT}-data" --format '{{.Name}}')" == "${volume_before}" ]] \
		|| die 'SQLite volume was not retained across the restart boundary'
	compose up --detach --no-build
	wait_for_stack
	verify_topology_and_resources restarted
	sample_all_resources restart-baseline
	assert_resource_phase_zero restart-baseline
	volume_after="$(docker volume inspect "${PROJECT}-data" --format '{{.Name}}')"
	[[ "${volume_after}" == "${volume_before}" ]] || die 'restart attached a different SQLite volume'
	configured="$(curl --noproxy '*' --fail --silent --show-error \
		--connect-timeout 2 --max-time 5 "${BASE_URL}/api/v1/auth/status" | jq -r '.configured')"
	[[ "${configured}" == 'true' ]] || die 'owner configuration was not retained after restart'
	if compose logs --no-color api 2>&1 | grep -q 'Zeus owner setup token'; then
		die 'configured restart unexpectedly minted a new bootstrap token'
	fi
	old_auth="${TEMP_ROOT}/restart-old-auth-status.json"
	status="$(curl --noproxy '*' --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		--cookie "${OWNER_COOKIE_JAR}" --header 'Accept: application/json' \
		--output "${old_auth}" --write-out '%{http_code}' \
		"${BASE_URL}/api/v1/auth/status")"
	[[ "${status}" == '200' ]] || die "retained auth Session check returned ${status}"
	jq -e '.configured == true and .authenticated == true and .user.username == "owner"' \
		"${old_auth}" >/dev/null || die 'the pre-restart owner auth Session was not retained'
	status="$(curl --noproxy '*' --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		--cookie "${OWNER_COOKIE_JAR}" --header 'Accept: application/json' \
		--output "${TEMP_ROOT}/restart-old-auth-session.json" --write-out '%{http_code}' \
		"${BASE_URL}/api/v1/sessions/session-linux-acceptance")"
	[[ "${status}" == '200' ]] || die "pre-restart auth Session could not read the retained Zeus Session: ${status}"

	login_request="${TEMP_ROOT}/restart-login.request.json"
	login_response="${TEMP_ROOT}/restart-login.response.json"
	restart_cookie="${TEMP_ROOT}/restart-owner.cookies"
	ensure_xtrace_disabled
	printf '%s\0' "${OWNER_PASSWORD}" \
		| jq -Rs 'split("\u0000") | {username:"owner",password:.[0]}' \
		>"${login_request}"
	status="$(curl_json_status POST "${BASE_URL}/api/v1/auth/login" \
		"${login_request}" "${login_response}" --cookie-jar "${restart_cookie}")"
	[[ "${status}" == '200' ]] || die "owner login after restart returned ${status}"
	restart_csrf="$(jq -er '.csrf_token | select(length > 20)' "${login_response}")"
	[[ -n "${restart_csrf}" ]] || die 'restart login omitted CSRF token'
	register_secret "${restart_csrf}"
	register_cookie_secrets "${restart_cookie}"
	detail="${TEMP_ROOT}/restart-session-detail.json"
	status="$(curl --noproxy '*' --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		--cookie "${restart_cookie}" --header 'Accept: application/json' \
		--output "${detail}" --write-out '%{http_code}' \
		"${BASE_URL}/api/v1/sessions/session-linux-acceptance")"
	[[ "${status}" == '200' ]] || die "persisted Session read after restart returned ${status}"
	jq -e '
		.session.status == "ready"
		and .session.sequence == 4
		and ([.events[].sequence] == [1, 2, 3, 4])
		and any(.turns[];
			.id == "turn-linux-acceptance"
			and .status == "flushed"
			and .assistant_message == "Your message was saved, but no model provider is configured.")
	' "${detail}" >/dev/null || die 'persisted Session/turn was not intact after restart'
	jq -n \
		--arg volume "${volume_after}" \
		'{configured:true,pre_restart_auth_session_retained:true,new_login:true,session:"session-linux-acceptance",turn:"turn-linux-acceptance",volume:$volume}' \
		>"${EVIDENCE_DIR}/restart-persistence.json"
	sample_all_resources restart-final
	assert_resource_phase_stable restart-baseline restart-final
	log 'verified retained SQLite volume, pre-restart auth cookie, new login, and sequence 1-4 Session continuity after recreate'
}

run_acceptance() {
	local pressure_pid marker_attempt
	prepare_run
	assert_project_unused
	log "project=${PROJECT} profile=${PROFILE} evidence=${EVIDENCE_DIR}"
	render_config >"${EVIDENCE_DIR}/compose-config.yaml"
	build_or_reuse_images
	write_environment_metadata
	STACK_TOUCHED=1
	compose up --detach --no-build
	wait_for_stack
	verify_topology_and_resources initial
	sample_all_resources fresh-baseline
	assert_resource_phase_zero fresh-baseline
	verify_fresh_anonymous_boundary
	bootstrap_and_verify_reply
	verify_two_concurrent_invalid_logins
	sample_all_resources after-argon
	sample_all_resources before-pressure
	run_readiness_pressure &
	pressure_pid=$!
	for ((marker_attempt = 1; marker_attempt <= 100; marker_attempt += 1)); do
		[[ -f "${TEMP_ROOT}/pressure.started" ]] && break
		kill -0 "${pressure_pid}" >/dev/null 2>&1 \
			|| die 'readiness pressure exited before it started'
		sleep 0.01
	done
	[[ -f "${TEMP_ROOT}/pressure.started" ]] || die 'readiness pressure did not publish its start marker'
	[[ ! -f "${TEMP_ROOT}/pressure.finished" ]] \
		|| die 'readiness pressure completed before live resource sampling began'
	kill -0 "${pressure_pid}" >/dev/null 2>&1 \
		|| die 'readiness pressure was not running when live resource sampling began'
	sample_all_resources during-pressure
	while [[ ! -f "${TEMP_ROOT}/pressure.finished" ]] \
		&& kill -0 "${pressure_pid}" >/dev/null 2>&1; do
		sleep 1
		if [[ ! -f "${TEMP_ROOT}/pressure.finished" ]] \
			&& kill -0 "${pressure_pid}" >/dev/null 2>&1; then
			sample_all_resources during-pressure
		fi
	done
	wait "${pressure_pid}"
	assert_during_pressure_samples
	wait_for_readiness_recovery
	sample_all_resources after-pressure
	verify_pressure_resource_stability
	verify_topology_and_resources post-pressure
	verify_volume_restart
	collect_logs passed
	log "Linux release-runtime acceptance passed; evidence: ${EVIDENCE_DIR}"
}

usage() {
	cat <<'EOF'
Usage: scripts/linux-container-acceptance.sh <command>

Commands:
  config  Validate prerequisites and render the isolated acceptance Compose model.
  run     Build/reuse release images, run live acceptance, retain evidence, then clean the stack and volume.

The default project is unique and begins with zeus-linux-acceptance-. An explicit
ZEUS_LINUX_ACCEPTANCE_PROJECT must keep that prefix. Only resources carrying the
exact Compose project label are considered, and an existing project is rejected.

Important overrides:
  ZEUS_LINUX_ACCEPTANCE_PROFILE=normal|low-memory
  ZEUS_LINUX_ACCEPTANCE_IMAGE_PREFIX, _REUSE_IMAGES=0|1

The normal and low-memory resource and pressure values are fixed authoritative
contracts. Supplying a mismatched resource or pressure override is rejected.
Both config and run require a clean Git worktree and bind image provenance to
the exact HEAD commit and tree.

Evidence is written below .zeus-linux-acceptance/. Bootstrap tokens, passwords,
cookies and CSRF tokens remain only in private process state and a mode-0700
temporary directory; they are never written to the evidence bundle or console.
EOF
}

validate_configuration
command="${1:-help}"
shift || true
case "${command}" in
	config)
		preflight
		prepare_source_identity
		render_config "$@"
		;;
	run)
		preflight
		prepare_source_identity
		run_acceptance "$@"
		;;
	help | --help | -h)
		usage
		;;
	*)
		usage >&2
		die "unknown command: ${command}"
		;;
esac
