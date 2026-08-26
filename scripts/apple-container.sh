#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT="${ZEUS_CONTAINER_PROJECT:-zeus-alpha}"
PLATFORM="${ZEUS_CONTAINER_PLATFORM:-linux/arm64}"
BUILD_CPUS="${ZEUS_CONTAINER_BUILD_CPUS:-4}"
BUILD_MEMORY="${ZEUS_CONTAINER_BUILD_MEMORY:-6G}"
BUILD_CONTEXT_ROOT="${ZEUS_CONTAINER_BUILD_CONTEXT_ROOT:-${REPO_ROOT}}"

API_IMAGE="${ZEUS_CONTAINER_API_IMAGE:-${PROJECT}-api:local}"
WEB_IMAGE="${ZEUS_CONTAINER_WEB_IMAGE:-${PROJECT}-web:local}"
GATEWAY_IMAGE="${ZEUS_CONTAINER_GATEWAY_IMAGE:-${PROJECT}-gateway:local}"

API_CONTAINER="${PROJECT}-api"
WEB_CONTAINER="${PROJECT}-web"
GATEWAY_CONTAINER="${PROJECT}-gateway"
INIT_CONTAINER="${PROJECT}-volume-init"
NETWORK="${PROJECT}-net"
DATA_VOLUME="${PROJECT}-data"

HTTP_PORT="${ZEUS_CONTAINER_HTTP_PORT:-18088}"
COOKIE_SECURE="${ZEUS_COOKIE_SECURE:-false}"
LLM_ENDPOINT="${ZEUS_LLM_ENDPOINT:-}"
LLM_MODEL="${ZEUS_LLM_MODEL:-}"
LLM_API_KEY="${ZEUS_LLM_API_KEY:-}"
MAX_SESSIONS_PER_SCOPE="${ZEUS_MAX_SESSIONS_PER_SCOPE-1000}"
MAX_SESSIONS_GLOBAL="${ZEUS_MAX_SESSIONS_GLOBAL-10000}"
MAX_OPEN_TURNS_PER_SCOPE="${ZEUS_MAX_OPEN_TURNS_PER_SCOPE-32}"
MAX_OPEN_TURNS_GLOBAL="${ZEUS_MAX_OPEN_TURNS_GLOBAL-64}"
MAX_ACTIVE_REPLY_JOBS_PER_SCOPE="${ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_SCOPE-32}"
MAX_ACTIVE_REPLY_JOBS_GLOBAL="${ZEUS_MAX_ACTIVE_REPLY_JOBS_GLOBAL-64}"
MAX_ACTIVE_DISPATCH_JOBS_PER_SCOPE="${ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_SCOPE-16}"
MAX_ACTIVE_DISPATCH_JOBS_GLOBAL="${ZEUS_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL-32}"
MAX_AUTH_SESSIONS_PER_USER="${ZEUS_MAX_AUTH_SESSIONS_PER_USER-32}"
MAX_AUTH_SESSIONS_GLOBAL="${ZEUS_MAX_AUTH_SESSIONS_GLOBAL-256}"
MAX_SESSION_EVENT_SLOTS_PER_SESSION="${ZEUS_MAX_SESSION_EVENT_SLOTS_PER_SESSION-10000}"
MAX_RUN_EVENT_SLOTS_PER_RUN="${ZEUS_MAX_RUN_EVENT_SLOTS_PER_RUN-50000}"
MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION="${ZEUS_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION-67108864}"
MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN="${ZEUS_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN-268435456}"
MAX_EVENT_PAYLOAD_BYTES_GLOBAL="${ZEUS_MAX_EVENT_PAYLOAD_BYTES_GLOBAL-1073741824}"
MAX_BOOTSTRAP_AUDIT_ROWS="${ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS-1024}"
SQLITE_MAX_MAIN_BYTES="${ZEUS_SQLITE_MAX_MAIN_BYTES-4294967296}"
SQLITE_WAL_TARGET_BYTES="${ZEUS_SQLITE_WAL_TARGET_BYTES-16777216}"
SQLITE_MIN_FREE_BYTES="${ZEUS_SQLITE_MIN_FREE_BYTES-268435456}"
SQLITE_ADMISSION_RESERVE_BYTES="${ZEUS_SQLITE_ADMISSION_RESERVE_BYTES-536870912}"
SQLITE_MAX_CONCURRENT_OPERATIONS="${ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS-8}"
SQLITE_RESERVED_PROGRESS_OPERATIONS="${ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS-1}"
SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS="${ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS-1000}"

API_CPUS="${ZEUS_CONTAINER_API_CPUS:-2}"
API_MEMORY="${ZEUS_CONTAINER_API_MEMORY:-1G}"

MANAGED_LABEL_KEY='dev.zeus-harness.managed'
PROJECT_LABEL_KEY='dev.zeus-harness.project'

GATEWAY_URL="http://127.0.0.1:${HTTP_PORT}"

log() {
	printf '[zeus-container] %s\n' "$*"
}

die() {
	printf '[zeus-container] error: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

preflight() {
	require_command container
	require_command curl
	require_command jq
	require_command rsync
	container system status >/dev/null
}

contains_exact_line() {
	local needle="$1"
	grep -Fqx -- "${needle}"
}

container_exists() {
	container list --all --quiet | contains_exact_line "$1"
}

container_state() {
	container inspect "$1" | jq -r '.[0].status.state // "unknown"'
}

container_is_owned() {
	container inspect "$1" | jq -e \
		--arg managed "${MANAGED_LABEL_KEY}" \
		--arg project_key "${PROJECT_LABEL_KEY}" \
		--arg project "${PROJECT}" \
		'.[0].configuration.labels[$managed] == "true"
		 and .[0].configuration.labels[$project_key] == $project' >/dev/null
}

network_is_owned() {
	container network inspect "$1" | jq -e \
		--arg managed "${MANAGED_LABEL_KEY}" \
		--arg project_key "${PROJECT_LABEL_KEY}" \
		--arg project "${PROJECT}" \
		'.[0].configuration.labels[$managed] == "true"
		 and .[0].configuration.labels[$project_key] == $project' >/dev/null
}

volume_is_owned() {
	container volume inspect "$1" | jq -e \
		--arg managed "${MANAGED_LABEL_KEY}" \
		--arg project_key "${PROJECT_LABEL_KEY}" \
		--arg project "${PROJECT}" \
		'.[0].configuration.labels[$managed] == "true"
		 and .[0].configuration.labels[$project_key] == $project' >/dev/null
}

require_owned_container() {
	container_is_owned "$1" || die "refusing to modify foreign or unlabeled container: $1"
}

require_owned_network() {
	network_is_owned "$1" || die "refusing to modify foreign or unlabeled network: $1"
}

require_owned_volume() {
	volume_is_owned "$1" || die "refusing to modify foreign or unlabeled volume: $1"
}

image_exists() {
	container image inspect "$1" >/dev/null 2>&1
}

network_exists() {
	container network list --quiet | contains_exact_line "$1"
}

volume_exists() {
	container volume list --quiet | contains_exact_line "$1"
}

stop_container() {
	local name="$1"
	if container_exists "${name}"; then
		require_owned_container "${name}"
	fi
	if container_exists "${name}" && [[ "$(container_state "${name}")" == "running" ]]; then
		log "stopping ${name}"
		container stop --time 20 "${name}" >/dev/null
	fi
}

remove_container() {
	local name="$1"
	if container_exists "${name}"; then
		stop_container "${name}"
		log "deleting ${name}"
		container delete "${name}" >/dev/null
	fi
}

ensure_network() {
	if network_exists "${NETWORK}"; then
		require_owned_network "${NETWORK}"
	else
		log "creating network ${NETWORK}"
		container network create \
			--label "${MANAGED_LABEL_KEY}=true" \
			--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
			"${NETWORK}" >/dev/null
	fi
}

ensure_volume() {
	if volume_exists "${DATA_VOLUME}"; then
		require_owned_volume "${DATA_VOLUME}"
	else
		log "creating persistent volume ${DATA_VOLUME}"
		container volume create \
			--label "${MANAGED_LABEL_KEY}=true" \
			--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
			"${DATA_VOLUME}" >/dev/null
	fi
}

wait_http() {
	local url="$1"
	local label="$2"
	local attempts="${3:-60}"
	local attempt
	for ((attempt = 1; attempt <= attempts; attempt += 1)); do
		if curl --noproxy '*' --fail --silent --show-error \
			--connect-timeout 2 --max-time 2 "${url}" >/dev/null 2>&1; then
			log "${label} is ready"
			return 0
		fi
		sleep 1
	done
	die "${label} did not become ready at ${url}"
}

http_is_ready() {
	local url="$1"
	local attempts="${2:-1}"
	local attempt
	for ((attempt = 1; attempt <= attempts; attempt += 1)); do
		if curl --noproxy '*' --fail --silent --show-error \
			--connect-timeout 2 --max-time 2 "${url}" >/dev/null 2>&1; then
			return 0
		fi
		if ((attempt < attempts)); then
			sleep 1
		fi
	done
	return 1
}

network_ipv4() {
	local name="$1"
	container inspect "${name}" | jq -r --arg network "${NETWORK}" '
		.[0].status.networks[]
		| select(.network == $network)
		| .ipv4Address
		| split("/")[0]
	' | head -n 1
}

container_direct_url() {
	local name="$1"
	local port="$2"
	local ip
	ip="$(network_ipv4 "${name}")"
	[[ -n "${ip}" && "${ip}" != 'null' ]] || return 1
	printf 'http://%s:%s\n' "${ip}" "${port}"
}

gateway_effective_url() {
	local direct_url
	if direct_url="$(container_direct_url "${GATEWAY_CONTAINER}" 8080)" \
		&& http_is_ready "${direct_url}/health/ready"; then
		printf '%s\n' "${direct_url}"
		return 0
	fi

	if http_is_ready "${GATEWAY_URL}/health/ready"; then
		printf '%s\n' "${GATEWAY_URL}"
		return 0
	fi
	return 1
}

build_dns() {
	if [[ -n "${ZEUS_CONTAINER_DNS:-}" ]]; then
		printf '%s\n' "${ZEUS_CONTAINER_DNS}"
		return
	fi
	if command -v route >/dev/null 2>&1; then
		route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'
	fi
}

decimal_lte() {
	local value="$1"
	local ceiling="$2"
	local index
	local value_digit
	local ceiling_digit

	if ((${#value} < ${#ceiling})); then
		return 0
	fi
	if ((${#value} > ${#ceiling})); then
		return 1
	fi
	for ((index = 0; index < ${#value}; index += 1)); do
		value_digit="${value:index:1}"
		ceiling_digit="${ceiling:index:1}"
		if ((10#${value_digit} < 10#${ceiling_digit})); then
			return 0
		fi
		if ((10#${value_digit} > 10#${ceiling_digit})); then
			return 1
		fi
	done
	return 0
}

memory_bytes() {
	local value="$1"
	local amount
	local multiplier
	local maximum_amount
	case "${value}" in
		*[Gg]) amount="${value%[Gg]}"; multiplier=$((1024 * 1024 * 1024)) ;;
		*[Mm]) amount="${value%[Mm]}"; multiplier=$((1024 * 1024)) ;;
		*[Kk]) amount="${value%[Kk]}"; multiplier=1024 ;;
		*) amount="${value}"; multiplier=1 ;;
	esac
	[[ "${amount}" =~ ^[1-9][0-9]*$ ]] \
		|| die "invalid positive memory limit: ${value}"
	maximum_amount="$((9223372036854775807 / multiplier))"
	decimal_lte "${amount}" "${maximum_amount}" \
		|| die "memory limit overflows byte representation: ${value}"
	printf '%s\n' "$((amount * multiplier))"
}

verify_container_resources() {
	local name="$1"
	local requested_cpus="$2"
	local requested_memory="$3"
	local requested_memory_bytes
	[[ "${requested_cpus}" =~ ^[1-9][0-9]*$ ]] \
		|| die "invalid positive Apple container CPU limit: ${requested_cpus}"
	requested_memory_bytes="$(memory_bytes "${requested_memory}")"
	require_owned_container "${name}"
	container inspect "${name}" | jq -e \
		--argjson cpus "${requested_cpus}" \
		--argjson memory "${requested_memory_bytes}" '
		.[0].configuration.resources.cpus == $cpus
		and .[0].configuration.resources.memoryInBytes == $memory
	' >/dev/null || {
		container inspect "${name}" | jq \
			'.[0].configuration.resources | {cpus, memoryInBytes}' >&2
		die "${name} was created without the requested ${requested_cpus} CPU/${requested_memory} limits"
	}
	log "verified ${name} resource configuration (${requested_cpus} CPU/${requested_memory})"
}

builder_matches() {
	local dns="$1"
	local required_memory
	required_memory="$(memory_bytes "${BUILD_MEMORY}")"
	container inspect buildkit | jq -e \
		--argjson cpus "${BUILD_CPUS}" \
		--argjson memory "${required_memory}" \
		--arg dns "${dns}" '
		.[0].configuration.resources.cpus >= $cpus
		and .[0].configuration.resources.memoryInBytes >= $memory
		and ($dns == "" or (.[0].configuration.dns.nameservers | index($dns)) != null)
	' >/dev/null
}

start_builder() {
	local dns="$1"
	local dns_args=()
	if [[ -n "${dns}" ]]; then
		dns_args=(--dns "${dns}")
	fi
	container builder start \
		--cpus "${BUILD_CPUS}" \
		--memory "${BUILD_MEMORY}" \
		"${dns_args[@]}" >/dev/null

	builder_matches "${dns}" \
		|| die 'Apple BuildKit started without the requested CPU, memory or DNS configuration'
}

ensure_builder() {
	local dns="$1"
	if ! container_exists buildkit; then
		log 'creating Apple BuildKit VM'
		start_builder "${dns}"
		return
	fi
	if [[ "$(container_state buildkit)" == 'running' ]] && builder_matches "${dns}"; then
		return
	fi
	if [[ "$(container_state buildkit)" == 'running' ]]; then
		[[ "${ZEUS_CONTAINER_RECONFIGURE_BUILDER:-}" == 'yes' ]] || die \
			"the shared Apple builder does not match ${BUILD_CPUS} CPU/${BUILD_MEMORY}/DNS ${dns}; rerun with ZEUS_CONTAINER_RECONFIGURE_BUILDER=yes"
		log 'stopping the shared Apple builder for explicit reconfiguration'
		container builder stop >/dev/null
	fi
	log 'starting Apple BuildKit VM with the requested resources and DNS'
	start_builder "${dns}"
}

create_build_context() {
	local context_root
	local context
	context_root="$(cd "${BUILD_CONTEXT_ROOT}" && pwd -P)"
	context="$(mktemp -d "${context_root}/.zeus-container-build.XXXXXX")"
	log "creating stable build context ${context}" >&2
	rsync -a \
		--exclude '.git/' \
		--exclude '.github/' \
		--exclude '.idea/' \
		--exclude '.env' \
		--exclude '.zeus/' \
		--exclude '.zeus-container-build.*/' \
		--exclude '.turbo/' \
		--exclude '.pnpm-store/' \
		--exclude '.svelte-kit/' \
		--exclude 'build/' \
		--exclude 'dist/' \
		--exclude 'node_modules/' \
		--exclude 'target/' \
		--exclude '*.log' \
		"${REPO_ROOT}/" "${context}/"
	printf '%s\n' "${context}"
}

remove_build_context() {
	local context="$1"
	local context_root
	context_root="$(cd "${BUILD_CONTEXT_ROOT}" && pwd -P)"
	case "${context}" in
		"${context_root}"/.zeus-container-build.*)
			rm -rf -- "${context}"
			;;
		*)
			die "refusing to remove unexpected build context path: ${context}"
			;;
	esac
}

build_images() {
	preflight
	local dns
	dns="$(build_dns)"
	local dns_args=()
	if [[ -n "${dns}" ]]; then
		dns_args=(--dns "${dns}")
		log "using BuildKit DNS ${dns}"
	else
		log 'no non-loopback BuildKit DNS was discovered; set ZEUS_CONTAINER_DNS if resolution fails'
	fi
	ensure_builder "${dns}"
	local build_context
	build_context="$(create_build_context)"
	trap 'remove_build_context "${build_context}"' EXIT INT TERM
	trap 'trap - EXIT INT TERM; remove_build_context "${build_context}"; exit 130' INT
	trap 'trap - EXIT INT TERM; remove_build_context "${build_context}"; exit 143' TERM

	log "building ${API_IMAGE} (${PLATFORM})"
	(
		cd "${build_context}"
		container build \
			--platform "${PLATFORM}" \
			--cpus "${BUILD_CPUS}" \
			--memory "${BUILD_MEMORY}" \
			--progress plain \
			"${dns_args[@]}" \
			--file infra/docker/rust.Dockerfile \
			--target runtime \
			--tag "${API_IMAGE}" \
			.
	)

	log "building ${WEB_IMAGE} (${PLATFORM})"
	(
		cd "${build_context}"
		container build \
			--platform "${PLATFORM}" \
			--cpus "${BUILD_CPUS}" \
			--memory "${BUILD_MEMORY}" \
			--progress plain \
			"${dns_args[@]}" \
			--file infra/docker/web.Dockerfile \
			--target runtime \
			--tag "${WEB_IMAGE}" \
			.
	)

	log "building ${GATEWAY_IMAGE} (${PLATFORM})"
	(
		cd "${build_context}"
		container build \
			--platform "${PLATFORM}" \
			--cpus "${BUILD_CPUS}" \
			--memory "${BUILD_MEMORY}" \
			--progress plain \
			"${dns_args[@]}" \
			--file infra/docker/caddy.Dockerfile \
			--tag "${GATEWAY_IMAGE}" \
			.
	)
	remove_build_context "${build_context}"
	trap - EXIT INT TERM
}

initialize_volume() {
	remove_container "${INIT_CONTAINER}"
	log "initializing ${DATA_VOLUME} ownership"
	container run \
		--remove \
		--name "${INIT_CONTAINER}" \
		--label "${MANAGED_LABEL_KEY}=true" \
		--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
		--user 0:0 \
		--volume "${DATA_VOLUME}:/var/lib/zeus" \
		--entrypoint /bin/sh \
		"${API_IMAGE}" \
		-c 'chown -R zeus:zeus /var/lib/zeus && chmod 0750 /var/lib/zeus'
}

start_api() {
	# Validate before creating anything, then verify the effective configuration
	# from Apple container's own inspect result immediately after creation.
	[[ "${API_CPUS}" =~ ^[1-9][0-9]*$ ]] \
		|| die "invalid positive Apple container CPU limit: ${API_CPUS}"
	memory_bytes "${API_MEMORY}" >/dev/null
	log "starting ${API_CONTAINER} on the private ${NETWORK} network"
	container run \
		--detach \
		--name "${API_CONTAINER}" \
		--label "${MANAGED_LABEL_KEY}=true" \
		--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
		--network "${NETWORK}" \
		--init \
		--cpus "${API_CPUS}" \
		--memory "${API_MEMORY}" \
		--volume "${DATA_VOLUME}:/var/lib/zeus" \
		--env ZEUS_LISTEN_ADDR=0.0.0.0:8081 \
		--env ZEUS_DATABASE_PATH=/var/lib/zeus/zeus.db \
		--env ZEUS_DEMO_PROFILE=production-guarded \
		--env ZEUS_LOCAL_MARKER_ROOT=/var/lib/zeus/local-markers \
		--env "ZEUS_COOKIE_SECURE=${COOKIE_SECURE}" \
		--env "ZEUS_LLM_ENDPOINT=${LLM_ENDPOINT}" \
		--env "ZEUS_LLM_MODEL=${LLM_MODEL}" \
		--env "ZEUS_LLM_API_KEY=${LLM_API_KEY}" \
		--env "ZEUS_MAX_SESSIONS_PER_SCOPE=${MAX_SESSIONS_PER_SCOPE}" \
		--env "ZEUS_MAX_SESSIONS_GLOBAL=${MAX_SESSIONS_GLOBAL}" \
		--env "ZEUS_MAX_OPEN_TURNS_PER_SCOPE=${MAX_OPEN_TURNS_PER_SCOPE}" \
		--env "ZEUS_MAX_OPEN_TURNS_GLOBAL=${MAX_OPEN_TURNS_GLOBAL}" \
		--env "ZEUS_MAX_ACTIVE_REPLY_JOBS_PER_SCOPE=${MAX_ACTIVE_REPLY_JOBS_PER_SCOPE}" \
		--env "ZEUS_MAX_ACTIVE_REPLY_JOBS_GLOBAL=${MAX_ACTIVE_REPLY_JOBS_GLOBAL}" \
		--env "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_PER_SCOPE=${MAX_ACTIVE_DISPATCH_JOBS_PER_SCOPE}" \
		--env "ZEUS_MAX_ACTIVE_DISPATCH_JOBS_GLOBAL=${MAX_ACTIVE_DISPATCH_JOBS_GLOBAL}" \
		--env "ZEUS_MAX_AUTH_SESSIONS_PER_USER=${MAX_AUTH_SESSIONS_PER_USER}" \
		--env "ZEUS_MAX_AUTH_SESSIONS_GLOBAL=${MAX_AUTH_SESSIONS_GLOBAL}" \
		--env "ZEUS_MAX_SESSION_EVENT_SLOTS_PER_SESSION=${MAX_SESSION_EVENT_SLOTS_PER_SESSION}" \
		--env "ZEUS_MAX_RUN_EVENT_SLOTS_PER_RUN=${MAX_RUN_EVENT_SLOTS_PER_RUN}" \
		--env "ZEUS_MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION=${MAX_SESSION_EVENT_PAYLOAD_BYTES_PER_SESSION}" \
		--env "ZEUS_MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN=${MAX_RUN_EVENT_PAYLOAD_BYTES_PER_RUN}" \
		--env "ZEUS_MAX_EVENT_PAYLOAD_BYTES_GLOBAL=${MAX_EVENT_PAYLOAD_BYTES_GLOBAL}" \
		--env "ZEUS_MAX_BOOTSTRAP_AUDIT_ROWS=${MAX_BOOTSTRAP_AUDIT_ROWS}" \
		--env "ZEUS_SQLITE_MAX_MAIN_BYTES=${SQLITE_MAX_MAIN_BYTES}" \
		--env "ZEUS_SQLITE_WAL_TARGET_BYTES=${SQLITE_WAL_TARGET_BYTES}" \
		--env "ZEUS_SQLITE_MIN_FREE_BYTES=${SQLITE_MIN_FREE_BYTES}" \
		--env "ZEUS_SQLITE_ADMISSION_RESERVE_BYTES=${SQLITE_ADMISSION_RESERVE_BYTES}" \
		--env "ZEUS_SQLITE_MAX_CONCURRENT_OPERATIONS=${SQLITE_MAX_CONCURRENT_OPERATIONS}" \
		--env "ZEUS_SQLITE_RESERVED_PROGRESS_OPERATIONS=${SQLITE_RESERVED_PROGRESS_OPERATIONS}" \
		--env "ZEUS_SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS=${SQLITE_OPERATION_ACQUIRE_TIMEOUT_MS}" \
		"${API_IMAGE}" >/dev/null
	verify_container_resources "${API_CONTAINER}" "${API_CPUS}" "${API_MEMORY}"
	local direct_url
	direct_url="$(container_direct_url "${API_CONTAINER}" 8081)" \
		|| die "could not resolve ${API_CONTAINER} IPv4 address"
	wait_http "${direct_url}/health/ready" 'Zeus API'
}

start_web() {
	log "starting ${WEB_CONTAINER} on the private ${NETWORK} network"
	container run \
		--detach \
		--name "${WEB_CONTAINER}" \
		--label "${MANAGED_LABEL_KEY}=true" \
		--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
		--network "${NETWORK}" \
		--init \
		--cpus 1 \
		--memory 512M \
		"${WEB_IMAGE}" >/dev/null
	local direct_url
	direct_url="$(container_direct_url "${WEB_CONTAINER}" 3000)" \
		|| die "could not resolve ${WEB_CONTAINER} IPv4 address"
	wait_http "${direct_url}/" 'Zeus Web'
}

start_gateway() {
	local api_ip
	local web_ip
	api_ip="$(network_ipv4 "${API_CONTAINER}")"
	web_ip="$(network_ipv4 "${WEB_CONTAINER}")"
	[[ -n "${api_ip}" ]] || die "could not resolve ${API_CONTAINER} IPv4 address"
	[[ -n "${web_ip}" ]] || die "could not resolve ${WEB_CONTAINER} IPv4 address"

	log "starting ${GATEWAY_CONTAINER} on ${GATEWAY_URL}"
	container run \
		--detach \
		--name "${GATEWAY_CONTAINER}" \
		--label "${MANAGED_LABEL_KEY}=true" \
		--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
		--network "${NETWORK}" \
		--cpus 1 \
		--memory 256M \
		--read-only \
		--tmpfs /config \
		--tmpfs /data \
		--publish "127.0.0.1:${HTTP_PORT}:8080" \
		--env "ZEUS_UPSTREAM=${api_ip}:8081" \
		--env "WEB_UPSTREAM=${web_ip}:3000" \
		"${GATEWAY_IMAGE}" >/dev/null
	local direct_url
	direct_url="$(container_direct_url "${GATEWAY_CONTAINER}" 8080)" \
		|| die "could not resolve ${GATEWAY_CONTAINER} IPv4 address"
	wait_http "${direct_url}/health/ready" 'Zeus gateway API route'
	wait_http "${direct_url}/" 'Zeus gateway Web route'
	if http_is_ready "${GATEWAY_URL}/health/ready" 5; then
		log "published gateway is ready at ${GATEWAY_URL}"
	else
		log "Apple localhost port forwarding is unavailable; using ${direct_url}"
	fi
}

validate_up_resources() {
	local name
	for name in \
		"${GATEWAY_CONTAINER}" \
		"${WEB_CONTAINER}" \
		"${API_CONTAINER}" \
		"${INIT_CONTAINER}"; do
		if container_exists "${name}"; then
			require_owned_container "${name}"
		fi
	done
	if network_exists "${NETWORK}"; then
		require_owned_network "${NETWORK}"
	fi
	if volume_exists "${DATA_VOLUME}"; then
		require_owned_volume "${DATA_VOLUME}"
	fi
}

up() {
	preflight
	image_exists "${API_IMAGE}" || die "missing image ${API_IMAGE}; run '$0 build' first"
	image_exists "${WEB_IMAGE}" || die "missing image ${WEB_IMAGE}; run '$0 build' first"
	image_exists "${GATEWAY_IMAGE}" || die "missing image ${GATEWAY_IMAGE}; run '$0 build' first"

	# Validate every collision before changing the old stack. Once the three old
	# containers are gone, any same-named owned container belongs to this attempt.
	validate_up_resources
	remove_container "${GATEWAY_CONTAINER}"
	remove_container "${WEB_CONTAINER}"
	remove_container "${API_CONTAINER}"
	trap 'cleanup_partial_stack $?' EXIT
	ensure_network
	ensure_volume
	initialize_volume
	start_api
	start_web
	start_gateway
	trap - EXIT
	status
}

cleanup_partial_stack() {
	local exit_code="$1"
	trap - EXIT ERR
	log 'startup failed; removing only labeled Zeus containers from this attempt'
	local name
	for name in "${GATEWAY_CONTAINER}" "${WEB_CONTAINER}" "${API_CONTAINER}" "${INIT_CONTAINER}"; do
		if container_exists "${name}" && container_is_owned "${name}"; then
			stop_container "${name}" || true
			container delete "${name}" >/dev/null 2>&1 || true
		fi
	done
	exit "${exit_code}"
}

down() {
	preflight
	remove_container "${GATEWAY_CONTAINER}"
	remove_container "${WEB_CONTAINER}"
	remove_container "${API_CONTAINER}"
	remove_container "${INIT_CONTAINER}"
	if network_exists "${NETWORK}"; then
		require_owned_network "${NETWORK}"
		log "deleting network ${NETWORK}"
		container network delete "${NETWORK}" >/dev/null
	fi
	log "persistent volume ${DATA_VOLUME} was retained"
}

status() {
	preflight
	local name
	for name in "${API_CONTAINER}" "${WEB_CONTAINER}" "${GATEWAY_CONTAINER}" "${INIT_CONTAINER}"; do
		if container_exists "${name}"; then
			printf '%-32s %s\n' "${name}" "$(container_state "${name}")"
		else
			printf '%-32s %s\n' "${name}" 'absent'
		fi
	done
	if volume_exists "${DATA_VOLUME}"; then
		printf '%-32s %s\n' "${DATA_VOLUME}" 'volume present'
	else
		printf '%-32s %s\n' "${DATA_VOLUME}" 'volume absent'
	fi
	if container_exists "${GATEWAY_CONTAINER}" \
		&& [[ "$(container_state "${GATEWAY_CONTAINER}")" == 'running' ]]; then
		local direct_url
		direct_url="$(container_direct_url "${GATEWAY_CONTAINER}" 8080)" || direct_url='unavailable'
		printf '%-32s %s\n' 'gateway direct URL' "${direct_url}"
		if http_is_ready "${GATEWAY_URL}/health/ready"; then
			printf '%-32s %s\n' 'gateway published URL' "${GATEWAY_URL}"
		else
			printf '%-32s %s\n' 'gateway published URL' "${GATEWAY_URL} (runtime forwarding unavailable)"
		fi
	fi
}

resource_evidence() {
	require_command container
	require_command jq
	container system status >/dev/null
	container_exists "${API_CONTAINER}" \
		|| die "container is absent: ${API_CONTAINER}"
	require_owned_container "${API_CONTAINER}"

	printf '%s\n' 'Apple container inspect resource configuration:'
	container inspect "${API_CONTAINER}" | jq --arg name "${API_CONTAINER}" '
		.[0] | {
			container: $name,
			state: (.status.state // "unknown"),
			resources: {
				cpus: .configuration.resources.cpus,
				memoryInBytes: .configuration.resources.memoryInBytes
			}
		}
	'

	if [[ "$(container_state "${API_CONTAINER}")" != 'running' ]]; then
		log 'API container is not running; internal cgroup v2 and /proc evidence is unavailable'
		return
	fi

	printf '%s\n' \
		'Apple container 1.0 has no per-container PID-limit CLI option; pids.max below is observed evidence, not a configured guarantee.'
	container exec "${API_CONTAINER}" /bin/sh -eu -c '
		print_file() {
			path="$1"
			printf "%s\n" "--- $path"
			if [ -r "$path" ]; then
				cat "$path"
			else
				printf "%s\n" "<unavailable>"
			fi
		}

		print_file /proc/self/cgroup
		print_file /sys/fs/cgroup/cgroup.controllers
		print_file /sys/fs/cgroup/cpu.max
		print_file /sys/fs/cgroup/cpu.stat
		print_file /sys/fs/cgroup/memory.max
		print_file /sys/fs/cgroup/memory.high
		print_file /sys/fs/cgroup/memory.current
		print_file /sys/fs/cgroup/memory.peak
		print_file /sys/fs/cgroup/memory.events
		print_file /sys/fs/cgroup/memory.events.local
		print_file /sys/fs/cgroup/memory.swap.current
		print_file /sys/fs/cgroup/memory.swap.max
		print_file /sys/fs/cgroup/pids.max
		print_file /sys/fs/cgroup/pids.current
		print_file /sys/fs/cgroup/pids.events
		printf "%s\n" "--- /proc/meminfo (selected)"
		awk "/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/" /proc/meminfo
		printf "%s\n" "--- /proc/1/status (container init, selected)"
		awk "/^(Name|Pid|PPid|Threads|VmPeak|VmRSS|VmHWM|Cpus_allowed_list):/" /proc/1/status

		zeus_pid=""
		for executable in /proc/[0-9]*/exe; do
			[ -e "$executable" ] || continue
			if [ "$(readlink "$executable" 2>/dev/null || true)" = /usr/local/bin/zeus ]; then
				zeus_pid="${executable#/proc/}"
				zeus_pid="${zeus_pid%/exe}"
				break
			fi
		done
		if [ -n "$zeus_pid" ]; then
			printf "%s\n" "--- /proc/$zeus_pid/status (Zeus, selected)"
			awk "/^(Name|Pid|PPid|Threads|VmPeak|VmRSS|VmHWM|Cpus_allowed_list):/" "/proc/$zeus_pid/status"
			print_file "/proc/$zeus_pid/smaps_rollup"
		else
			printf "%s\n" "--- Zeus process evidence"
			printf "%s\n" "<zeus process unavailable>"
		fi
	'
}

show_logs() {
	preflight
	local service="${1:-api}"
	local name
	case "${service}" in
		api) name="${API_CONTAINER}" ;;
		web) name="${WEB_CONTAINER}" ;;
		gateway) name="${GATEWAY_CONTAINER}" ;;
		*) die 'logs service must be api, web, or gateway' ;;
	esac
	container_exists "${name}" || die "container is absent: ${name}"
	container logs --follow "${name}"
}

verify() {
	preflight
	local gateway_url
	local auth_status
	local protected_status
	gateway_url="$(gateway_effective_url)" \
		|| die 'could not reach the gateway through localhost or its container IP'
	wait_http "${gateway_url}/health/ready" 'Zeus gateway API route' 5
	wait_http "${gateway_url}/" 'Zeus gateway Web route' 5
	auth_status="$(curl --noproxy '*' --fail --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		"${gateway_url}/api/v1/auth/status")"
	jq -e '
		(.configured | type == "boolean")
		and .authenticated == false
	' <<<"${auth_status}" >/dev/null \
		|| die 'anonymous auth status did not match the expected schema'
	protected_status="$(curl --noproxy '*' --silent --show-error \
		--output /dev/null --write-out '%{http_code}' \
		--connect-timeout 2 --max-time 5 \
		"${gateway_url}/api/v1/overview")"
	[[ "${protected_status}" == '401' ]] \
		|| die "anonymous overview returned ${protected_status}, expected 401"

	log 'verified Web, API, gateway, auth status and the anonymous protection boundary'
}

restart_verify() {
	preflight
	local gateway_url
	local before_configured
	local after_configured

	gateway_url="$(gateway_effective_url)" \
		|| die 'could not reach the gateway before restart verification'
	before_configured="$(curl --noproxy '*' --fail --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		"${gateway_url}/api/v1/auth/status" | jq -r '.configured')"
	[[ "${before_configured}" == 'true' || "${before_configured}" == 'false' ]] \
		|| die 'auth status did not contain a boolean configured value before restart'

	down
	up

	gateway_url="$(gateway_effective_url)" \
		|| die 'could not reach the gateway after restart verification'
	after_configured="$(curl --noproxy '*' --fail --silent --show-error \
		--connect-timeout 2 --max-time 5 \
		"${gateway_url}/api/v1/auth/status" | jq -r '.configured')"
	[[ "${after_configured}" == "${before_configured}" ]] \
		|| die "owner configuration changed across restart: ${before_configured} -> ${after_configured}"

	verify
	log "verified named-volume owner-state recovery (configured=${after_configured})"
}

reset_data() {
	preflight
	[[ "${ZEUS_CONTAINER_CONFIRM_RESET:-}" == "${DATA_VOLUME}" ]] \
		|| die "refusing to delete ${DATA_VOLUME}; set ZEUS_CONTAINER_CONFIRM_RESET=${DATA_VOLUME}"
	down
	if volume_exists "${DATA_VOLUME}"; then
		require_owned_volume "${DATA_VOLUME}"
		log "deleting persistent volume ${DATA_VOLUME}"
		container volume delete "${DATA_VOLUME}" >/dev/null
	fi
}

usage() {
	cat <<'EOF'
Usage: scripts/apple-container.sh <command>

Commands:
  build            Build API, Web and gateway runtime images.
  up               Start API, Web and gateway; retain SQLite in a named volume.
  down             Stop/delete Zeus containers and network; retain the volume.
  status           Show Zeus container and volume state.
  resources        Read API inspect, cgroup v2 and /proc resource evidence.
  logs [service]   Follow api, web or gateway logs (default: api).
  verify           Check Web, API, gateway and anonymous auth protection.
  restart-verify   Recreate the stack and prove owner setup state persists.
  reset            Delete persistent data; confirmation must equal the exact volume name.

Useful overrides:
  ZEUS_CONTAINER_PROJECT, ZEUS_CONTAINER_DNS, ZEUS_CONTAINER_PLATFORM,
  ZEUS_CONTAINER_HTTP_PORT.
  ZEUS_CONTAINER_API_CPUS and ZEUS_CONTAINER_API_MEMORY default to 2 CPU/1G;
  the helper verifies their effective Apple VM configuration after creation.
  Apple container 1.0 has no per-container PID-limit CLI option; `resources`
  reports the observed pids.max alongside CPU/memory evidence.
  ZEUS_CONTAINER_BUILD_CONTEXT_ROOT defaults to the physical repository path
  to avoid Apple container's temporary-path empty-transfer bug.
  Set ZEUS_CONTAINER_RECONFIGURE_BUILDER=yes to opt into changing Apple's
  shared BuildKit VM when its CPU, memory or DNS do not match this project.
EOF
}

command="${1:-help}"
shift || true

case "${command}" in
	build) build_images "$@" ;;
	up) up "$@" ;;
	down) down "$@" ;;
	status) status "$@" ;;
	resources) resource_evidence "$@" ;;
	logs) show_logs "$@" ;;
	verify) verify "$@" ;;
	restart-verify) restart_verify "$@" ;;
	reset) reset_data "$@" ;;
	help | --help | -h) usage ;;
	*) usage >&2; die "unknown command: ${command}" ;;
esac
