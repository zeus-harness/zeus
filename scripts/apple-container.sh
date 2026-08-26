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

memory_bytes() {
	local value="$1"
	case "${value}" in
		*[Gg]) printf '%s\n' "$(( ${value%[Gg]} * 1024 * 1024 * 1024 ))" ;;
		*[Mm]) printf '%s\n' "$(( ${value%[Mm]} * 1024 * 1024 ))" ;;
		*[Kk]) printf '%s\n' "$(( ${value%[Kk]} * 1024 ))" ;;
		*) printf '%s\n' "${value}" ;;
	esac
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
	log "starting ${API_CONTAINER} on the private ${NETWORK} network"
	container run \
		--detach \
		--name "${API_CONTAINER}" \
		--label "${MANAGED_LABEL_KEY}=true" \
		--label "${PROJECT_LABEL_KEY}=${PROJECT}" \
		--network "${NETWORK}" \
		--init \
		--cpus 2 \
		--memory 1G \
		--volume "${DATA_VOLUME}:/var/lib/zeus" \
		--env ZEUS_LISTEN_ADDR=0.0.0.0:8081 \
		--env ZEUS_DATABASE_PATH=/var/lib/zeus/zeus.db \
		--env ZEUS_DEMO_PROFILE=production-guarded \
		--env ZEUS_LOCAL_MARKER_ROOT=/var/lib/zeus/local-markers \
		--env "ZEUS_COOKIE_SECURE=${COOKIE_SECURE}" \
		--env "ZEUS_LLM_ENDPOINT=${LLM_ENDPOINT}" \
		--env "ZEUS_LLM_MODEL=${LLM_MODEL}" \
		--env "ZEUS_LLM_API_KEY=${LLM_API_KEY}" \
		"${API_IMAGE}" >/dev/null
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
  logs [service]   Follow api, web or gateway logs (default: api).
  verify           Check Web, API, gateway and anonymous auth protection.
  restart-verify   Recreate the stack and prove owner setup state persists.
  reset            Delete persistent data; confirmation must equal the exact volume name.

Useful overrides:
  ZEUS_CONTAINER_PROJECT, ZEUS_CONTAINER_DNS, ZEUS_CONTAINER_PLATFORM,
  ZEUS_CONTAINER_HTTP_PORT.
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
	logs) show_logs "$@" ;;
	verify) verify "$@" ;;
	restart-verify) restart_verify "$@" ;;
	reset) reset_data "$@" ;;
	help | --help | -h) usage ;;
	*) usage >&2; die "unknown command: ${command}" ;;
esac
