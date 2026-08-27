import type {
	AccountAuditCheckpointRequest,
	AccountAuditCheckpointResponse,
	AccountAuditPageResponse,
	AccountAuditPolicy,
	AuthenticationResponse,
	AuthStatusResponse,
	BootstrapRequest,
	CreateMemberRequest,
	CreateSessionRequest,
	CreateSessionResponse,
	LoginRequest,
	LogoutResponse,
	MemberListResponse,
	MemberSetupRequest,
	MemberSetupTokenResponse,
	OverviewResponse,
	RotateMemberSetupTokenRequest,
	ResumeSessionResponse,
	ReviewDecision,
	ReviewRequest,
	ReviewResponse,
	RunEvent,
	SessionDetail,
	SessionEvent,
	SessionSummary,
	SessionTurn,
	StartTurnResponse,
	UpdateAccountAuditPolicyRequest,
	UpdateMemberRequest,
	UpdateMemberResponse
} from './types';
import { apiFetch } from './http';
import { buildSessionListPath, type SessionListQuery } from './session-list';
import { createStreamAuthorizationProbe } from './stream-auth';

export type StreamStatus = 'connected' | 'reconnecting';

export interface SessionListPage {
	items: SessionSummary[];
	nextCursor: string | null;
}

export interface ListSessionsOptions extends SessionListQuery {
	signal?: AbortSignal;
}

export class ApiError extends Error {
	constructor(
		message: string,
		readonly status: number,
		readonly code: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

async function responseError(response: Response, fallback: string): Promise<ApiError> {
	let detail = '';
	let code = 'http_error';
	if (response.headers.get('content-type')?.includes('json')) {
		try {
			const problem = (await response.json()) as {
				code?: unknown;
				detail?: unknown;
				title?: unknown;
			};
			if (typeof problem.code === 'string' && problem.code) code = problem.code;
			detail =
				typeof problem.detail === 'string'
					? problem.detail
					: typeof problem.title === 'string'
						? problem.title
						: '';
		} catch {
			// Fall through to the status-based message for malformed error bodies.
		}
	} else {
		detail = await response.text();
	}
	return new ApiError(detail || `${fallback} returned ${response.status}`, response.status, code);
}

function eventKey(event: RunEvent): string {
	return event.id ?? `${event.sequence}:${event.type}`;
}

export function mergeEvents(current: RunEvent[], incoming: RunEvent[]): RunEvent[] {
	const events = new Map(current.map((event) => [eventKey(event), event]));
	for (const event of incoming) events.set(eventKey(event), event);
	return [...events.values()].sort((left, right) => left.sequence - right.sequence);
}

export async function getOverview(signal?: AbortSignal): Promise<OverviewResponse> {
	const response = await apiFetch('/api/v1/overview', {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Overview API');
	return response.json() as Promise<OverviewResponse>;
}

export async function getSession(sessionId: string, signal?: AbortSignal): Promise<SessionDetail> {
	const response = await apiFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}`, {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Session API');
	return response.json() as Promise<SessionDetail>;
}

export async function getSessionTurn(
	sessionId: string,
	turnId: string,
	signal?: AbortSignal
): Promise<SessionTurn> {
	const response = await apiFetch(
		`/api/v1/sessions/${encodeURIComponent(sessionId)}/turns/${encodeURIComponent(turnId)}`,
		{
			headers: { Accept: 'application/json' },
			signal
		}
	);
	if (!response.ok) throw await responseError(response, 'Session turn API');
	return response.json() as Promise<SessionTurn>;
}

export async function startSessionTurn(
	sessionId: string,
	request: { turn_id: string; user_message: string; expected_sequence: number },
	idempotencyKey: string
): Promise<StartTurnResponse> {
	const response = await apiFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/turns`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json',
			'Idempotency-Key': idempotencyKey
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Start turn API');
	return response.json() as Promise<StartTurnResponse>;
}

export async function getAuthStatus(signal?: AbortSignal): Promise<AuthStatusResponse> {
	const response = await apiFetch('/api/v1/auth/status', {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Authentication status API');
	return response.json() as Promise<AuthStatusResponse>;
}

export async function bootstrapOwner(request: BootstrapRequest): Promise<AuthenticationResponse> {
	const response = await apiFetch('/api/v1/auth/bootstrap', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Owner setup API');
	return response.json() as Promise<AuthenticationResponse>;
}

export async function login(request: LoginRequest): Promise<AuthenticationResponse> {
	const response = await apiFetch('/api/v1/auth/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Login API');
	return response.json() as Promise<AuthenticationResponse>;
}

export async function completeMemberSetup(
	request: MemberSetupRequest
): Promise<AuthenticationResponse> {
	const response = await apiFetch('/api/v1/auth/member-setup', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Member setup API');
	return response.json() as Promise<AuthenticationResponse>;
}

export async function listMembers(
	cursor?: string,
	limit = 50,
	signal?: AbortSignal
): Promise<MemberListResponse> {
	const query = new URLSearchParams({ limit: String(limit) });
	if (cursor) query.set('cursor', cursor);
	const response = await apiFetch(`/api/v1/members?${query}`, {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Members API');
	return response.json() as Promise<MemberListResponse>;
}

export async function createMember(
	request: CreateMemberRequest
): Promise<MemberSetupTokenResponse> {
	const response = await apiFetch('/api/v1/members', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Create member API');
	return response.json() as Promise<MemberSetupTokenResponse>;
}

export async function updateMember(
	userId: string,
	request: UpdateMemberRequest
): Promise<UpdateMemberResponse> {
	const response = await apiFetch(`/api/v1/members/${encodeURIComponent(userId)}`, {
		method: 'PATCH',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Update member API');
	return response.json() as Promise<UpdateMemberResponse>;
}

export async function rotateMemberSetupToken(
	userId: string,
	request: RotateMemberSetupTokenRequest
): Promise<MemberSetupTokenResponse> {
	const response = await apiFetch(`/api/v1/members/${encodeURIComponent(userId)}/setup-token`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Rotate member setup token API');
	return response.json() as Promise<MemberSetupTokenResponse>;
}

export async function listAccountAuditEvents(
	cursor?: string,
	limit = 50,
	signal?: AbortSignal
): Promise<AccountAuditPageResponse> {
	const query = new URLSearchParams({ limit: String(limit) });
	if (cursor) query.set('cursor', cursor);
	const response = await apiFetch(`/api/v1/audit/events?${query}`, {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Account audit API');
	return response.json() as Promise<AccountAuditPageResponse>;
}

export async function getAccountAuditPolicy(signal?: AbortSignal): Promise<AccountAuditPolicy> {
	const response = await apiFetch('/api/v1/audit/policy', {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Account audit policy API');
	return response.json() as Promise<AccountAuditPolicy>;
}

export async function updateAccountAuditPolicy(
	request: UpdateAccountAuditPolicyRequest
): Promise<AccountAuditPolicy> {
	const response = await apiFetch('/api/v1/audit/policy', {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Update account audit policy API');
	return response.json() as Promise<AccountAuditPolicy>;
}

export async function downloadAccountAuditExport(signal?: AbortSignal): Promise<Blob> {
	const response = await apiFetch('/api/v1/audit/export', {
		headers: { Accept: 'application/x-ndjson' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Account audit export API');
	return response.blob();
}

export async function createAccountAuditCheckpoint(
	request: AccountAuditCheckpointRequest
): Promise<AccountAuditCheckpointResponse> {
	const response = await apiFetch('/api/v1/audit/archive/checkpoint', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json'
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Account audit checkpoint API');
	return response.json() as Promise<AccountAuditCheckpointResponse>;
}

export async function logout(): Promise<LogoutResponse> {
	const response = await apiFetch('/api/v1/auth/logout', {
		method: 'POST',
		headers: { Accept: 'application/json' }
	});
	if (!response.ok) throw await responseError(response, 'Logout API');
	return response.json() as Promise<LogoutResponse>;
}

export async function listSessions(options: ListSessionsOptions = {}): Promise<SessionListPage> {
	const response = await apiFetch(buildSessionListPath(options), {
		headers: { Accept: 'application/json' },
		signal: options.signal
	});
	if (!response.ok) throw await responseError(response, 'Sessions API');
	return {
		items: (await response.json()) as SessionSummary[],
		nextCursor: response.headers.get('X-Zeus-Next-Cursor') || null
	};
}

export async function createSession(
	request: CreateSessionRequest,
	idempotencyKey: string
): Promise<CreateSessionResponse> {
	const response = await apiFetch('/api/v1/sessions', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json',
			'Idempotency-Key': idempotencyKey
		},
		body: JSON.stringify(request)
	});
	if (!response.ok) throw await responseError(response, 'Create session API');
	return response.json() as Promise<CreateSessionResponse>;
}

export async function resumeSession(
	sessionId: string,
	expectedSequence: number,
	idempotencyKey: string
): Promise<ResumeSessionResponse> {
	const response = await apiFetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/resume`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Accept: 'application/json',
			'Idempotency-Key': idempotencyKey
		},
		body: JSON.stringify({ expected_sequence: expectedSequence })
	});
	if (!response.ok) throw await responseError(response, 'Resume session API');
	return response.json() as Promise<ResumeSessionResponse>;
}

export async function reviewRun(
	runId: string,
	approvalId: string,
	decision: ReviewDecision,
	idempotencyKey: string,
	note: string | null = null
): Promise<ReviewResponse> {
	const request: ReviewRequest = { decision, note };
	const response = await apiFetch(
		`/api/v1/runs/${encodeURIComponent(runId)}/approvals/${encodeURIComponent(approvalId)}/decision`,
		{
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Accept: 'application/json',
				'Idempotency-Key': idempotencyKey
			},
			body: JSON.stringify(request)
		}
	);

	if (!response.ok) throw await responseError(response, 'Review API');
	return response.json() as Promise<ReviewResponse>;
}

export function subscribeToRun(
	runId: string,
	after: number,
	onEvent: (event: RunEvent) => void,
	onStatus: (status: StreamStatus) => void,
	onUnauthorized: () => void = () => {}
): () => void {
	const stream = new EventSource(
		`/api/v1/runs/${encodeURIComponent(runId)}/events?after=${encodeURIComponent(after)}`
	);
	const authorization = createStreamAuthorizationProbe(
		() => getAuthStatus(),
		() => {
			stream.close();
			onUnauthorized();
		}
	);
	stream.onopen = () => onStatus('connected');
	stream.onerror = () => {
		onStatus('reconnecting');
		authorization.check();
	};
	const handleMessage = (message: MessageEvent<string>) => {
		try {
			onEvent(JSON.parse(message.data) as RunEvent);
		} catch {
			// Ignore malformed frames; the stream remains usable for later valid events.
		}
	};
	stream.addEventListener('run.event', handleMessage);
	stream.onmessage = handleMessage;
	return () => {
		authorization.stop();
		stream.close();
	};
}

export function subscribeToSession(
	sessionId: string,
	after: number,
	onEvent: (event: SessionEvent) => void,
	onStatus: (status: StreamStatus) => void,
	onUnauthorized: () => void = () => {}
): () => void {
	const stream = new EventSource(
		`/api/v1/sessions/${encodeURIComponent(sessionId)}/events?after=${encodeURIComponent(after)}`
	);
	const authorization = createStreamAuthorizationProbe(
		() => getAuthStatus(),
		() => {
			stream.close();
			onUnauthorized();
		}
	);
	stream.onopen = () => onStatus('connected');
	stream.onerror = () => {
		onStatus('reconnecting');
		authorization.check();
	};
	const handleMessage = (message: MessageEvent<string>) => {
		try {
			onEvent(JSON.parse(message.data) as SessionEvent);
		} catch {
			// Ignore malformed frames; durable replay can still deliver later valid events.
		}
	};
	stream.addEventListener('session.event', handleMessage);
	stream.onmessage = handleMessage;
	return () => {
		authorization.stop();
		stream.close();
	};
}
