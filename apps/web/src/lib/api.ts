import type {
	AuthenticationResponse,
	AuthStatusResponse,
	BootstrapRequest,
	CreateSessionRequest,
	CreateSessionResponse,
	LoginRequest,
	LogoutResponse,
	OverviewResponse,
	ResumeSessionResponse,
	ReviewDecision,
	ReviewRequest,
	ReviewResponse,
	RunEvent,
	SessionDetail,
	SessionEvent,
	SessionSummary,
	StartTurnResponse
} from './types';
import { apiFetch } from './http';

export type StreamStatus = 'connected' | 'reconnecting';

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

export async function logout(): Promise<LogoutResponse> {
	const response = await apiFetch('/api/v1/auth/logout', {
		method: 'POST',
		headers: { Accept: 'application/json' }
	});
	if (!response.ok) throw await responseError(response, 'Logout API');
	return response.json() as Promise<LogoutResponse>;
}

export async function listSessions(signal?: AbortSignal): Promise<SessionSummary[]> {
	const response = await apiFetch('/api/v1/sessions', {
		headers: { Accept: 'application/json' },
		signal
	});
	if (!response.ok) throw await responseError(response, 'Sessions API');
	return response.json() as Promise<SessionSummary[]>;
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
	onStatus: (status: StreamStatus) => void
): () => void {
	const stream = new EventSource(
		`/api/v1/runs/${encodeURIComponent(runId)}/events?after=${encodeURIComponent(after)}`
	);
	stream.onopen = () => onStatus('connected');
	stream.onerror = () => onStatus('reconnecting');
	const handleMessage = (message: MessageEvent<string>) => {
		try {
			onEvent(JSON.parse(message.data) as RunEvent);
		} catch {
			// Ignore malformed frames; the stream remains usable for later valid events.
		}
	};
	stream.addEventListener('run.event', handleMessage);
	stream.onmessage = handleMessage;
	return () => stream.close();
}

export function subscribeToSession(
	sessionId: string,
	after: number,
	onEvent: (event: SessionEvent) => void,
	onStatus: (status: StreamStatus) => void
): () => void {
	const stream = new EventSource(
		`/api/v1/sessions/${encodeURIComponent(sessionId)}/events?after=${encodeURIComponent(after)}`
	);
	stream.onopen = () => onStatus('connected');
	stream.onerror = () => onStatus('reconnecting');
	const handleMessage = (message: MessageEvent<string>) => {
		try {
			onEvent(JSON.parse(message.data) as SessionEvent);
		} catch {
			// Ignore malformed frames; durable replay can still deliver later valid events.
		}
	};
	stream.addEventListener('session.event', handleMessage);
	stream.onmessage = handleMessage;
	return () => stream.close();
}
