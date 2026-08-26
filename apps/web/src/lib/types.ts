export type MetricTone = 'neutral' | 'positive' | 'warning' | 'critical';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'investigating' | 'mitigating' | 'resolved';
export type RunStatus =
	| 'waiting_for_approval'
	| 'queued'
	| 'running'
	| 'blocked'
	| 'needs_attention'
	| 'active'
	| 'succeeded'
	| 'failed'
	| 'cancelled';
export type SessionStatus = 'ready' | 'running' | 'needs_attention';
export type SessionTurnStatus = 'open' | 'flushed' | 'interrupted';

export type EventType =
	'user' | 'reasoning' | 'step' | 'tool_call' | 'evidence' | 'approval' | 'context' | 'system';

export type ApprovalScope = 'allow_once';
export type SandboxProfile =
	'read_only' | 'workspace_write' | 'isolated_container' | 'production_guarded';
export type ToolEffect = 'read_only' | 'local_write' | 'production_write' | 'destructive';
export type ToolExecutorStatus = 'available' | 'unavailable';
export type ToolCallStatus =
	| 'requested'
	| 'waiting_for_approval'
	| 'queued'
	| 'running'
	| 'not_dispatched'
	| 'succeeded'
	| 'failed'
	| 'cancelled'
	| 'outcome_unknown';
export type PolicyDecision = 'allow' | 'require_approval' | 'deny';
export type ReviewDecision = 'approve' | 'reject';
export type NotDispatchedReason =
	| 'approval_rejected'
	| 'executor_unavailable'
	| 'sandbox_unavailable'
	| 'policy_denied'
	| 'policy_changed';

export interface ToolCall {
	call_id: string;
	tool: string;
	tool_version: string;
	arguments: unknown;
	arguments_digest: string;
	effect: ToolEffect;
	sandbox_profile: SandboxProfile;
	executor_status: ToolExecutorStatus;
}

export type ToolOutcome =
	| {
			status: 'succeeded';
			summary: string;
			output_digest?: string;
	  }
	| {
			status: 'failed';
			summary: string;
			error_code?: string;
	  }
	| {
			status: 'cancelled';
			summary: string;
	  }
	| {
			status: 'not_dispatched';
			reason: NotDispatchedReason;
			summary: string;
	  }
	| {
			status: 'outcome_unknown';
			summary: string;
	  };

export type RunEventData =
	| {
			kind: 'tool_call_requested';
			call: ToolCall;
			status: ToolCallStatus;
	  }
	| {
			kind: 'tool_policy_decided';
			call_id: string;
			decision: PolicyDecision;
			policy_revision: string;
			reason: string;
	  }
	| {
			kind: 'approval_requested';
			approval_id: string;
			call_id: string;
			scope: ApprovalScope;
			status: ToolCallStatus;
	  }
	| {
			kind: 'approval_decided';
			approval_id: string;
			call_id: string;
			decision: ReviewDecision;
			status: ToolCallStatus;
	  }
	| {
			kind: 'tool_dispatch_started';
			call_id: string;
			executor: string;
			executor_status: ToolExecutorStatus;
			sandbox_profile: SandboxProfile;
			status: ToolCallStatus;
	  }
	| {
			kind: 'tool_result';
			call_id: string;
			outcome: ToolOutcome;
			status: ToolCallStatus;
	  };

export interface ApprovalState {
	id: string;
	status: 'pending' | 'approved' | 'rejected';
	action: string;
	tool: string;
	change: string;
	requires_approval: boolean;
	call_id?: string;
	policy_revision?: string;
	arguments_digest?: string;
	sandbox_profile?: SandboxProfile;
	scope?: ApprovalScope;
}

export interface RunEvent {
	id?: string;
	sequence: number;
	turn: number;
	step: number;
	type: EventType;
	title: string;
	at: string;
	summary?: string;
	content?: string;
	metadata?: Record<string, unknown>;
	approval?: ApprovalState;
	data?: RunEventData;
	source?: 'api' | 'demo';
	stream?: 'run' | 'session';
	local_order?: number;
}

export interface SessionSummary {
	id: string;
	title: string;
	status: SessionStatus;
	created_at: string;
	updated_at: string;
	sequence: number;
	active_turn_id?: string;
}

export interface SessionTurn {
	id: string;
	session_id: string;
	ordinal: number;
	status: SessionTurnStatus;
	user_message: string;
	assistant_message?: string;
	started_at: string;
	completed_at?: string;
}

export type SessionEventData =
	| { kind: 'session_created'; title: string }
	| { kind: 'run_attached'; run_id: string }
	| { kind: 'session_resumed'; from_status: SessionStatus }
	| { kind: 'user_message'; turn_id: string; content: string }
	| { kind: 'assistant_message'; turn_id: string; content: string }
	| { kind: 'turn_flushed'; turn_id: string }
	| { kind: 'turn_interrupted'; turn_id: string; reason: string };

export interface SessionEvent {
	sequence: number;
	id: string;
	at: string;
	data: SessionEventData;
}

export interface SessionDetail {
	session: SessionSummary;
	run_ids: string[];
	turns: SessionTurn[];
	events: SessionEvent[];
}

export interface StartTurnRequest {
	turn_id: string;
	user_message: string;
	expected_sequence: number;
}

export interface StartTurnResponse {
	session: SessionSummary;
	turn: SessionTurn;
	event: SessionEvent;
	replayed: boolean;
}

export interface FlushSessionRequest {
	turn_id: string;
	assistant_message?: string;
	expected_sequence: number;
}

export interface SessionFlushAck {
	session_id: string;
	turn_id: string;
	durability_sequence: number;
}

export interface FlushSessionResponse {
	session: SessionSummary;
	turn: SessionTurn;
	events: SessionEvent[];
	ack: SessionFlushAck;
	replayed: boolean;
}

export interface ResumeSessionResponse {
	session: SessionSummary;
	event: SessionEvent;
	replayed: boolean;
}

export interface IncidentOverview {
	id: string;
	title: string;
	severity: Severity;
	status: IncidentStatus;
	service: string;
	region: string;
	user_impact: string;
	since: string;
}

export interface RunOverview {
	id: string;
	status: RunStatus;
	environment: string;
	started_at: string;
	duration_seconds: number;
	agent: string;
	sequence: number;
}

export interface Metric {
	label: string;
	value: string;
	unit?: string;
	trend?: string;
	tone?: MetricTone;
}

export interface EvidenceItem {
	id: string;
	at: string;
	label: string;
	source: string;
}

export interface ToolPolicy {
	name: string;
	allows: string[];
	requires_approval: string[];
	denies: string[];
}

export interface OverviewResponse {
	primary_session_id: string;
	incident: IncidentOverview;
	run: RunOverview;
	metrics: Metric[];
	recent_events: RunEvent[];
	evidence?: EvidenceItem[];
	tool_policy?: ToolPolicy;
}

export interface ReviewRequest {
	decision: ReviewDecision;
	note: string | null;
}

export interface ReviewResponse {
	run: RunOverview;
	event: RunEvent;
	replayed: boolean;
}

export type DataSource = 'api' | 'demo';
