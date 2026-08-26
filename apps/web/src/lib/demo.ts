import type { OverviewResponse } from './types';

export const demoOverview: OverviewResponse = {
	primary_session_id: 'session-ZR-1842',
	incident: {
		id: 'INC-2048',
		title: 'Checkout API latency',
		severity: 'critical',
		status: 'mitigating',
		service: 'checkout-api',
		region: 'us-east-1',
		user_impact: 'Elevated latency, errors increasing',
		since: '10:36 UTC (5m)'
	},
	run: {
		id: 'ZR-1842',
		status: 'waiting_for_approval',
		environment: 'production',
		started_at: '2026-08-26T10:41:22+08:00',
		duration_seconds: 468,
		agent: 'Zeus Responder',
		sequence: 8
	},
	metrics: [
		{ label: 'p95 latency', value: '5.7', unit: 's', trend: 'threshold 2.0s', tone: 'critical' },
		{ label: 'Error rate', value: '22.4', unit: '%', trend: 'errors increasing', tone: 'critical' }
	],
	evidence: [
		{ id: 'evi-1', at: '10:41', label: 'RDS metrics', source: 'CloudWatch' },
		{ id: 'evi-2', at: '10:40', label: 'Slow query sample', source: 'RDS' },
		{ id: 'evi-3', at: '10:39', label: 'Connection pool', source: 'ProxySQL' },
		{ id: 'evi-4', at: '10:38', label: 'ALB target latency', source: 'CloudWatch' },
		{ id: 'evi-5', at: '10:37', label: 'Error logs', source: 'checkout-api' }
	],
	tool_policy: {
		name: 'RDS Safe Changes',
		allows: ['Modify DB instance (config)', 'No disruptive actions'],
		requires_approval: ['Parameter group changes', 'Scaling / capacity changes'],
		denies: ['Delete / Stop resources']
	},
	recent_events_page: { has_more: false },
	recent_events: [
		{
			id: 'evt-1',
			sequence: 1,
			turn: 1,
			step: 1,
			type: 'user',
			title: 'User',
			at: '10:41:22',
			summary: 'PagerDuty alert: Checkout API p95 latency > 2s for 5m (current 5.7s).',
			content: 'Affects us-east-1. Impacting conversion.'
		},
		{
			id: 'evt-2',
			sequence: 2,
			turn: 1,
			step: 1,
			type: 'reasoning',
			title: 'Reasoning',
			at: '10:41:24',
			summary: 'Elevated latency isolated to us-east-1. Hypothesis: DB connection saturation.',
			content: 'Plan: check DB metrics, slow queries, then connection pool.',
			metadata: { Model: 'deepseek-chat', Tokens: '1.2k in / 420 out', Latency: '1.1s' }
		},
		{
			id: 'evt-3',
			sequence: 3,
			turn: 1,
			step: 2,
			type: 'step',
			title: 'Step',
			at: '10:41:26',
			summary: 'Collect RDS metrics for Checkout DB',
			content: 'Connections, CPU, ReadLatency',
			metadata: { Model: 'deepseek-chat', Tokens: '340 in / 120 out', Latency: '620ms' }
		},
		{
			id: 'evt-4',
			sequence: 4,
			turn: 1,
			step: 2,
			type: 'tool_call',
			title: 'Tool call',
			at: '10:41:27',
			summary: 'aws.cloudwatch.get_metrics',
			content:
				'{\n  "namespace": "AWS/RDS",\n  "metric_names": ["DatabaseConnections", "CPUUtilization", "ReadLatency"],\n  "period": 60,\n  "statistics": ["Average", "Maximum"]\n}',
			metadata: { Policy: 'CloudWatch Read', Duration: '1.2s' }
		},
		{
			id: 'evt-5',
			sequence: 5,
			turn: 1,
			step: 2,
			type: 'evidence',
			title: 'Evidence',
			at: '10:41:29',
			summary: 'RDS metrics (us-east-1 / checkout-prod)',
			content:
				'DatabaseConnections   Maximum   1982 / 2000   ↑ high\nCPUUtilization        Average   78.4%         ↑ elevated\nReadLatency           Average   6632 ms       ↑ high'
		},
		{
			id: 'evt-6',
			sequence: 6,
			turn: 1,
			step: 4,
			type: 'tool_call',
			title: 'Production RDS change proposed',
			at: '10:41:30',
			summary: 'A production write was requested. It has not been dispatched or executed.',
			data: {
				kind: 'tool_call_requested',
				call: {
					call_id: 'call-rds-limit-001',
					tool: 'rds.connection_limit.update',
					tool_version: '1',
					arguments: {
						connections: 120,
						region: 'us-east-1',
						service: 'checkout-api'
					},
					arguments_digest:
						'sha256:1abd923258c2708eff661a7119542a9dade6c48f44e2d13547d4df973ae2b04d',
					effect: 'production_write',
					sandbox_profile: 'production_guarded',
					executor_status: 'unavailable'
				},
				status: 'requested'
			}
		},
		{
			id: 'evt-7',
			sequence: 7,
			turn: 1,
			step: 4,
			type: 'system',
			title: 'Production policy requires approval',
			at: '10:41:31',
			summary: 'Policy requires one explicit approval for this exact call and argument digest.',
			data: {
				kind: 'tool_policy_decided',
				call_id: 'call-rds-limit-001',
				decision: 'require_approval',
				policy_revision: 'production-guarded/v1',
				reason: 'production_write requires allow-once review'
			}
		},
		{
			id: 'evt-8',
			sequence: 8,
			turn: 1,
			step: 4,
			type: 'approval',
			title: 'Production change awaiting review',
			at: '10:41:30',
			summary: 'Approve or reject the guarded RDS connection change.',
			approval: {
				id: 'APR-901',
				status: 'pending',
				action: 'update connection ceiling',
				tool: 'rds.connection_limit.update',
				change: 'checkout-api connections: 80 → 120',
				requires_approval: true,
				call_id: 'call-rds-limit-001',
				policy_revision: 'production-guarded/v1',
				arguments_digest: 'sha256:1abd923258c2708eff661a7119542a9dade6c48f44e2d13547d4df973ae2b04d',
				sandbox_profile: 'production_guarded',
				scope: 'allow_once'
			},
			data: {
				kind: 'approval_requested',
				approval_id: 'APR-901',
				call_id: 'call-rds-limit-001',
				scope: 'allow_once',
				status: 'waiting_for_approval'
			}
		}
	]
};
