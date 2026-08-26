export interface SessionListQuery {
	cursor?: string;
	limit?: number;
}

export function buildSessionListPath({ cursor, limit }: SessionListQuery): string {
	const query = new URLSearchParams();
	if (cursor) query.set('cursor', cursor);
	if (limit !== undefined) query.set('limit', String(limit));
	return query.size > 0 ? `/api/v1/sessions?${query}` : '/api/v1/sessions';
}
