const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export const CSRF_COOKIE_NAME = 'zeus_csrf';
export const CSRF_HEADER_NAME = 'X-CSRF-Token';

export function readCookie(name: string, cookieHeader: string): string | null {
	for (const segment of cookieHeader.split(';')) {
		const cookie = segment.trim();
		const separator = cookie.indexOf('=');
		if (separator < 0 || cookie.slice(0, separator) !== name) continue;
		const value = cookie.slice(separator + 1);
		try {
			return decodeURIComponent(value);
		} catch {
			return value;
		}
	}
	return null;
}

export function requestHeaders(
	method: string | undefined,
	initial: HeadersInit | undefined,
	cookieHeader: string
): Headers {
	const headers = new Headers(initial);
	if (!SAFE_METHODS.has((method ?? 'GET').toUpperCase())) {
		const csrfToken = readCookie(CSRF_COOKIE_NAME, cookieHeader);
		if (csrfToken) headers.set(CSRF_HEADER_NAME, csrfToken);
	}
	return headers;
}

export function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
	let cookieHeader = '';
	try {
		cookieHeader = typeof document === 'undefined' ? '' : document.cookie;
	} catch {
		// Cookie access can be disabled by browser policy; the API will fail closed.
	}
	const request = typeof Request !== 'undefined' && input instanceof Request ? input : null;
	return fetch(input, {
		...init,
		credentials: init.credentials ?? 'same-origin',
		headers: requestHeaders(
			init.method ?? request?.method,
			init.headers ?? request?.headers,
			cookieHeader
		)
	});
}
