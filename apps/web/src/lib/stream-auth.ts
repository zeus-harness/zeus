export interface AuthenticationStatusLike {
	authenticated: boolean;
}

export interface StreamAuthorizationProbe {
	check: () => void;
	stop: () => void;
}

export function createStreamAuthorizationProbe(
	loadStatus: () => Promise<AuthenticationStatusLike>,
	onUnauthorized: () => void
): StreamAuthorizationProbe {
	let active = true;
	let checking = false;

	return {
		check() {
			if (!active || checking) return;
			checking = true;
			void loadStatus()
				.then((status) => {
					if (active && !status.authenticated) onUnauthorized();
				})
				.catch(() => {
					// A network failure is not proof that the durable login was revoked.
				})
				.finally(() => {
					checking = false;
				});
		},
		stop() {
			active = false;
		}
	};
}
