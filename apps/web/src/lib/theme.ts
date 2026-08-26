export const THEME_STORAGE_KEY = 'zeus.theme';

export type ThemePreference = 'light' | 'dark' | 'system';
export type ResolvedTheme = Exclude<ThemePreference, 'system'>;

type ThemeStorage = Pick<Storage, 'getItem' | 'setItem'>;
type ThemeRoot = Pick<HTMLElement, 'classList' | 'dataset' | 'style'>;

export function parseThemePreference(value: unknown): ThemePreference {
	return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}

export function resolveTheme(
	preference: ThemePreference,
	systemPrefersDark: boolean
): ResolvedTheme {
	if (preference === 'system') return systemPrefersDark ? 'dark' : 'light';
	return preference;
}

function browserStorage(): ThemeStorage | null {
	if (typeof window === 'undefined') return null;
	try {
		return window.localStorage;
	} catch {
		return null;
	}
}

function browserSystemPrefersDark(): boolean {
	return (
		typeof window !== 'undefined' &&
		typeof window.matchMedia === 'function' &&
		window.matchMedia('(prefers-color-scheme: dark)').matches
	);
}

export function readThemePreference(
	storage: ThemeStorage | null = browserStorage()
): ThemePreference {
	if (!storage) return 'system';
	try {
		return parseThemePreference(storage.getItem(THEME_STORAGE_KEY));
	} catch {
		return 'system';
	}
}

export function saveThemePreference(
	preference: ThemePreference,
	storage: ThemeStorage | null = browserStorage()
): void {
	if (!storage) return;
	try {
		storage.setItem(THEME_STORAGE_KEY, preference);
	} catch {
		// The selected theme still applies for this page when storage is unavailable.
	}
}

export function applyThemePreference(
	preference: ThemePreference,
	root: ThemeRoot | null = typeof document === 'undefined' ? null : document.documentElement,
	systemPrefersDark = browserSystemPrefersDark()
): ResolvedTheme {
	const resolved = resolveTheme(preference, systemPrefersDark);
	if (!root) return resolved;

	root.classList.toggle('dark', resolved === 'dark');
	root.dataset.theme = resolved;
	root.style.colorScheme = resolved;
	return resolved;
}

export function selectThemePreference(
	preference: ThemePreference,
	storage: ThemeStorage | null = browserStorage(),
	root: ThemeRoot | null = typeof document === 'undefined' ? null : document.documentElement,
	systemPrefersDark = browserSystemPrefersDark()
): ResolvedTheme {
	saveThemePreference(preference, storage);
	return applyThemePreference(preference, root, systemPrefersDark);
}
