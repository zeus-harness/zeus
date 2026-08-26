import assert from 'node:assert/strict';
import test from 'node:test';

import {
	THEME_STORAGE_KEY,
	applyThemePreference,
	parseThemePreference,
	readThemePreference,
	resolveTheme,
	selectThemePreference
} from './theme.ts';

class MemoryStorage {
	readonly values = new Map<string, string>();

	getItem(key: string): string | null {
		return this.values.get(key) ?? null;
	}

	setItem(key: string, value: string): void {
		this.values.set(key, value);
	}
}

function themeRoot() {
	const classes = new Set<string>();
	const root = {
		classList: {
			toggle(token: string, force?: boolean) {
				const enabled = force ?? !classes.has(token);
				if (enabled) classes.add(token);
				else classes.delete(token);
				return enabled;
			}
		},
		dataset: {} as Record<string, string>,
		style: { colorScheme: '' }
	};
	return { classes, root };
}

test('normalizes missing or invalid preferences to system', () => {
	assert.equal(parseThemePreference(null), 'system');
	assert.equal(parseThemePreference('sepia'), 'system');
	assert.equal(parseThemePreference('light'), 'light');
	assert.equal(parseThemePreference('dark'), 'dark');
	assert.equal(parseThemePreference('system'), 'system');
});

test('resolves system mode against the current media preference', () => {
	assert.equal(resolveTheme('system', true), 'dark');
	assert.equal(resolveTheme('system', false), 'light');
	assert.equal(resolveTheme('light', true), 'light');
	assert.equal(resolveTheme('dark', false), 'dark');
});

test('reads a persisted preference and rejects unsupported stored values', () => {
	const storage = new MemoryStorage();
	storage.setItem(THEME_STORAGE_KEY, 'dark');
	assert.equal(readThemePreference(storage), 'dark');

	storage.setItem(THEME_STORAGE_KEY, 'unsupported');
	assert.equal(readThemePreference(storage), 'system');
});

test('applies the resolved class, dataset, and color scheme', () => {
	const { classes, root } = themeRoot();

	assert.equal(applyThemePreference('system', root as never, true), 'dark');
	assert.equal(classes.has('dark'), true);
	assert.equal(root.dataset.theme, 'dark');
	assert.equal(root.style.colorScheme, 'dark');

	assert.equal(applyThemePreference('light', root as never, true), 'light');
	assert.equal(classes.has('dark'), false);
	assert.equal(root.dataset.theme, 'light');
	assert.equal(root.style.colorScheme, 'light');
});

test('persists a selection and applies it in one operation', () => {
	const storage = new MemoryStorage();
	const { classes, root } = themeRoot();

	assert.equal(selectThemePreference('dark', storage, root as never, false), 'dark');
	assert.equal(storage.getItem(THEME_STORAGE_KEY), 'dark');
	assert.equal(classes.has('dark'), true);
});
