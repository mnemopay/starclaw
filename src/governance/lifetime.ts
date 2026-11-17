import { AsyncLocalStorage } from 'node:async_hooks';

// Captured per sandbox invocation, rather than looked up on a shared conversation.
// A late approval must not revive a tool call after its sandbox has exited.
const lifetime = new AsyncLocalStorage<() => boolean>();
export function withActionLifetime<T>(live: () => boolean, fn: () => Promise<T>): Promise<T> {
  const parent = lifetime.getStore();
  return lifetime.run(() => live() && (parent?.() ?? true), fn);
}
export function actionIsLive(): boolean { return lifetime.getStore()?.() ?? true; }
