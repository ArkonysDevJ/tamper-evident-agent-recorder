// SPDX-License-Identifier: AGPL-3.0-or-later
// Layer 3 of mutual exclusion (Blueprint §5.3): one strict serial FIFO queue
// per chain. Each operation starts only after the previous one settled.

export class SerialQueue {
  private tail: Promise<unknown> = Promise.resolve();
  private closed = false;

  run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(new Error('queue closed'));
    const result = this.tail.then(fn);
    this.tail = result.catch(() => undefined);
    return result;
  }

  /** Stops admitting work and resolves once everything already queued has settled. */
  async drain(): Promise<void> {
    this.closed = true;
    await this.tail;
  }
}
