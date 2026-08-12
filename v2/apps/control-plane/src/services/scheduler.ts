import { makeWorkerUtils, type WorkerUtils } from "graphile-worker";

export interface OperationScheduler {
  readonly initialEnqueueIsTransactional: boolean;
  enqueue(operationId: string, runAt?: Date): Promise<void>;
  close(): Promise<void>;
}

export class InlineOperationScheduler implements OperationScheduler {
  readonly initialEnqueueIsTransactional = false;
  private handler?: (operationId: string) => Promise<void>;
  private pending = new Set<string>();
  bind(handler: (operationId: string) => Promise<void>): void { this.handler = handler; }
  async enqueue(operationId: string, runAt?: Date): Promise<void> {
    if (this.pending.has(operationId)) return;
    this.pending.add(operationId);
    const delay = Math.max(0, (runAt?.getTime() ?? Date.now()) - Date.now());
    setTimeout(() => {
      this.pending.delete(operationId);
      void this.handler?.(operationId).catch(() => undefined);
    }, delay).unref();
  }
  async drain(operationId: string, maxTurns = 40): Promise<void> {
    if (!this.handler) throw new Error("Inline scheduler is not bound");
    for (let turn = 0; turn < maxTurns; turn += 1) await this.handler(operationId);
  }
  async close(): Promise<void> { this.pending.clear(); }
}

export class GraphileOperationScheduler implements OperationScheduler {
  readonly initialEnqueueIsTransactional = true;
  private utils?: WorkerUtils;
  constructor(private readonly connectionString: string) {}
  private async getUtils(): Promise<WorkerUtils> { this.utils ??= await makeWorkerUtils({ connectionString: this.connectionString }); return this.utils; }
  async enqueue(operationId: string, runAt?: Date): Promise<void> {
    await (await this.getUtils()).addJob("advance_operation", { operationId }, { maxAttempts: 3, jobKey: `operation:${operationId}`, ...(runAt ? { runAt } : {}) });
  }
  async close(): Promise<void> { await this.utils?.release(); }
}
