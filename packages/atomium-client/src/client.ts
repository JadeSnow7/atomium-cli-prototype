import type { JsonRpcRequest, JsonRpcResponse, TaskEvent } from "@atomium/protocol-types";
import type { RpcTransport } from "./transport";

export class AtomiumClient {
  private nextId = 1;
  private lastSeq = 0;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private eventListeners = new Set<(ev: TaskEvent) => void>();

  constructor(private readonly transport: RpcTransport) {
    this.transport.onMessage((frame) => this.handleFrame(frame));
    this.transport.onStateChange((state) => {
      if (state === "open") {
        // 断线重连后自动按 lastSeq 游标补拉缺失事件
        void this.call("events.subscribe", { after_seq: this.lastSeq }).catch(() => {});
      }
    });
  }

  get cursor(): number {
    return this.lastSeq;
  }

  async connect(initialLastSeq = 0): Promise<void> {
    this.lastSeq = initialLastSeq;
    await this.transport.connect();
  }

  disconnect(): void {
    this.transport.disconnect();
  }

  onEvent(handler: (ev: TaskEvent) => void): () => void {
    this.eventListeners.add(handler);
    return () => this.eventListeners.delete(handler);
  }

  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = this.nextId++;
    const req: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.transport.send(JSON.stringify(req)).catch((err) => {
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  private handleFrame(raw: string): void {
    const msg = JSON.parse(raw) as JsonRpcResponse & { method?: string; params?: TaskEvent };
    if (msg.method === "events.push" && msg.params) {
      const seq = Number(msg.params.seq);
      if (seq > this.lastSeq) {
        this.lastSeq = seq;
      }
      this.eventListeners.forEach((fn) => fn(msg.params!));
      return;
    }
    const id = typeof msg.id === "number" ? msg.id : Number(msg.id);
    const waiter = this.pending.get(id);
    if (!waiter) return;
    this.pending.delete(id);
    if (msg.error) {
      waiter.reject(new Error(`[${msg.error.code}] ${msg.error.message}`));
    } else {
      waiter.resolve(msg.result);
    }
  }
}
