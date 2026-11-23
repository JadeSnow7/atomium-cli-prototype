import type { RpcTransport, TransportState } from "../transport";

export interface TauriBridgeApi {
  invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
  listen: (event: string, handler: (event: { payload: string }) => void) => Promise<() => void>;
}

export class TauriIpcTransport implements RpcTransport {
  private unlisten: (() => void) | null = null;
  private msgHandlers = new Set<(raw: string) => void>();
  private stateHandlers = new Set<(s: TransportState) => void>();

  constructor(
    private readonly bridge: TauriBridgeApi,
    private readonly socketPath: string,
  ) {}

  async connect(): Promise<void> {
    this.emitState("connecting");
    this.unlisten = await this.bridge.listen("atomium:rpc_recv", (ev) => {
      if (typeof ev.payload === "string") {
        this.msgHandlers.forEach((fn) => fn(ev.payload));
      }
    });
    await this.bridge.invoke("rpc_connect", { socketPath: this.socketPath });
    this.emitState("open");
  }

  disconnect(): void {
    this.unlisten?.();
    this.unlisten = null;
    this.emitState("closed");
  }

  async send(rawJsonFrame: string): Promise<void> {
    await this.bridge.invoke("rpc_send", { frame: rawJsonFrame });
  }

  onMessage(handler: (raw: string) => void): () => void {
    this.msgHandlers.add(handler);
    return () => this.msgHandlers.delete(handler);
  }

  onStateChange(handler: (s: TransportState) => void): () => void {
    this.stateHandlers.add(handler);
    return () => this.stateHandlers.delete(handler);
  }

  private emitState(s: TransportState): void {
    this.stateHandlers.forEach((fn) => fn(s));
  }
}
