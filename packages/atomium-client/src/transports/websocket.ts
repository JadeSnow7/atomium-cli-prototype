import type { RpcTransport, TransportState } from "../transport";

export interface WsTransportOptions {
  url: string;
  deviceToken: string;
}

export class WebSocketTransport implements RpcTransport {
  private ws: WebSocket | null = null;
  private manualClose = false;
  private retryMs = 500;
  private msgHandlers = new Set<(raw: string) => void>();
  private stateHandlers = new Set<(s: TransportState) => void>();

  constructor(private readonly opts: WsTransportOptions) {}

  async connect(): Promise<void> {
    this.manualClose = false;
    this.openSocket();
  }

  disconnect(): void {
    this.manualClose = true;
    this.ws?.close();
    this.ws = null;
    this.emitState("closed");
  }

  async send(rawJsonFrame: string): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocketTransport is not open");
    }
    this.ws.send(rawJsonFrame);
  }

  onMessage(handler: (raw: string) => void): () => void {
    this.msgHandlers.add(handler);
    return () => this.msgHandlers.delete(handler);
  }

  onStateChange(handler: (s: TransportState) => void): () => void {
    this.stateHandlers.add(handler);
    return () => this.stateHandlers.delete(handler);
  }

  private openSocket(): void {
    this.emitState("connecting");
    const url = `${this.opts.url}?token=${encodeURIComponent(this.opts.deviceToken)}`;
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.onopen = () => {
      this.retryMs = 500;
      this.emitState("open");
    };
    ws.onmessage = (e) => {
      if (typeof e.data === "string") {
        this.msgHandlers.forEach((fn) => fn(e.data));
      }
    };
    ws.onclose = () => {
      this.emitState("closed");
      if (!this.manualClose) {
        const delay = this.retryMs;
        this.retryMs = Math.min(this.retryMs * 2, 10_000);
        setTimeout(() => this.openSocket(), delay);
      }
    };
  }

  private emitState(s: TransportState): void {
    this.stateHandlers.forEach((fn) => fn(s));
  }
}
