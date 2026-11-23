export type TransportState = "connecting" | "open" | "closed";

export interface RpcTransport {
  connect(): Promise<void>;
  disconnect(): void;
  send(rawJsonFrame: string): Promise<void>;
  onMessage(handler: (rawJsonFrame: string) => void): () => void;
  onStateChange(handler: (state: TransportState) => void): () => void;
}
