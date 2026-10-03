export interface KpiEvent {
  kpiId: string;
  value: number;
  unit: 'ms' | 'bytes' | 'boolean';
  timestamp: number;
  sessionId: string;
  executionContext: {
    cryptoMode: 'true';
    hostClass: 'desktop' | 'mobile-emulation' | 'target-edge';
    networkMode: 'none' | 'emulated';
  };
  context?: Record<string, string | number | boolean>;
}

class KpiTelemetryService {
  private events: KpiEvent[] = [];
  private sessionId: string;
  private isEnabled: boolean = true;

  constructor() {
    this.sessionId = crypto.randomUUID();
    // Dual-safe environment inspection: Node.js (CJS/process.env) vs Browser (Vite/ESM)
    let envVal: string | undefined;
    if (typeof process !== 'undefined' && process.env) {
      envVal = process.env.VITE_ENABLE_KPI_TELEMETRY;
    } else {
      try {
        // Safe access in browser/ESM without throwing ReferenceError
        envVal = (typeof import.meta !== 'undefined' ? (import.meta as any)?.env?.VITE_ENABLE_KPI_TELEMETRY : undefined);
      } catch {
        envVal = undefined;
      }
    }
    this.isEnabled = envVal !== 'false';
  }

  public record(
    kpiId: string,
    value: number,
    unit: 'ms' | 'bytes' | 'boolean',
    context?: Record<string, string | number | boolean>
  ): void {
    if (!this.isEnabled) return;

    const event: KpiEvent = {
      kpiId,
      value,
      unit,
      timestamp: Date.now(),
      sessionId: this.sessionId,
      executionContext: {
        cryptoMode: 'true',
        // In a real environment, we might detect this dynamically. Assuming desktop for now.
        hostClass: 'desktop', 
        networkMode: 'none',
      },
      context,
    };

    this.events.push(event);
    console.debug(`[KPI] ${kpiId}: ${value} ${unit}`, event);
  }

  public getSnapshot(): KpiEvent[] {
    return [...this.events];
  }

  public exportSnapshotAsJson(): string {
    return JSON.stringify(this.getSnapshot(), null, 2);
  }

  public clear(): void {
    this.events = [];
  }

  public disable(): void {
    this.isEnabled = false;
  }

  public enable(): void {
    this.isEnabled = true;
  }
}

export const KpiTelemetry = new KpiTelemetryService();
