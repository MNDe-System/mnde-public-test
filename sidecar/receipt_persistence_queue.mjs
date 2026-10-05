import { appendFile, mkdir, open } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalizeJson } from "../shared/json.ts";

export const RECEIPT_QUEUE_SATURATED = "ERR_RECEIPT_QUEUE_SATURATED";
export const SYSTEM_SATURATED = "ERR_SYSTEM_SATURATED";
export const RECEIPT_PERSISTENCE_CONFIG = "ERR_RECEIPT_PERSISTENCE_CONFIG";
export const RECEIPT_FLUSH_FAILED = "ERR_RECEIPT_FLUSH_FAILED";

const DURABILITY_MODES = new Set(["strict_audit", "throughput"]);

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

export function validateReceiptPersistenceConfig(config) {
  const problems = [];
  if (!config || typeof config !== "object") problems.push("config must be an object");
  if (!config?.path || typeof config.path !== "string") problems.push("path must be a non-empty string");
  if (!DURABILITY_MODES.has(config?.durability_mode)) problems.push("durability_mode must be strict_audit or throughput");
  if (!positiveInteger(config?.max_items)) problems.push("max_items must be a positive safe integer");
  if (!positiveInteger(config?.max_bytes)) problems.push("max_bytes must be a positive safe integer");
  if (!positiveInteger(config?.max_batch_size)) problems.push("max_batch_size must be a positive safe integer");
  if (!positiveInteger(config?.max_batch_age_ms)) problems.push("max_batch_age_ms must be a positive safe integer");
  if (config?.flush_timeout_ms !== undefined && !positiveInteger(config.flush_timeout_ms)) {
    problems.push("flush_timeout_ms must be a positive safe integer");
  }
  if (positiveInteger(config?.max_items) && positiveInteger(config?.max_batch_size) && config.max_batch_size > config.max_items) {
    problems.push("max_batch_size cannot exceed max_items");
  }
  if (positiveInteger(config?.max_bytes) && positiveInteger(config?.max_items) && config.max_bytes < config.max_items * 128) {
    problems.push("max_bytes is too small for configured max_items");
  }
  if (problems.length > 0) {
    throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: ${problems.join("; ")}`);
  }
  return {
    path: config.path,
    durability_mode: config.durability_mode,
    max_items: config.max_items,
    max_bytes: config.max_bytes,
    max_batch_size: config.max_batch_size,
    max_batch_age_ms: config.max_batch_age_ms,
    flush_timeout_ms: config.flush_timeout_ms ?? 2_000
  };
}

export class ReceiptPersistenceQueue {
  #config;
  #queue = [];
  #queuedBytes = 0;
  #timer = null;
  #flushActive = false;
  #started = false;
  #closed = false;
  #failClosedReason = null;
  #metrics = {
    accepted: 0,
    saturated: 0,
    flush_failures: 0,
    flush_count: 0,
    flush_timeouts: 0,
    flushed_receipts: 0,
    queue_depth: 0,
    queue_bytes: 0,
    max_queue_depth: 0,
    max_queue_bytes: 0,
    last_flush_ms: 0,
    persistence_flush_ms_total: 0
  };

  constructor(config) {
    this.#config = validateReceiptPersistenceConfig(config);
  }

  get config() {
    return { ...this.#config };
  }

  metrics() {
    return { ...this.#metrics, fail_closed: Boolean(this.#failClosedReason), fail_closed_reason: this.#failClosedReason };
  }

  async start() {
    if (this.#started) return;
    await mkdir(dirname(this.#config.path), { recursive: true });
    const handle = await open(this.#config.path, "a");
    await handle.close();
    this.#started = true;
  }

  async enqueue(receipt) {
    if (!this.#started || this.#closed || this.#failClosedReason) {
      return { ok: false, reason_code: this.#failClosedReason ?? RECEIPT_FLUSH_FAILED };
    }

    const line = `${canonicalizeJson(receipt)}\n`;
    const byteLength = Buffer.byteLength(line, "utf8");
    if (
      this.#queue.length >= this.#config.max_items ||
      this.#queuedBytes + byteLength > this.#config.max_bytes
    ) {
      this.#metrics.saturated += 1;
      return { ok: false, reason_code: RECEIPT_QUEUE_SATURATED };
    }

    let resolveDurable;
    let rejectDurable;
    const durable = new Promise((resolve, reject) => {
      resolveDurable = resolve;
      rejectDurable = reject;
    });
    this.#queue.push({ line, byteLength, resolveDurable, rejectDurable });
    this.#queuedBytes += byteLength;
    this.#metrics.accepted += 1;
    this.#syncDepthMetrics();

    if (this.#queue.length >= this.#config.max_batch_size) {
      this.flush();
    } else {
      this.#scheduleFlush();
    }

    return { ok: true, durable, bytes: byteLength };
  }

  flush() {
    if (this.#flushActive || this.#queue.length === 0) return;
    this.#clearTimer();
    this.#flushActive = true;
    const batch = this.#queue.splice(0, this.#config.max_batch_size);
    const batchBytes = batch.reduce((sum, item) => sum + item.byteLength, 0);
    this.#queuedBytes -= batchBytes;
    this.#syncDepthMetrics();

    const started = performance.now();
    let timeout = null;
    const append = appendFile(this.#config.path, batch.map((item) => item.line).join(""), "utf8");
    const timeoutPromise = new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error(`${RECEIPT_FLUSH_FAILED}: flush timeout`)), this.#config.flush_timeout_ms);
      timeout.unref?.();
    });
    Promise.race([append, timeoutPromise])
      .then(() => {
        clearTimeout(timeout);
        const elapsed = performance.now() - started;
        this.#metrics.flush_count += 1;
        this.#metrics.flushed_receipts += batch.length;
        this.#metrics.last_flush_ms = Math.max(0, Math.round(elapsed));
        this.#metrics.persistence_flush_ms_total += this.#metrics.last_flush_ms;
        for (const item of batch) item.resolveDurable({ ok: true, persistence_flush_ms: this.#metrics.last_flush_ms });
      })
      .catch((error) => {
        clearTimeout(timeout);
        this.#failClosedReason = RECEIPT_FLUSH_FAILED;
        this.#metrics.flush_failures += 1;
        if (String(error?.message ?? "").includes("timeout")) this.#metrics.flush_timeouts += 1;
        for (const item of batch) item.rejectDurable(error);
        for (const item of this.#queue.splice(0)) item.rejectDurable(error);
        this.#queuedBytes = 0;
        this.#syncDepthMetrics();
      })
      .finally(() => {
        this.#flushActive = false;
        if (!this.#failClosedReason && this.#queue.length > 0) {
          if (this.#queue.length >= this.#config.max_batch_size) this.flush();
          else this.#scheduleFlush();
        }
      });
  }

  async shutdown() {
    this.#closed = true;
    this.#clearTimer();
    const deadline = Date.now() + this.#config.flush_timeout_ms;
    while (this.#queue.length > 0 || this.#flushActive) {
      if (Date.now() > deadline) {
        this.#failClosedReason = RECEIPT_FLUSH_FAILED;
        break;
      }
      if (!this.#flushActive) this.flush();
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
  }

  #scheduleFlush() {
    if (this.#timer || this.#closed) return;
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.flush();
    }, this.#config.max_batch_age_ms);
  }

  #clearTimer() {
    if (!this.#timer) return;
    clearTimeout(this.#timer);
    this.#timer = null;
  }

  #syncDepthMetrics() {
    this.#metrics.queue_depth = this.#queue.length;
    this.#metrics.queue_bytes = this.#queuedBytes;
    this.#metrics.max_queue_depth = Math.max(this.#metrics.max_queue_depth, this.#queue.length);
    this.#metrics.max_queue_bytes = Math.max(this.#metrics.max_queue_bytes, this.#queuedBytes);
  }
}

export class SystemSaturationController {
  #config;

  constructor(config) {
    this.#config = {
      max_inflight: config.max_inflight,
      inflight_shed_threshold: config.inflight_shed_threshold,
      max_event_loop_lag_ms: config.max_event_loop_lag_ms,
      queue_high_watermark_items: config.queue_high_watermark_items,
      queue_high_watermark_bytes: config.queue_high_watermark_bytes
    };
    if (!positiveInteger(this.#config.max_inflight)) throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: max_inflight must be positive`);
    if (!positiveInteger(this.#config.inflight_shed_threshold)) throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: inflight_shed_threshold must be positive`);
    if (this.#config.inflight_shed_threshold > this.#config.max_inflight) {
      throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: inflight_shed_threshold cannot exceed max_inflight`);
    }
    if (!positiveInteger(this.#config.max_event_loop_lag_ms)) throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: max_event_loop_lag_ms must be positive`);
    if (!positiveInteger(this.#config.queue_high_watermark_items)) throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: queue_high_watermark_items must be positive`);
    if (!positiveInteger(this.#config.queue_high_watermark_bytes)) throw new Error(`${RECEIPT_PERSISTENCE_CONFIG}: queue_high_watermark_bytes must be positive`);
  }

  config() {
    return { ...this.#config };
  }

  shouldRefuse(snapshot) {
    if (snapshot.inflight >= this.#config.inflight_shed_threshold || snapshot.inflight >= this.#config.max_inflight) {
      return { ok: false, reason_code: SYSTEM_SATURATED, saturation_signal: "inflight" };
    }
    if (snapshot.event_loop_lag_ms > this.#config.max_event_loop_lag_ms) {
      return { ok: false, reason_code: SYSTEM_SATURATED, saturation_signal: "event_loop_lag" };
    }
    if (snapshot.queue_depth > this.#config.queue_high_watermark_items) {
      return { ok: false, reason_code: SYSTEM_SATURATED, saturation_signal: "receipt_queue_depth" };
    }
    if (snapshot.queue_bytes > this.#config.queue_high_watermark_bytes) {
      return { ok: false, reason_code: SYSTEM_SATURATED, saturation_signal: "receipt_queue_bytes" };
    }
    return { ok: true };
  }
}
