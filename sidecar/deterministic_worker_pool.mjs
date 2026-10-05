import { Worker } from "node:worker_threads";

export const WORKER_POOL_SATURATED = "ERR_WORKER_POOL_SATURATED";
export const WORKER_POOL_FAILED = "ERR_WORKER_POOL_FAILED";
export const WORKER_TIMEOUT = "ERR_WORKER_TIMEOUT";

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

export function validateWorkerPoolConfig(config) {
  const problems = [];
  if (!positiveInteger(config?.worker_count)) problems.push("worker_count must be a positive safe integer");
  if (!positiveInteger(config?.max_queue_depth)) problems.push("max_queue_depth must be a positive safe integer");
  if (config?.task_timeout_ms !== undefined && !positiveInteger(config.task_timeout_ms)) {
    problems.push("task_timeout_ms must be a positive safe integer");
  }
  if (problems.length > 0) throw new Error(`ERR_WORKER_POOL_CONFIG: ${problems.join("; ")}`);
  return {
    worker_count: config.worker_count,
    max_queue_depth: config.max_queue_depth,
    task_timeout_ms: config.task_timeout_ms ?? 2_000,
    worker_url: config.worker_url
  };
}

export class DeterministicWorkerPool {
  #config;
  #workers = [];
  #idle = [];
  #queue = [];
  #nextTaskId = 1;
  #closed = false;
  #metrics = {
    submitted: 0,
    completed: 0,
    failed: 0,
    refused: 0,
    queue_depth: 0,
    max_queue_depth: 0,
    queue_wait_ms_total: 0,
    queue_wait_ms_max: 0,
    exec_ms_total: 0,
    exec_ms_max: 0,
    busy_ms_total: 0,
    timeout_count: 0,
    restart_count: 0,
    started_at_ms: 0,
    workers: []
  };

  constructor(config) {
    this.#config = validateWorkerPoolConfig(config);
    this.#metrics.started_at_ms = performance.now();
  }

  start() {
    if (this.#workers.length > 0) return;
    for (let index = 0; index < this.#config.worker_count; index += 1) {
      const state = this.#createWorkerState(index);
      this.#workers.push(state);
      this.#idle.push(state);
    }
    this.#syncWorkerMetrics();
  }

  submit(raw_input) {
    if (this.#closed) return { ok: false, reason_code: WORKER_POOL_FAILED };
    this.start();
    if (this.#idle.length === 0 && this.#queue.length >= this.#config.max_queue_depth) {
      this.#metrics.refused += 1;
      return { ok: false, reason_code: WORKER_POOL_SATURATED };
    }

    let resolve;
    const promise = new Promise((done) => {
      resolve = done;
    });
    const task = {
      id: this.#nextTaskId,
      raw_input,
      enqueued_at_ms: performance.now(),
      resolve
    };
    this.#nextTaskId += 1;
    this.#metrics.submitted += 1;
    this.#queue.push(task);
    this.#syncDepthMetrics();
    this.#dispatch();
    return { ok: true, result: promise };
  }

  metrics() {
    this.#syncWorkerMetrics();
    const elapsed = Math.max(1, performance.now() - this.#metrics.started_at_ms);
    return {
      submitted: this.#metrics.submitted,
      completed: this.#metrics.completed,
      failed: this.#metrics.failed,
      refused: this.#metrics.refused,
      timeout_count: this.#metrics.timeout_count,
      restart_count: this.#metrics.restart_count,
      queue_depth: this.#metrics.queue_depth,
      max_queue_depth: this.#metrics.max_queue_depth,
      queue_wait_ms_avg: this.#metrics.completed === 0 ? 0 : Math.round(this.#metrics.queue_wait_ms_total / this.#metrics.completed),
      queue_wait_ms_max: this.#metrics.queue_wait_ms_max,
      exec_ms_avg: this.#metrics.completed === 0 ? 0 : Math.round(this.#metrics.exec_ms_total / this.#metrics.completed),
      exec_ms_max: this.#metrics.exec_ms_max,
      busy_ratio: Math.min(1, this.#metrics.busy_ms_total / (elapsed * this.#config.worker_count)),
      workers: this.#metrics.workers
    };
  }

  async shutdown() {
    this.#closed = true;
    for (const task of this.#queue.splice(0)) {
      task.resolve({ ok: false, reason_code: WORKER_POOL_FAILED });
    }
    await Promise.allSettled(this.#workers.map((state) => state.worker.terminate()));
    this.#workers = [];
    this.#idle = [];
    this.#syncDepthMetrics();
  }

  #dispatch() {
    while (this.#idle.length > 0 && this.#queue.length > 0) {
      const state = this.#idle.shift();
      const task = this.#queue.shift();
      const now = performance.now();
      const queueWait = Math.max(0, Math.round(now - task.enqueued_at_ms));
      state.busy = true;
      const timeout = setTimeout(() => this.#handleTaskTimeout(state, task.id), this.#config.task_timeout_ms);
      timeout.unref?.();
      state.active_task = { ...task, started_at_ms: now, queue_wait_ms: queueWait, timeout };
      this.#metrics.queue_wait_ms_total += queueWait;
      this.#metrics.queue_wait_ms_max = Math.max(this.#metrics.queue_wait_ms_max, queueWait);
      state.worker.postMessage({ task_id: task.id, raw_input: task.raw_input });
    }
    this.#syncDepthMetrics();
    this.#syncWorkerMetrics();
  }

  #handleMessage(state, message) {
    const task = state.active_task;
    if (!task || message?.task_id !== task.id) {
      this.#metrics.failed += 1;
      return;
    }
    clearTimeout(task.timeout);
    const busyMs = Math.max(0, Math.round(performance.now() - task.started_at_ms));
    const execMs = Math.max(0, Math.round(message.exec_ms ?? busyMs));
    state.busy = false;
    state.active_task = null;
    state.throughput += 1;
    state.busy_ms_total += busyMs;
    this.#metrics.completed += 1;
    this.#metrics.exec_ms_total += execMs;
    this.#metrics.exec_ms_max = Math.max(this.#metrics.exec_ms_max, execMs);
    this.#metrics.busy_ms_total += busyMs;
    const reply = {
      ...message,
      queue_wait_ms: task.queue_wait_ms
    };
    task.resolve(reply.ok ? reply : { ok: false, reason_code: reply.reason_code ?? WORKER_POOL_FAILED, queue_wait_ms: task.queue_wait_ms });
    if (!this.#closed) this.#idle.push(state);
    this.#dispatch();
  }

  #handleWorkerFailure(state, error) {
    if (state.replacing) return;
    state.failed += 1;
    this.#metrics.failed += 1;
    if (state.active_task) {
      clearTimeout(state.active_task.timeout);
      state.active_task.resolve({ ok: false, reason_code: WORKER_POOL_FAILED, error: error.message });
      state.active_task = null;
    }
    state.busy = false;
    this.#idle = this.#idle.filter((item) => item !== state);
    this.#replaceWorker(state);
    this.#dispatch();
    this.#syncWorkerMetrics();
  }

  #handleTaskTimeout(state, taskId) {
    const task = state.active_task;
    if (!task || task.id !== taskId) return;
    state.active_task = null;
    state.busy = false;
    state.failed += 1;
    this.#metrics.failed += 1;
    this.#metrics.timeout_count += 1;
    task.resolve({ ok: false, reason_code: WORKER_TIMEOUT, queue_wait_ms: task.queue_wait_ms });
    this.#idle = this.#idle.filter((item) => item !== state);
    this.#replaceWorker(state);
    this.#dispatch();
    this.#syncWorkerMetrics();
  }

  #createWorkerState(worker_id) {
    const worker = new Worker(this.#config.worker_url, { workerData: { worker_id } });
    const state = {
      worker,
      worker_id,
      busy: false,
      active_task: null,
      replacing: false,
      throughput: 0,
      failed: 0,
      busy_ms_total: 0
    };
    worker.on("message", (message) => this.#handleMessage(state, message));
    worker.on("error", (error) => this.#handleWorkerFailure(state, error));
    worker.on("exit", (code) => {
      if (!this.#closed && !state.replacing && code !== 0) {
        this.#handleWorkerFailure(state, new Error(`${WORKER_POOL_FAILED}: worker exited ${code}`));
      }
    });
    return state;
  }

  #replaceWorker(state) {
    if (this.#closed || state.replacing) return;
    state.replacing = true;
    this.#metrics.restart_count += 1;
    state.worker.terminate().catch(() => {});
    const replacement = this.#createWorkerState(state.worker_id);
    const index = this.#workers.indexOf(state);
    if (index >= 0) this.#workers[index] = replacement;
    else this.#workers.push(replacement);
    this.#idle.push(replacement);
  }

  #syncDepthMetrics() {
    this.#metrics.queue_depth = this.#queue.length;
    this.#metrics.max_queue_depth = Math.max(this.#metrics.max_queue_depth, this.#queue.length);
  }

  #syncWorkerMetrics() {
    this.#metrics.workers = this.#workers.map((state) => ({
      worker_id: state.worker_id,
      busy: state.busy ? 1 : 0,
      throughput: state.throughput,
      failed: state.failed,
      busy_ms_total: state.busy_ms_total,
      replacing: state.replacing ? 1 : 0
    }));
  }
}
