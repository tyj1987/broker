// Serialize in-process configuration transactions, including rollback. Reading
// must wait for in-flight mutations; proxy streaming does not hold this gate.
export function createMutationGate({ maxPending = 64 } = {}) {
  let tail = Promise.resolve();
  let pending = 0;
  return {
    async run(operation) {
      if (pending >= maxPending) {
        const error = new Error('Configuration transaction queue is full');
        error.statusCode = 503;
        throw error;
      }
      pending += 1;
      const previous = tail;
      let release;
      tail = new Promise((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        return await operation();
      } finally {
        pending -= 1;
        release();
      }
    },
    async idle() {
      while (pending) await tail;
    },
    get pending() {
      return pending;
    },
  };
}
