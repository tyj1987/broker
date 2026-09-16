// CI fixture wire projection only. Never an independent or durable backend.
export function fixtureReadPage(records, { after_sequence, through_sequence, limit }) {
  if (!Array.isArray(records) || !Number.isSafeInteger(after_sequence) || after_sequence < 0
    || !Number.isSafeInteger(through_sequence) || through_sequence <= after_sequence
    || !Number.isSafeInteger(limit) || limit < 1 || limit > 32) {
    throw new Error('Invalid synthetic page request');
  }
  return { after_sequence, through_sequence,
    anchors: records.filter(a => a.payload.sequence > after_sequence && a.payload.sequence <= through_sequence).slice(0, limit) };
}
