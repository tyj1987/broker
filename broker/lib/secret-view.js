export function renderSecretFields(fields, profile = 'strict') {
  const source = fields && typeof fields === 'object' ? fields : {};
  if (profile !== 'strict') return { ...source };
  return Object.fromEntries(Object.keys(source).map((field) => [field, '[REDACTED]']));
}

