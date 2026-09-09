export async function reloadRuntimeAtomically({ prepareConfig, prepareSecrets, commit }) {
  if (typeof prepareConfig !== 'function' || typeof prepareSecrets !== 'function' || typeof commit !== 'function') {
    throw new TypeError('runtime reload requires prepareConfig, prepareSecrets and commit');
  }
  const config = await prepareConfig();
  const secrets = await prepareSecrets();
  return commit({ config, secrets });
}
