const { ensureRootDid } = require('./create-did');

(async () => {
  try {
    const { artifacts } = await ensureRootDid();
    const outputs = artifacts?.outputs || [];
    if (outputs.length === 0) {
      console.log('⚠️ DID artifacts were not generated. Ensure SECRET_KEY is set and writable paths exist.');
    } else {
      for (const output of outputs) {
        console.log(`✅ ${output.type.toUpperCase()} artifact available at ${output.path}`);
      }
    }
  } catch (err) {
    console.error('❌ Error exporting DID artifacts:', err);
    process.exitCode = 1;
  }
})();
