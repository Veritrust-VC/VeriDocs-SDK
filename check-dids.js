// check-dids.js
const { createAgentInstance } = require('./agent-setup');

(async () => {
  try {
    const agent = await createAgentInstance();
    const dids = await agent.didManagerFind();
    console.log('✅ Found DIDs:', dids);
  } catch (err) {
    console.error('❌ Error listing DIDs:', err);
  }
})();
