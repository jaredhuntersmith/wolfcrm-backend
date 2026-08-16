// WolfCRM production entrypoint with the additive Texting Blue iMessage transport.
// The existing index.js still owns Twilio SMS, Voice, voicemail, automations,
// finance, Google Sheets, and every current API route.
process.env.WOLFCRM_SKIP_SERVER_START = "true";

const [{ app, pool, startServer }, { installIMessageSystem }] = await Promise.all([
  import("./index.js"),
  import("./imessage.js")
]);

await installIMessageSystem({ app, pool });
await startServer();
