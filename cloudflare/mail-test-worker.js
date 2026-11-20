/**
 * VdigDNS email test: Cloudflare Email Worker.
 *
 * Cloudflare Email Routing hands every email sent to the test address to this Worker.
 * It passes the raw email to VdigDNS, which keeps it for one hour and analyses it.
 * Nothing is stored here.
 *
 * Settings (Worker -> Settings -> Variables and secrets):
 *   VDIG_URL     plain text   https://dig.sujaiprojects.stream
 *   VDIG_SECRET  secret       the same value as MAILTEST_SECRET in Vercel (24+ random characters)
 */
export default {
  async email(message, env) {
    // test+abc123@check.example.com (subaddressing) or abc123@example.com (catch-all): the id is the part we added
    const local = message.to.toLowerCase().split("@")[0];
    const id = (local.includes("+") ? local.split("+").pop() : local).replace(/[^a-z0-9]/g, "");
    if (!/^[a-z0-9]{8,24}$/.test(id)) {
      message.setReject("This isn't a VdigDNS test address. Get one at " + env.VDIG_URL + "/#email-test");
      return;
    }
    if (message.rawSize > 25 * 1024 * 1024) {
      message.setReject("Test emails must be under 25 MB.");
      return;
    }
    const raw = await new Response(message.raw).arrayBuffer();
    let res;
    try {
      res = await fetch(`${env.VDIG_URL}/api/v1/mailtest/inbound?id=${id}`, {
        method: "POST",
        headers: {
          "Content-Type": "message/rfc822",
          "X-Vdig-Secret": env.VDIG_SECRET,
          "X-Envelope-From": message.from,
        },
        body: raw,
      });
    } catch (err) {
      message.setReject("VdigDNS couldn't be reached. Please try again in a few minutes.");
      return;
    }
    if (res.status === 404) message.setReject("This test address has expired. Start a new test on VdigDNS.");
    else if (!res.ok) message.setReject(`VdigDNS couldn't store the test (HTTP ${res.status}). Please try again.`);
  },
};
