export default {
  async fetch(request, env, ctx) {
    return new Response("Halo, worker jalan!", { status: 200 });
  },
};
