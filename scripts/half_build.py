import sys
mode = sys.argv[1]
src = open('src/index.js').read()
if mode == "fetch1":
    idx = src.find('export default {')
    head = src[:idx]
    out = head + '''export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const allowedUUIDs = parseUUIDList(env);
    return new Response("fetch1 ok uuids=" + allowedUUIDs.length);
  }
};
'''
elif mode == "full-real":
    out = src
open('/tmp/halfmain.js','w').write(out)
toml = open('wrangler.toml').read().replace('name = "v2ray"', 'name = "half-gw"').replace('main = "src/index.js"', 'main = "/tmp/halfmain.js"')
open('/tmp/half.toml','w').write(toml)
print("built", mode)
