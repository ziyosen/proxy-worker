import sys
mode = sys.argv[1]
src = open('src/index.js').read()
idx = src.find('export default {')
head = src[:idx]
bodies = {
 "url-only": '''export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    return new Response("url ok " + url.pathname);
  }
};
''',
 "parse-only": '''export default {
  async fetch(request, env, ctx) {
    const a = parseUUIDList(env);
    return new Response("parse ok " + a.length);
  }
};
''',
 "full-real": src,
}
open('/tmp/halfmain.js','w').write(head + bodies[mode])
toml = open('wrangler.toml').read().replace('name = "v2ray"', 'name = "half-gw"').replace('main = "src/index.js"', 'main = "/tmp/halfmain.js"')
open('/tmp/half.toml','w').write(toml)
print("built", mode)
