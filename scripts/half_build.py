import sys
n = int(sys.argv[1])
lines = open('src/index.js').read().split('\n')
body = '\n'.join(lines[:n])
idx = body.find('export default {')
if idx >= 0:
    body = body[:idx]
out = body + '\nexport default {\n  async fetch(request, env, ctx) {\n    return new Response("ok ' + str(n) + '");\n  }\n};\n'
open('/tmp/halfmain.js', 'w').write(out)
toml = open('wrangler.toml').read().replace('name = "v2ray"', 'name = "half-gw"').replace('main = "src/index.js"', 'main = "/tmp/halfmain.js"')
open('/tmp/half.toml', 'w').write(toml)
print("built", n)
