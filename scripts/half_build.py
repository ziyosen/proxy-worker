import sys
mode = sys.argv[1]
lines = open('src/index.js').read().split('\n')
body = '\n'.join(lines[:555])  # everything before 'export default {'
if mode == "full-stubfetch":
    # keep ALL code incl default export, but override fetch via module wrap: import original? can't.
    # Instead: replace body of fetch to stub via regex on FULL file
    src = open('src/index.js').read()
    idx = src.find('export default {')
    head = src[:idx]
    out = head + 'export default {\n  async fetch(request, env, ctx) {\n    return new Response("stub-fetch-ok");\n  }\n};\n'
    open('/tmp/halfmain.js','w').write(out)
    name = "half-gw"
elif mode == "full-real":
    out = open('src/index.js').read()
    open('/tmp/halfmain.js','w').write(out)
    name = "half-gw"
toml = open('wrangler.toml').read().replace('name = "v2ray"', 'name = "%s"' % name).replace('main = "src/index.js"', 'main = "/tmp/halfmain.js"')
open('/tmp/half.toml','w').write(toml)
print("built", mode)
