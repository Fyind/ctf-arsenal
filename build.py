import os
with open("modified_code.js","r") as f:
    text = f.read()

with open("node_modules/hexo-asset-image/index.js","w") as f:
    f.write(text)
with open("node_modules/hexo-theme-shokax/scripts/filters/post.js","w") as f:
    f.write(text)

os.system("hexo g")