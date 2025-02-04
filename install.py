import os
import subprocess

a = subprocess.check_output("node -v").decode()
if a[0] != 'v':
    print("Node JS not installed. Go to: https://nodejs.org/en/")
    exit()
a = subprocess.check_output("git -v").decode()
if a[:11] != 'git version':
    print("Git not installed. Go to: https://git-scm.com/downloads")
    exit()

os.system("npm install -g hexo-cli")
os.system("npm install shokax-cli --location=global")
os.system("SXC install shokaX")
os.system("npm install hexo-asset-image --save")

with open("modified_code.js","r") as f:
    text = f.read()
with open("node_modules/hexo-asset-image/index.js","w") as f:
    f.write(text)
with open("node_modules/hexo-theme-shokax/scripts/filters/post.js","w") as f:
    f.write(text)
    
os.system("hexo g")
print("Successfuly installed")