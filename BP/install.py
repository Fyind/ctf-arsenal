import site
import os
site_path = [x for x in site.getsitepackages() if "site-packages" in x][0]

p = os.path.join(site_path,'tkinterdnd2')

cmd = "pyinstaller --noconfirm --onefile --icon=icon.ico --windowed --add-data " + p + ":tkinterdnd2 bp.py"
os.system(cmd)