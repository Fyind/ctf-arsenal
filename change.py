filename = "RISC-V-汇编语言入门.md"

s = open(filename, "r",encoding="utf-8").read()

if s.find("{%") == -1:
    exit()

while s.find("{% kbd") != -1:
    l = s.find("{% kbd")
    r = s.find("%}")
    s = s[:l] + "`"+ s[l+7:r].strip() +"`" + s[r+3:]
    
open(filename,"w",encoding='utf-8').write(s)
