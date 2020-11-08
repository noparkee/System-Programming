import re

time = []
fs_name = []
block_num = []

f = open("out2", "r")
g = open("time2", "w")
while True:
    line = f.readline()
    s = re.findall("\d+", line)
    if not line:
        break
    time.append(s[1])
    fs_name.append(s[2])
    block_num.append(s[3])
    g.write(s[1] +"\n")

f.close()
g.close()

print(time)

1603963944511920 -- 46

1603970767453550