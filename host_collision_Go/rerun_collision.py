import subprocess
import time

# Read SLD list
slds = [
        "qlogo.cn",
        "daxuepc.com",
        "qcloud.com",
        "weiyun.com",
        "cnzz.com",
        "cnzz.net",
        "vip.com",
        "bilibili.com"
    ]

for sld in slds:
    log_file = f"recheck-{sld}.log"
    cmd = f"nohup go run hostCollision.go -sld {sld} -t 40 -RecheckInetdm true > {log_file} 2>&1 &"
    
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"Started: {sld}")
    except subprocess.CalledProcessError as e:
        print(f"Error starting {sld}: {e}")
    
    time.sleep(0.5)  # Slight delay to avoid starting too many at once

print("All tasks started.")
