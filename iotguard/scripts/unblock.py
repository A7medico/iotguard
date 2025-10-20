# scripts/unblock_all.py
import os, subprocess, shutil, json

def run(cmd): 
    return subprocess.run(cmd, capture_output=True, text=True)

if os.name == "nt":
    # Delete every rule that starts with IoTGuardBlock_
    show = run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]).stdout
    to_delete = []
    name = None
    for line in show.splitlines():
        if line.strip().startswith("Rule Name:"):
            name = line.split(":",1)[1].strip()
        if name and name.startswith("IoTGuardBlock_"):
            to_delete.append(name)
    for n in to_delete:
        run(["netsh","advfirewall","firewall","delete","rule",f"name={n}"])
    print(f"Removed {len(to_delete)} Windows rules.")
else:
    if shutil.which("nft"):
        run(["nft","delete","table","inet","iotguard"])
        print("Deleted nft table inet/iotguard.")
    elif shutil.which("iptables"):
        # naive flush: remove all INPUT rules containing DROP
        print("Please flush iptables rules manually or provide a saved chain name.")
    else:
        print("No firewall tool found.")
