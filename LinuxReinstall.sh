#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

function CopyRight() {
  clear
  echo "########################################################"
  echo "#                                                      #"
  echo "#  Linux Reinstall Script                              #"
  echo "#                                                      #"
  echo "#  Author: Skiyet                                      #"
  echo "#  Blog: www.skiyet.com                                #"
  echo "#  GIT: https://github.com/SKIYET/LinuxReinstall       #"
  echo "#  Version : 1.35                                      #"
  echo "#                                                      #"
  echo "#  Special Thanks to Vicer , hiCasper and Veip007      #"
  echo "#                                                      #"
  echo "########################################################"
  echo -e "\n"
}


function CheckDependency(){
        CopyRight
        echo -e "\nPlease note some dependencies are necessary.\n"
        source /etc/os-release
   if [[ "${ID}" == "debian" ]] || [[ "${ID}" == "ubuntu" ]]; then
        echo -e "For debian or ubuntu, the following dependencies will be installed.\n"
        echo -e "\nxz-utils openssl gawk file net-tools curl wget\n"
        echo -e "\n"
        read -s -n1 -p "Press any key to continue..."
        clear
        apt-get update
        apt-get install -y xz-utils openssl gawk file net-tools curl wget
    elif [[ "${ID}" == "centos" ]];then
        echo -e "For centos, the following dependencies will be installed.\n\ncoreutils openssl gawk file net-tools curl wget\n"
        echo -e "\ncoreutils openssl gawk file net-tools curl wget\n"
        echo -e "\n"
        read -s -n1 -p "Press any key to continue..."
        clear
        yum update
        yum install -y coreutils openssl gawk file net-tools curl wget
    else
        echo -e "Special OS, You should install the dependency mannually."
    fi
}

function isValidIp() {
  local ip=$1
  local ret=1
  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    ip=(${ip//\./ })
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    ret=$?
  fi
  return $ret
}

function ipCheck() {
  isLegal=0
  for add in $MAINIP $GATEWAYIP $NETMASK; do
    isValidIp $add
    if [ $? -eq 1 ]; then
      isLegal=1
    fi
  done
  return $isLegal
}

function GetIp() {
  MAINIP=$(ip route get 1 | awk -F 'src ' '{print $2}' | awk '{print $1}')
  GATEWAYIP=$(ip route | grep default | awk '{print $3}')
  SUBNET=$(ip -o -f inet addr show | awk '/scope global/{sub(/[^.]+\//,"0/",$4);print $4}' | head -1 | awk -F '/' '{print $2}')
  value=$(( 0xffffffff ^ ((1 << (32 - $SUBNET)) - 1) ))
  NETMASK="$(( (value >> 24) & 0xff )).$(( (value >> 16) & 0xff )).$(( (value >> 8) & 0xff )).$(( value & 0xff ))"
}

function UpdateIp() {
  read -r -p "Your IP: " MAINIP
  read -r -p "Your Gateway: " GATEWAYIP
  read -r -p "Your Netmask: " NETMASK
}

function SetNetwork() {
  isAuto='0'
  if [[ -f '/etc/network/interfaces' ]];then
    [[ ! -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && isAuto='1'
    [[ -d /etc/network/interfaces.d ]] && {
      cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
      [[ "$cfgNum" -ne '0' ]] && {
        for netConfig in `ls -1 /etc/network/interfaces.d/*.cfg`
        do
          [[ ! -z "$(cat $netConfig | sed -n '/iface.*inet static/p')" ]] && isAuto='1'
        done
      }
    }
  fi

  if [[ -d '/etc/sysconfig/network-scripts' ]];then
    cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
    [[ "$cfgNum" -ne '0' ]] && {
      for netConfig in `ls -1 /etc/sysconfig/network-scripts/ifcfg-* | grep -v 'lo$' | grep -v ':[0-9]\{1,\}'`
      do
        [[ ! -z "$(cat $netConfig | sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p')" ]] && isAuto='1'
      done
    }
  fi
}

function IPv4Mode() {
  CopyRight

  if [ "$isAuto" == '0' ]; then
    read -r -p "Using DHCP to configure network automatically? [y/n]:" input
    case $input in
      [yY][eE][sS]|[yY]) NETSTAT='' ;;
      [nN][oO]|[nN]) isAuto='1' ;;
      *) clear; echo "Canceled by user!"; exit 1;;
    esac
  fi

  if [ "$isAuto" == '1' ]; then
    GetIp
    ipCheck
    if [ $? -ne 0 ]; then
      echo -e "Error occurred when detecting ip. Please input manually.\n"
      UpdateIp
    else
      CopyRight
      echo "IP: $MAINIP"
      echo "Gateway: $GATEWAYIP"
      echo "Netmask: $NETMASK"
      echo -e "\n"
      read -r -p "Is IPv4 configuration correct ? [y/n]:" input
      case $input in
        [yY][eE][sS]|[yY]) ;;
        [nN][oO]|[nN])
          echo -e "\n"
          UpdateIp
          ipCheck
          [[ $? -ne 0 ]] && {
            clear
            echo -e "Input error!\n"
            exit 1
          }
        ;;
        *) clear; echo "Canceled by user!"; exit 1;;
      esac
    fi
    NETSTAT="--ip-addr ${MAINIP} --ip-gate ${GATEWAYIP} --ip-mask ${NETMASK} "
  fi
}

function IPv6Mode(){
  echo -e "\n"
  echo "IPv6 mode may be testing. Now we will list your network configurations"
  IPv6MASKUrl="https://raw.githubusercontent.com/SKIYET/LinuxReinstall/master/Tools/IPv6MASK.txt"
  if [ -f "./IPv6MASK.txt" ]; then
   rm -f ./IPv6MASK.txt
  fi
  wget --no-check-certificate -qO  IPv6MASK.txt ${IPv6MASKUrl}
  sed 's/ //g' IPv6MASK.txt >IPv6MASK2.txt && rm -rf IPv6MASK.txt
  IPV6ADDR=$(curl -s ipv6.ip.sb)
  IPV6GATE=$(route -6 -n | grep UG | awk '{print $2}'|sed '/^fe80:/d')
  IPV6SUBCOUNT=$(ip addr |grep ${IPV6ADDR}| awk -F '/' '{print $2}' | tr -d 'a-zA-Z' | sed 's/ //g')
  IPV6MASK=$(cat IPv6MASK2.txt|grep /$IPV6SUBCOUNT| awk -F '=' '{print $2}')
  CopyRight
  echo "IP: $IPV6ADDR/$IPV6SUBCOUNT"
  echo "Gateway : $IPV6GATE"
  echo "Netmask : $IPV6MASK"
  echo -e "\nPlease check each of them.\n"
  echo -e "\nATTENETION! \nIs the gateway in your subnet? \nIf not, selecting a smaller number can solve this issue. Because it means a more wide sunbet."
  read -r -p "Is IPv6 configuration correct ? [y/n]:" IPv6CORR
  IPv6CORR=$(echo ${IPv6CORR}|tr [A-Z] [a-z])
  if [[ "$IPv6CORR" == "y" ]] || [[ "$IPv6CORR" == "yes" ]]; then
          echo "The IPv6 configuration will be adopted in the installation."
  elif [[ "$IPv6CORR" == "n" ]] || [[ "$IPv6CORR" == "no" ]]; then
          echo -e "\nLet's check the configuration step by step. You may update the configure manually.\n"
          echo -e "\nIP: $IPV6ADDR\n"
          read -r -p "Is IPv6 address correct(except netmask) ? [y/n]: " IPv6ADDRCORR
          if [[ "$IPv6ADDRCORR" == "n" ]]; then
          echo -e "\nNow let's list IPv6 address configuration\n"
          ip -6 addr show
          echo -e "\n"
          read -r -p "Please input IPv6 address (Do NOT input any part of netmask) : " IPV6ADDR
          echo -e "New IPv6 Address : ${IPV6ADDR}\n"
          fi
          echo -e "\nGateway : $IPV6GATE\n"
          read -r -p "Is IPv6 gateway correct ? [y/n]: " IPv6GATECORR
          if [[ "$IPv6GATECORR" == "n" ]]; then
          echo -e "\nNow let's list IPv6 route configuration\n"
          #route -6 -n
          ip -6 route show
          echo -e "\n"
          read -r -p "Please input IPv6 Gateway : " IPV6GATE
          echo -e "New IPv6 Gateway : ${IPV6GATE}\n"
          fi
          echo -e "\nNetmask : $IPV6MASK\n"
      read -r -p "Is IPv6 subnet mask correct ? [y/n]: " IPv6MASKCORR
          if [[ "$IPv6MASKCORR" == "n" ]]; then
          read -r -p "Please input the IPv6 subnet mask, such as 48, 64 and 96. Proper format will be generated : " IPV6MASK
          IPV6SUBCOUNT=${IPV6MASK}
          IPV6MASK=$(cat IPv6MASK2.txt|grep /$IPV6SUBCOUNT| awk -F '=' '{print $2}')
          echo -e "New IPv6 netmask : ${IPV6MASK}\n"
          fi
          IPV6ADDR="${IPV6ADDR}/${IPV6SUBCOUNT}"
          echo "The IPv6 configuration you input will be adopted in the installation."
  else
      echo -e "Unknow operation. Program will exit now."
          exit 1
  fi
  rm -rf IPv6MASK2.txt
  NETSTAT="--ip-addr ${IPV6ADDR} --ip-gate ${IPV6GATE} --ip-mask ${IPV6MASK}"
  CopyRight
  echo "IP: $IPV6ADDR"
  echo "Gateway : $IPV6GATE"
  echo "Netmask : $IPV6MASK"
  echo -e "\n"
}


function Mirror(){
        echo "Geographical location detection will start"
        Country=$(wget --no-check-certificate -qO- https://api.ip.sb/geoip)
        Country=${Country##*"country_code"} && Country=${Country%"region_code"*}
        Country=${Country#*\:} && Country=${Country#*\"}
        Country=${Country%,*} && Country=${Country%\"*}
        echo "Location : ${Country}"
         Country=$(echo ${Country}|tr [A-Z] [a-z])
        if [[ "$Country" == "cn" ]];then
                echo "USTC mirror will be adopted in all of platforms."
                DebianMirror="--mirror http://mirrors.ustc.edu.cn/debian/"
                UbuntuMirror="--mirror http://mirrors.ustc.edu.cn/ubuntu/"
                CentosMirror="--mirror http://mirrors.ustc.edu.cn/centos/"
        elif [[ "$Country" != "cn" ]]; then
                echo "Specific country mirror will be adopted on debian/ubuntu platforms."
                echo "Domestic mode will be adopted on centos platform."
                DebianMirror="--mirror http://ftp.${Country}.debian.org/debian/"
                UbuntuMirror="--mirror http://${Country}.archive.ubuntu.com/ubuntu/"
                CentosMirror=""
        elif [[ "$Country" == "" ]]; then
            echo "Domestic mode will be adopted on all of platforms."
                DebianMirror=" "
                UbuntuMirror=" "
                CentosMirror=" "
        fi
}


function Preparation() {
  clear
  echo -e "\n"
  echo "Download core script now"

  if [ -f "./Core.sh" ]; then
   rm -f ./Core.sh
  fi

  CoreUrl="https://raw.githubusercontent.com/SKIYET/LinuxReinstall/master/Core/Core.sh"
  wget --no-check-certificate -qO ./Core.sh ${CoreUrl} && chmod a+x ./Core.sh
  #Remove some grub-installer configurations, or the grub installation will fail.
  sed -i '/force-efi-extra-removable/d' ./Core.sh
  CopyRight
  echo -e "\n"
  echo "Now you should input some parameters"
  echo -e "\n"
  echo "Please input a distribution. What you input is NOT case-sensitive."
  read -r -p "Input (the first letter of) the distribution you want , Press ENTER to skip (default : debian) : " ChosenDist
  ChosenDist=$(echo ${ChosenDist}|tr [A-Z] [a-z])
  if [[ "$ChosenDist" == '' ]] || [[ "$ChosenDist" == 'd' ]] || [[ "$ChosenDist" == 'debian' ]] ; then
     ChosenDist='-d'
         MirrorFinal="${DebianMirror}"
         #define the security updates mirror
         sed -i '/d\-i apt\-setup\/services-select multiselect/a\d\-i apt\-setup\/security\_host string security\.debian\.org' ./Core.sh
         #enable all offical sourcesÃ¯Â¼Å¡non-free contrib and backports
         #The backports on debian should be select in multiselect option
         sed -i '/d\-i apt\-setup\/services-select multiselect/i\d\-i apt\-setup\/contrib boolean true' ./Core.sh
         sed -i '/d\-i apt\-setup\/contrib boolean true/i\d\-i apt\-setup\/non-free boolean true' ./Core.sh
         sed -i 's/d\-i apt\-setup\/services-select multiselect/& security\, updates\, backports/' ./Core.sh
         echo -e "Selected distribution is debian."
  elif [[ "$ChosenDist" == 'u' ]] || [[ "$ChosenDist" == 'ubuntu' ]]; then
     ChosenDist='-u'
         MirrorFinal="${UbuntuMirror}"
         #define the security updates mirror
         sed -i '/d\-i apt\-setup\/services-select multiselect/a\d\-i apt-setup\/security\_host string security\.ubuntu\.com' ./Core.sh
         sed -i '/d\-i apt-setup\/security\_host string security\.ubuntu\.com/a\d\-i apt\-setup\/security\_path string \/ubuntu' ./Core.sh
         #enable all offical sources:universe restricted and backports
         #The backports on debian should be configured as universe
         sed -i '/d\-i apt\-setup\/services-select multiselect/i\d\-i apt\-setup\/universe boolean true' ./Core.sh
         sed -i '/d\-i apt\-setup\/universe boolean true/i\d\-i apt\-setup\/restricted boolean true' ./Core.sh
         sed -i '/d\-i apt\-setup\/universe boolean true/a\d\-i apt\-setup\/backports boolean true' ./Core.sh
         sed -i 's/d\-i apt\-setup\/services-select multiselect/& security\, updates/'  ./Core.sh
         echo -e "Selected distribution is ubuntu."
  elif [[ "$ChosenDist" == 'c' ]] || [[ "$ChosenDist" == 'centos' ]]; then
         ChosenDist='-c'
         MirrorFinal="${CentosMirror}"
         echo -e "Selected distribution is centos."
  else
         echo -e "Unrecognized parameter, this program will exit now"
         exit 1
  fi

  echo -e "\n"
  echo "Please input a version number for your distribution. Please note ONLY numbers are allowed here."
  read -r -p "Input version here ,Press ENTER to skip (default : 10/18.04/6.9 for debian/ubuntu/centos) : " ChosenVersion
  VerDefaultDeb='10 '
  VerDefaultUbu='18.04 '
  VerDefaultCen='6.9 '
  if [[ "$ChosenVersion" == '' ]] && [[ "$ChosenDist" == '-d' ]]; then
         ChosenVersion="${VerDefaultDeb} "
  elif [[ "$ChosenVersion" == '' ]] && [[ "$ChosenDist" == '-u' ]]; then
         ChosenVersion="${VerDefaultUbu} "
  elif [[ "$ChosenVersion" == '' ]] && [[ "$ChosenDist" == '-c' ]]; then
         ChosenVersion="${VerDefaultCen} "
  else
     ChosenVersion="${ChosenVersion}"
  fi
  echo -e "Selected version number is ${ChosenVersion}"

  echo -e "\n"
  echo "Please note your server will have only one patition with the entire disk if you select debian/ubuntu."
  echo "Please input a filesystem you want, such as ext4 and xfs. This option is valid only when you choose debian/ubuntu."
  read -r -p "Input file system you want here , Press ENTER to skip (default : ext4) : " ChosenFS
  ChosenFS=$(echo ${ChosenFS}|tr [A-Z] [a-z])
  FSDefault='ext4'
  if [[ "$ChosenFS" == '' ]] ; then
         ChosenFS=${FSDefault}
  fi
  sed -i "s@TargetFS@${ChosenFS}@" ./Core.sh
  echo -e "Selected file system is ${ChosenFS}"

  echo -e "\n"
  echo "Please select a login method. The valid options are public-private keys and password "
  echo "Please confirm whether the public-private keys is adopted. If you input n(o), a passward will be asked."
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : y) : " ChosenSSHPUB
  ChosenSSHPUB=$(echo ${ChosenSSHPUB}|tr [A-Z] [a-z])
  if [[ "$ChosenSSHPUB" == '' ]] || [[ "$ChosenSSHPUB" == 'y' ]] || [[ "$ChosenSSHPUB" == 'yes' ]]; then
                echo -e "\n"
                read -r -p "Please input your public key. What you input is case-sensitive : " ChosenPUBKEY
                if [[ "$ChosenPUBKEY" == '' ]] ; then
                    echo -e "Empty input, this program will exit now"
                    exit 1
                fi
                echo -e "\nPublic key you input is as follow.\n"
                echo -e "${ChosenPUBKEY}"
                ChosenPasswd=""
                sed -i '/PasswordAuthentication yes/d' ./Core.sh
                sed -i "s@TargetPUBKEY@${ChosenPUBKEY}@" ./Core.sh
  elif [[ "$ChosenSSHPUB" == 'n' ]] || [[ "$ChosenSSHPUB" == 'no' ]] ; then
                echo -e "\n"
                echo -e "Please input a custom password for your server. What you input is case-sensitive "
                read -r -p "Please input ssh password you want , Press ENTER to skip (default : ILoveChina!) : " ChosenPasswd
                PasswdDefault='ILoveChina!'
                if [[ "$ChosenPasswd" == '' ]] ; then
                ChosenPasswd=${PasswdDefault}
                fi
                echo -e "\nPasswd you want is ${ChosenPasswd}.\n"
                ChosenPasswd="-p ${ChosenPasswd}"
                sed -i '/PasswordAuthentication no/d' ./Core.sh
                sed -i '/PubkeyAuthentication yes/d' ./Core.sh
                sed -i '/AuthorizedKeysFile/d' ./Core.sh
                sed -i '/AuthorizedKeysFile/d' ./Core.sh
                sed -i '/\/root\/\.ssh\//d' ./Core.sh
                sed -i '/TargetPUBKEY/d' ./Core.sh
  fi
  echo -e "\n"
  read -r -p "Please input ssh port you want , Press ENTER to skip (default : 22) : " ChosenSSH
  SSHDefault='22'
  if [[ "$ChosenSSH" == '' ]] ; then
         ChosenSSH=${SSHDefault}
  fi
  sed -i "s@TargetSSH@${ChosenSSH}@" ./Core.sh
  echo -e "Selected ssh port is ${ChosenSSH}"

  echo -e "\n"
  echo -e "Does your server work with a IPv6-Only internet?"
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : n) : " ChosenIPV6
  ChosenIPV6=$(echo ${ChosenIPV6}|tr [A-Z] [a-z])
  if [[ "$ChosenIPV6" == '' ]] || [[ "$ChosenIPV6" == 'n' ]] || [[ "$ChosenIPV6" == 'no' ]] ; then
         ChosenIPV6='n'
         ChosenNS="8.8.8.8"
         echo "We will work in ipv4 mode"
         sed -i "s@TargetNS@${ChosenNS}@" ./Core.sh
  elif [[ "$ChosenIPV6" == 'y' ]] || [[ "$ChosenIPV6" == 'yes' ]]; then
         ChosenIPV6='y'
         ChosenNS="2001:4860:4860::8888"
         echo "We will work in ipv6 mode (testing)"
         sed -i "s@TargetNS@${ChosenNS}@" ./Core.sh
  fi

  echo -e "\n"
  echo -e "Do you want a 64bit system?"
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : y) : " ChosenX64
  ChosenX64=$(echo ${ChosenX64}|tr [A-Z] [a-z])
  if [[ "$ChosenX64" == '' ]] || [[ "$ChosenX64" == 'y' ]] || [[ "$ChosenX64" == 'yes' ]] ; then
         ChosenX64='-v 64'
         echo "You select a 64bit linux."
  elif [[ "$ChosenX64" == 'n' ]] || [[ "$ChosenX64" == 'no' ]]; then
         ChosenX64='-v 32'
         echo "You select a 32bit linux."
  fi

  echo -e "\n"
  echo -e "Do you want to install the extra firmware?"
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : n) : " ChosenFirmware
  ChosenFirmware=$(echo ${ChosenFirmware}|tr [A-Z] [a-z])
  if [[ "$ChosenFirmware" == '' ]] || [[ "$ChosenFirmware" == 'n' ]] || [[ "$ChosenFirmware" == 'no' ]] ; then
         ChosenFirmware=''
         echo "Extra firmware is not selected."
  elif [[ "$ChosenFirmware" == 'y' ]] || [[ "$ChosenFirmware" == 'yes' ]]; then
           ChosenFirmware='-firmware'
           echo "Extra firmware will be installed."
  fi

  echo -e "\n"
  echo -e "Do you want install the linux automatically?"
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : y) : " ChosenAutoInstall
  ChosenAutoInstall=$(echo ${ChosenAutoInstall}|tr [A-Z] [a-z])
  if [[ "$ChosenAutoInstall" == '' ]] || [[ "$ChosenAutoInstall" == 'y' ]] || [[ "$ChosenAutoInstall" == 'yes' ]] ; then
         ChosenAutoInstall='-a'
         echo "The installation will work in auto mode"
  elif [[ "$ChosenAutoInstall" == 'n' ]] || [[ "$ChosenAutoInstall" == 'no' ]]; then
         ChosenAutoInstall='-m'
         echo "You should complete the installation with vnc"
  fi

  echo -e "\n"
  echo -e "If your memory is 512M or lower, The low memory mode should be enabled."
  echo -e "This option is valid only when you choose debian or ubuntu."
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : n) : " ChosenLowMemMode
  ChosenLowMemMode=$(echo ${ChosenLowMemMode}|tr [A-Z] [a-z])
  if [[ "$ChosenLowMemMode" == '' ]] || [[ "$ChosenLowMemMode" == 'n' ]] || [[ "$ChosenLowMemMode" == 'no' ]] ; then
         ChosenLowMemMode='n'
  elif [[ "$ChosenLowMemMode" == 'y' ]] || [[ "$ChosenLowMemMode" == 'yes' ]]; then
         ChosenLowMemMode='y'
         echo "The installation will work in low memory mode"
         #low memory mode
         sed -i '/d\-i debian\-installer\/locale string en_US/i\d\-i lowmem\/low note' ./Core.sh
         sed -i '/d\-i lowmem\/low note/i\d\-i lowmem\/insufficient error' ./Core.sh
         sed -i '/d\-i lowmem\/low note/a\d\-i anna\/choose\_modules\_lowmem multiselect' ./Core.sh
         #Some configurations must be reconfigured respectively.
         sed -i '/d\-i debian\-installer\/locale string en_US/a\d\-i debian\-installer\/country string US' ./Core.sh
         sed -i '/d\-i debian\-installer\/country string US/a\d\-i debian-installer\/language string en' ./Core.sh
         sed -i '/d\-i debian-installer\/language string en/a\d\-i debian-installer\/locale string en\_GB\.UTF\-8' ./Core.sh
    fi

  echo -e "\n"
  echo -e "Do you want to use google IPv4/6 dns nameserver?"
  read -r -p "Please input y(es) or n(o) , Press ENTER to skip (default : y) : " ChosenGoogleNS
  ChosenGoogleNS=$(echo ${ChosenGoogleNS}|tr [A-Z] [a-z])
  if [[ "$ChosenGoogleNS" == '' ]] || [[ "$ChosenGoogleNS" == 'y' ]] || [[ "$ChosenGoogleNS" == 'yes' ]] ; then
rm -rf /etc/resolv.conf
cat <<EOF>/etc/resolv.conf
#IPv4 DNS-NameServer
nameserver 8.8.8.8
nameserver 8.8.4.4
#IPv6 DNS-NameServer
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844
EOF
  fi

  UserParameter="${ChosenFirmware} ${ChosenDist} ${ChosenVersion} ${ChosenX64} ${ChosenAutoInstall} ${ChosenPasswd} ${MirrorFinal}"

}
function Reinstall() {
  CopyRight
  if [[ "$ChosenIPV6" == 'n' ]] && [[ "$isAuto" == '0' ]] ; then
     echo "Using DHCP mode."
  elif [[ "$ChosenIPV6" == 'n' ]] || [[ "$isAuto" == '1' ]]; then
      echo "IP: $MAINIP"
      echo "Gateway: $GATEWAYIP"
      echo "Netmask: $NETMASK"
  elif [[ "$ChosenIPV6" == 'y' ]] ; then
      echo "IPv6 Address: $IPV6ADDR"
      echo "IPv6 Gateway: $IPV6GATE"
      echo "IPv6 Netmask: $IPV6MASK"
  fi

      echo -e "\n"
      read -s -n1 -p "Press any key to continue..."
      bash ./Core.sh $UserParameter $NETSTAT
}
CheckDependency
Mirror
Preparation
if [[ "$ChosenIPV6" == 'n' ]];then
      SetNetwork
      IPv4Mode
elif [[ "$ChosenIPV6" == 'y' ]];then
      IPv6Mode
else
      echo -e "\n"
      echo -e "No IPv4 or IPv6. Program will exit now "
fi
Reinstall
