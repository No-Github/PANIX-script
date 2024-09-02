#!/usr/bin/env bash
#set -x

# 定义日志文件夹路径
Log_dir="/tmp/linux_forensics_log/"
script_version="v0.0.2(2024/08/30)"

# ===================== Abbreviations =====================
Echo_INFOR(){

    echo -e "\033[1;36m$(date +"%H:%M:%S")\033[0m \033[1;32m[INFOR]\033[0m - \033[1;32m$1\033[0m"

}

Echo_ALERT(){

    echo -e "\033[1;36m$(date +"%H:%M:%S")\033[0m \033[1;33m[ALERT]\033[0m - \033[1;33m$1\033[0m"

}

Echo_ERROR(){

    echo -e "\033[1;36m$(date +"%H:%M:%S")\033[0m \033[1;31m[ERROR]\033[0m - \033[1;31m$1\n\033[0m"

}

# ===================== Default =====================
Sys_Version(){

    case "$(uname -m)" in
        *"arm64"*|*"aarch64"*)
            Linux_architecture_Name="linux-arm64"
            ;;
        *"x86_64"*)
            Linux_architecture_Name="linux-x86_64"
            ;;
        *)
            echo "Not supported on current architecture"
            exit 1
            ;;
    esac

    case $(cat /etc/*-release | head -n 3) in
        *"Kali"*|*"kali"*)
            Linux_Version="Kali"
            case $(cat /etc/*-release | head -n 4) in
                *"2022"*)
                    Linux_Version_Num="kali-rolling"
                    Linux_Version_Name="buster"
                    ;;
                *"2021"*)
                    Linux_Version_Num="kali-rolling"
                    Linux_Version_Name="buster"
                    ;;
                *"2020"*)
                    Linux_Version_Num="kali-rolling"
                    Linux_Version_Name="buster"
                    ;;
                *)
                    Linux_Version_Num="kali-rolling"
                    Linux_Version_Name="stretch"
                    ;;
            esac
            ;;
        *"Ubuntu"*|*"ubuntu"*)
            Linux_Version="Ubuntu"
            case $(cat /etc/*-release | head -n 4) in
                *"noble"*)
                    Linux_Version_Num="24.04"
                    Linux_Version_Name="noble"
                    ;;
                *"mantic"*)
                    Linux_Version_Num="23.10"
                    Linux_Version_Name="mantic"
                    ;;
                *"lunar"*)
                    Linux_Version_Num="23.04"
                    Linux_Version_Name="lunar"
                    ;;
                *"kinetic"*)
                    Linux_Version_Num="22.10"
                    Linux_Version_Name="kinetic"
                    ;;
                *"jammy"*)
                    Linux_Version_Num="22.04"
                    Linux_Version_Name="jammy"
                    ;;
                *"impish"*)
                    Linux_Version_Num="21.10"
                    Linux_Version_Name="impish"
                    ;;
                *"hirsute"*)
                    Linux_Version_Num="21.04"
                    Linux_Version_Name="hirsute"
                    ;;
                *"groovy"*)
                    Linux_Version_Num="20.10"
                    Linux_Version_Name="groovy"
                    ;;
                *"focal"*)
                    Linux_Version_Num="20.04"
                    Linux_Version_Name="focal"
                    ;;
                *"eoan"*)
                    Linux_Version_Num="19.10"
                    Linux_Version_Name="eoan"
                    ;;
                *"disco"*)
                    Linux_Version_Num="19.04"
                    Linux_Version_Name="disco"
                    ;;
                *"cosmic"*)
                    Linux_Version_Num="18.10"
                    Linux_Version_Name="cosmic"
                    ;;
                *"bionic"*)
                    Linux_Version_Num="18.04"
                    Linux_Version_Name="bionic"
                    ;;
                *"xenial"*)
                    Linux_Version_Num="16.04"
                    Linux_Version_Name="xenial"
                    ;;
                *"vivid"*)
                    Linux_Version_Num="15.04"
                    Linux_Version_Name="vivid"
                    ;;
                *"trusty"*)
                    Linux_Version_Num="14.04"
                    Linux_Version_Name="trusty"
                    ;;
                *"precise"*)
                    Linux_Version_Num="12.04"
                    Linux_Version_Name="precise"
                    ;;
                *)
                    Echo_ALERT "Unknown Ubuntu Codename, attempting automatic adaptation."
                    Linux_Version_Num=$(cat /etc/*-release | awk -F "=" '/DISTRIB_RELEASE/ {print $2}')
                    Linux_Version_Name=$(cat /etc/*-release | awk -F "=" '/DISTRIB_CODENAME/ {print $2}')
                    ;;
            esac
            ;;
        *"Debian"*|*"debian"*)
            Linux_Version="Debian"
            case $(cat /etc/*-release | head -n 4) in
                *"bookworm"*)
                    Linux_Version_Num="12"
                    Linux_Version_Name="bookworm"
                    ;;
                *"bullseye"*)
                    Linux_Version_Num="11"
                    Linux_Version_Name="bullseye"
                    ;;
                *"buster"*)
                    Linux_Version_Num="10"
                    Linux_Version_Name="buster"
                    ;;
                *"stretch"*)
                    Linux_Version_Num="9"
                    Linux_Version_Name="stretch"
                    ;;
                *"jessie"*)
                    Linux_Version_Num="8"
                    Linux_Version_Name="jessie"
                    ;;
                *"wheezy"*)
                    Linux_Version_Num="7"
                    Linux_Version_Name="wheezy"
                    ;;
                *)
                    Echo_ALERT "Unknown Debian Codename, attempting automatic adaptation."
                    Linux_Version_Num=$(grep -Po '(?<=VERSION_ID=")\d+' /etc/*-release)
                    Linux_Version_Name=$(cat /etc/*-release | awk -F "=" '/VERSION_CODENAME/ {print $2}')
                    ;;
            esac
            ;;
        *"CentOS"*|*"centos"*)
            wget_option=""
            echo -e "\033[1;31mPlease replace your Centos, as Centos will not be maintained.\033[0m"
            Linux_Version="CentOS"
            case $(cat /etc/*-release | head -n 1) in
                *"Stream release 9"*)
                    Linux_Version_Num="9 Stream"
                    Linux_Version_Name=""
                    ;;
                *"Stream release 8"*)
                    Linux_Version_Num="8 Stream"
                    Linux_Version_Name=""
                    ;;
                *"release 8"*)
                    Linux_Version_Num="8"
                    Linux_Version_Name=""
                    ;;
                *"release 7"*)
                    Linux_Version_Num="7"
                    Linux_Version_Name=""
                    ;;
                *"release 6"*)
                    Linux_Version_Num="6"
                    Linux_Version_Name=""
                    ;;
                *)
                    Echo_ERROR "Unknown CentOS Codename"
                    exit 1
                    ;;
            esac
            ;;
        *"RedHat"*|*"redhat"*)
            Linux_Version="RedHat"
            ;;
        *"Fedora"*|*"fedora"*)
            Linux_Version="Fedora"
            case $(cat /etc/*-release | head -n 1) in
                *"release 40"*)
                    Linux_Version_Num="40"
                    Linux_Version_Name=""
                    ;;
                *"release 39"*)
                    Linux_Version_Num="39"
                    Linux_Version_Name=""
                    ;;
                *"release 38"*)
                    Linux_Version_Num="38"
                    Linux_Version_Name=""
                    ;;
                *"release 37"*)
                    Linux_Version_Num="37"
                    Linux_Version_Name=""
                    ;;
                *"release 36"*)
                    Linux_Version_Num="36"
                    Linux_Version_Name=""
                    ;;
                *"release 35"*)
                    Linux_Version_Num="35"
                    Linux_Version_Name=""
                    ;;
                *"release 34"*)
                    Linux_Version_Num="34"
                    Linux_Version_Name=""
                    ;;
                *"release 33"*)
                    Linux_Version_Num="33"
                    Linux_Version_Name=""
                    ;;
                *"release 32"*)
                    Linux_Version_Num="32"
                    Linux_Version_Name=""
                    ;;
                *)
                    Echo_ALERT "Unknown Fedora Codename, attempting automatic adaptation."
                    Linux_Version_Num=$(cat /etc/*-release | awk -F "=" '/VERSION_ID/ {print $2}')
                    Linux_Version_Name=""
                    ;;
            esac
            ;;
        *"AlmaLinux"*)
            Linux_Version="AlmaLinux"
            ;;
        *"Virtuozzo"*)
            Linux_Version="VzLinux"
            ;;
        *"Rocky"*)
            Linux_Version="Rocky"
            ;;
        *)
            Echo_ERROR "Unknown version"
            echo -e "\033[1;33m\nPlease enter distribution Kali[k] Ubuntu[u] Debian[d] Centos[c] RedHat[r] Fedora[f] AlmaLinux[a] VzLinux[v] Rocky[r]\033[0m" && read -r input
            case $input in
                [kK])
                    Linux_Version="Kali"
                    ;;
                [uU])
                    Linux_Version="Ubuntu"
                    echo -e "\033[1;33m\nPlease enter the system version number [22.04] [21.10] [21.04] [20.10] [20.04] [19.10] [19.04] [18.10] [18.04] [16.04] [15.04] [14.04] [12.04]\033[0m" && read -r input
                    Linux_Version_Name=$input
                    ;;
                [dD])
                    Linux_Version="Debian"
                    echo -e "\033[1;33m\nPlease enter the system version number [11] [10] [9] [8] [7]\033[0m" && read -r input
                    Linux_Version_Name=$input
                    ;;
                [cC])
                    Linux_Version="CentOS"
                    echo -e "\033[1;33m\nPlease enter the system version number [9 Stream] [8 Stream] [8] [7] [6]\033[0m" && read -r input
                    Linux_Version_Name=$input
                    ;;
                [rR])
                    Linux_Version="RedHat"
                    ;;
                [aA])
                    Linux_Version="AlmaLinux"
                    ;;
                [fF])
                    Linux_Version="Fedora"
                    echo -e "\033[1;33m\nPlease enter the system version number [36] [35] [34] [33] [32]\033[0m" && read -r input
                    Linux_Version_Name=$input
                    ;;
                [vV])
                    Linux_Version="VzLinux"
                    ;;
                [rR])
                    Linux_Version="Rocky"
                    ;;
                *)
                    Echo_ERROR "Unknown version"
                    exit 1
                    ;;
            esac
            ;;
    esac

}

Sys_Version_Mac(){

    Linux_Version="$(sw_vers -ProductName)"

    case "$(uname -m)" in
        *"arm64"*)
            Linux_architecture_Name="mac-arm64"
            Linux_Version_Num="$(sw_vers -productVersion)"
            Linux_Version_Name="$(sw_vers -BuildVersion)"
            ;;
        *)
            echo "Not supported on current architecture"
            exit 1
            ;;
    esac

}

Sys_Info(){


    echo -e "\033[1;32mUID           :\033[0m \033[1;35mVersion $script_version \033[0m"
    echo -e "\033[1;32mUID           :\033[0m \033[1;35m$UID \033[0m"
    echo -e "\033[1;32mDate          :\033[0m \033[1;35m$(date +"%Y-%m-%d") \033[0m"
    echo -e "\033[1;32mTime          :\033[0m \033[1;35m$(date +"%H:%M:%S") \033[0m"
    echo -e "\033[1;32mRuntime       :\033[0m \033[1;35m$(uptime 2>/dev/null | awk '{print $3 $4}' | sed 's/\,.*$//g') \033[0m"
    echo -e "\033[1;32mHostname      :\033[0m \033[1;35m$(hostname) \033[0m"
    echo -e "\033[1;32mDistribution  :\033[0m \033[1;35m$Linux_Version $Linux_Version_Num $Linux_Version_Name $Linux_architecture_Name\033[0m"

    case $Linux_Version in
        *"CentOS"*|*"RedHat"*|*"Fedora"*|*"AlmaLinux"*|*"VzLinux"*|*"Rocky"*)
            if test -e /var/log/secure
            then
                echo -e "\033[1;32mLast login IP :\033[0m"
                echo -e "\033[1;35m$(grep 'Accepted' /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -nr) \033[0m"
            fi
            ;;
        *"Kali"*)
                echo "" > /dev/null
            ;;
        *)
            if test -e /var/log/auth.log
            then
                echo -e "\033[1;32mLast login IP :\033[0m"
                echo -e "\033[1;35m$(grep --text "Accepted " /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr) \033[0m"
            fi
            ;;

    esac

}

# Main
Main(){

    case "$(uname)" in
        *"Darwin"*)
            Running_Mode="Darwin"
            ;;
        *"MINGW64_NT"*)
            echo "Not supported on windows platform"
            exit 1
            ;;
        *)
            Running_Mode="Linux"
            setenforce 0 > /dev/null 2>&1
            ;;
    esac

    if [[ $UID != 0 ]]; then
        Echo_ERROR "Please run with sudo or root privileged account!"
        exit 1
    fi

    printf "\033c"

    case $Running_Mode in
    *"Darwin"*)
        Sys_Version_Mac
        ;;
    *"Linux"*)
        Sys_Version
        ;;
    *)
        exit 1
        ;;
    esac

}

Init_Dir(){

    if test -d $Log_dir
    then
        Echo_ALERT "$Log_dir folder already exists"
    else
        mkdir -p $Log_dir && Echo_INFOR "$Log_dir folder created"
    fi

}

part(){

    echo -e "\n" >> $Log_dir/log.md
    echo "$1" >> $Log_dir/log.md

}

part2(){

    echo "$1" >> $Log_dir/log.md

}

run_command() {

    part "## $*"

    echo -e "\`\`\`" >> $Log_dir/log.md

    eval "$*" 1>> $Log_dir/log.md 2>> $Log_dir/errlog.md
    if [ $? -ne 0 ]; then
        echo -e "Command failed: $*" >> $Log_dir/err.log
    fi

    echo -e "\`\`\`" >> $Log_dir/log.md
}

System_info(){

    rm -f $Log_dir/log.md > /dev/null 2>&1
    rm -f $Log_dir/errlog.md > /dev/null 2>&1
    date +"%Y-%m-%d" > $Log_dir/log.md

    # 查看过去5天内创建的文件
    part "# 查看过去5天内创建的文件"
    run_command "find / -xdev -type f -ctime -5 -exec ls -l {} \;"

    # 查看过去5天内修改过的文件
    part "# 查看过去5天内修改过的文件"
    run_command "find / -xdev -type f -mtime -5 -exec ls -l {} \;"

    # SUID backdoor persistence
    part "SUID 后门 (7天内新增)"
    run_command "find / -perm -u=s -type f -ctime -7 -exec ls -l {} \; 2>/dev/null"
    run_command "find / -perm -u=s -type f -mtime -7 -exec ls -l {} \; 2>/dev/null"

    # Package manager persistence
    part "包管理器 后门 (7天内新增)"
    run_command "find /etc/apt/apt.conf.d/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/yum/pluginconf.d/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/*/site-packages/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/apt/apt.conf.d/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /etc/yum/pluginconf.d/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/*/site-packages/ -type f -mtime -5 -exec ls -l {} \;"

    # Malicious package persistence
    run_command "find /var/lib/dpkg/info/ -xdev -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /var/lib/dpkg/info/ -xdev -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /var/lib/rpm/ -xdev -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /var/lib/rpm/ -xdev -type f -mtime -5 -exec ls -l {} \;"

    # Capabilities backdoor persistence
    part "Capabilities 后门"
    run_command "getcap -r / 2>/dev/null"

    # secure 内容
    case $Linux_Version in
        *"CentOS"*|*"RedHat"*|*"Fedora"*|*"AlmaLinux"*|*"VzLinux"*|*"Rocky"*)
            part "# 复制 /var/log/secure"
            run_command "stat /var/log/secure"
            run_command "cp /var/log/secure $Log_dir"

            # 查看尝试暴力破解机器密码的ip
            run_command "grep \"Failed password for root\" /var/log/secure"
            run_command "grep \"Failed password for invalid user\" /var/log/secure"
            ;;
        *"Kali"*|*"Ubuntu"*|*"Debian"*)
            part "# 复制 /var/log/auth.log"
            run_command "stat /var/log/auth.log"
            run_command "cp /var/log/auth.log $Log_dir"

            # 查看尝试暴力破解机器密码的ip
            run_command "grep \"Failed password for root\" /var/log/auth.log"
            run_command "grep \"Failed password for invalid user\" /var/log/auth.log"
            ;;
        *) ;;
    esac

    # MOTD backdoor persistence
    part "# MOTD 配置"
    run_command "cat /etc/update-motd.d/*"

    # 文件完整性
    part "# 文件完整性"
    run_command "rpm -Va"

    # Udev persistence
    part "# Udev 后门"
    run_command "find /etc/udev/rules.d/ -xdev -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/udev/rules.d/ -xdev -type f -mtime -5 -exec ls -l {} \;"

    # journalctl 内容
    journalctl --since "30 days ago" 1>> $Log_dir/journalctl.log 2>> $Log_dir/errlog.md

    # 查看历史记录文件
    part "# 查看历史记录文件"
    run_command "cp /root/.bash_history $Log_dir"
    run_command "ls -la /home/*/.bash_history"
    run_command "cat /home/*/.bash_history"

    # 查看近期登录的用户
    part "# 查看近期登录的用户 last"
    run_command "last"

    # 查看目前在登录的用户
    part "# 查看目前在登录的用户 w"
    run_command "w"

    # 启动项
    part "# 启动项"
    run_command "cat /etc/rc.local"
    run_command "cat /etc/rc.d/rc.local"

    # init.d backdoor
    part "# init.d 后门 (以下部分内容应该为空)"
    run_command "find /etc/init.d/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/init.d/ -type f -mtime -5 -exec ls -l {} \;"

    # 服务项
    part "# 服务项 (以下部分内容应该为空)"
    run_command "systemctl list-unit-files --type service |grep enabled"
    run_command "find /etc/systemd/system/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/systemd/system/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/system/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/system/ -type f -mtime -5 -exec ls -l {} \;"

    # Systemd Generator persistence
    part "# Systemd Generator (以下部分内容应该为空)"
    run_command "find /etc/systemd/system-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/local/lib/systemd/system-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /lib/systemd/system-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/system-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/systemd/user-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/local/lib/systemd/user-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/user-generators/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /run/systemd/generator.early/ -type f -ctime -5 -exec ls -l {} \;"

    run_command "find /etc/systemd/system-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/local/lib/systemd/system-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /lib/systemd/system-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/system-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /etc/systemd/user-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/local/lib/systemd/user-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /usr/lib/systemd/user-generators/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /run/systemd/generator.early/ -type f -mtime -5 -exec ls -l {} \;"

    # 查看计划任务
    part "# 查看计划任务"
    run_command "crontab -l"

    run_command "ls -la /etc/cron.d/"
    run_command "cat /etc/cron.d/*"

    run_command "ls -la /etc/cron.daily/"
    run_command "cat /etc/cron.daily/*"

    run_command "ls -la /etc/cron.hourly/"
    run_command "cat /etc/cron.hourly/*"

    run_command "ls -la /etc/cron.monthly/"
    run_command "cat /etc/cron.monthly/*"

    run_command "ls -la /etc/cron.weekly/"
    run_command "cat /etc/cron.weekly/*"

    run_command "less /etc/crontab"

    run_command "ls -la /var/spool/cron/"
    run_command "cat /var/spool/cron/*"

    run_command "less /var/log/cron"
    run_command "grep CRON /var/log/messages"
    run_command "cat /var/log/syslog | grep -w 'cron'"

    # at
    part "# at 定时任务"
    run_command "atq"
    run_command "journalctl | grep \"atd.service\""
    run_command "/etc/init.d/atd status"

    # 监听端口
    part "# 监听端口"
    run_command "netstat -an"
    run_command "netstat -utnpl"

    # 对外连接
    part "# 对外连接"
    run_command "netstat -anop"
    run_command "netstat -alpw4"

    # 进程
    part "# 进程"
    run_command "ps aux"
    run_command "pstree"

    # nopid 后门
    part "# 查询nopid 类型的后门 (注意是否有 /proc 等关键字)"
    run_command "cat /proc/mounts"

    # ssh 密钥
    part "# 查询 ssh 密钥"
    run_command "ls -la /etc/ssh/"
    run_command "ls -la /root/.ssh/"
    run_command "cat /root/.ssh/known_hosts"
    run_command "find /root/.ssh/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /root/.ssh/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /home/*/.ssh/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /home/*/.ssh/ -type f -mtime -5 -exec ls -l {} \;"

    # 可疑用户
    part "# 可疑用户"
    run_command "awk -F: '{if(\$7!=\"/usr/sbin/nologin\"&&\$7!=\"/sbin/nologin\")print \$1}' /etc/passwd"
    run_command "awk -F: '{if(\$3==0||\$4==0)print \$1}' /etc/passwd"
    run_command "cat /etc/passwd"

    # pam 后门
    part "# pam 后门"
    run_command "ls -la /var/lib/extrausers/"

    # Sudoers 后门
    part "# Sudoers 后门"
    run_command "ls -la /etc/sudoers.d/"
    run_command "cat /etc/sudoers.d/*"

    # 异常用户配置
    part "# 异常用户配置"
    run_command "cat /etc/profile"
    run_command "cat /home/*/.bash_profile"

    # XDG persistence
    part "# XDG 配置"
    run_command "find /etc/xdg/autostart/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /etc/xdg/autostart/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "find /home/*/.config/autostart/ -type f -ctime -5 -exec ls -l {} \;"
    run_command "find /home/*/.config/autostart/ -type f -mtime -5 -exec ls -l {} \;"
    run_command "cat /etc/xdg/autostart/*"
    run_command "cat /home/*/.config/autostart/*"

    # rootkit排查
    part "# rootkit排查"
    run_command "lsmod"
    dmesg 1>> $Log_dir/dmesg.log 2>> $Log_dir/errlog.md

}

Main
Sys_Info
Init_Dir
System_info

# 打包
rm -rf linux_forensics.tar.gz
tar -zcvf linux_forensics.tar.gz $Log_dir
rm -rf $Log_dir

Echo_INFOR "备份至 linux_forensics.tar.gz"
