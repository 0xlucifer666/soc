#!/bin/bash

# SOCKS5代理用户管理脚本
# 用于添加、删除、修改密码和列出代理用户
# 适用于CentOS 8+

# 设置颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}错误: 此脚本必须以root用户身份运行${NC}" 1>&2
   exit 1
fi

# 显示帮助信息
show_help() {
    echo -e "${BLUE}SOCKS5代理用户管理工具${NC}"
    echo -e "${YELLOW}用法:${NC}"
    echo -e "  $0 ${GREEN}add${NC} <用户名> [密码]     - 添加新用户"
    echo -e "  $0 ${GREEN}del${NC} <用户名>           - 删除用户"
    echo -e "  $0 ${GREEN}passwd${NC} <用户名>        - 修改用户密码"
    echo -e "  $0 ${GREEN}list${NC}                  - 列出所有代理用户"
    echo -e "  $0 ${GREEN}status${NC} <用户名>        - 检查用户状态"
    echo -e "  $0 ${GREEN}help${NC}                  - 显示此帮助信息"
}

# 添加用户
add_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}错误: 缺少用户名参数${NC}"
        show_help
        exit 1
    fi
    
    # 检查用户是否已存在
    if id "$1" &>/dev/null; then
        echo -e "${YELLOW}警告: 用户 $1 已存在${NC}"
        exit 1
    fi
    
    # 创建用户
    useradd -M -s /sbin/nologin "$1"
    
    # 如果提供了密码参数，则直接设置密码
    if [ -n "$2" ]; then
        echo "$1:$2" | chpasswd
        echo -e "${GREEN}用户 $1 已添加，密码已设置${NC}"
    else
        # 否则交互式设置密码
        passwd "$1"
        echo -e "${GREEN}用户 $1 已添加${NC}"
    fi
}

# 删除用户
del_user() {
    if [ -z "$1" ]; then
        echo -e "${RED}错误: 缺少用户名参数${NC}"
        show_help
        exit 1
    fi
    
    # 检查用户是否存在
    if ! id "$1" &>/dev/null; then
        echo -e "${RED}错误: 用户 $1 不存在${NC}"
        exit 1
    fi
    
    # 删除用户
    userdel "$1"
    echo -e "${GREEN}用户 $1 已删除${NC}"
}

# 修改用户密码
change_passwd() {
    if [ -z "$1" ]; then
        echo -e "${RED}错误: 缺少用户名参数${NC}"
        show_help
        exit 1
    fi
    
    # 检查用户是否存在
    if ! id "$1" &>/dev/null; then
        echo -e "${RED}错误: 用户 $1 不存在${NC}"
        exit 1
    fi
    
    # 修改密码
    passwd "$1"
    echo -e "${GREEN}用户 $1 的密码已更新${NC}"
}

# 列出所有代理用户
list_users() {
    echo -e "${BLUE}SOCKS5代理用户列表:${NC}"
    echo -e "${YELLOW}用户名\t\t最后密码修改时间${NC}"
    echo "-------------------------------------"
    
    # 获取所有非系统用户
    for user in $(awk -F: '$3 >= 1000 && $7 == "/sbin/nologin" {print $1}' /etc/passwd); do
        # 获取密码最后修改时间
        last_change=$(chage -l "$user" | grep "最近更改" | awk -F: '{print $2}')
        if [ -z "$last_change" ]; then
            last_change=$(chage -l "$user" | grep "Last password change" | awk -F: '{print $2}')
        fi
        echo -e "${GREEN}$user${NC}\t\t$last_change"
    done
}

# 检查用户状态
check_status() {
    if [ -z "$1" ]; then
        echo -e "${RED}错误: 缺少用户名参数${NC}"
        show_help
        exit 1
    fi
    
    # 检查用户是否存在
    if ! id "$1" &>/dev/null; then
        echo -e "${RED}错误: 用户 $1 不存在${NC}"
        exit 1
    fi
    
    # 显示用户信息
    echo -e "${BLUE}用户 $1 的状态:${NC}"
    echo -e "${YELLOW}账户信息:${NC}"
    id "$1"
    
    echo -e "\n${YELLOW}密码信息:${NC}"
    chage -l "$1"
}

# 主逻辑
case "$1" in
    add)
        add_user "$2" "$3"
        ;;
    del)
        del_user "$2"
        ;;
    passwd)
        change_passwd "$2"
        ;;
    list)
        list_users
        ;;
    status)
        check_status "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}错误: 未知命令 $1${NC}"
        show_help
        exit 1
        ;;
esac

exit 0 