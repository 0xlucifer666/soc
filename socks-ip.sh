#!/bin/bash

# SOCKS5代理服务器IP管理脚本
# 用于管理多IP配置

# 设置颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 配置文件路径
CONF_FILE="/etc/sockd.conf"
IP_LIST_FILE="/etc/sockd.ips"
TEMP_CONF="/tmp/sockd.conf.tmp"

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}错误: 此脚本必须以root用户身份运行${NC}" 1>&2
   exit 1
fi

# 确保配置文件存在
if [ ! -f "$CONF_FILE" ]; then
    echo -e "${RED}错误: 配置文件 $CONF_FILE 不存在${NC}"
    exit 1
fi

# 如果IP列表文件不存在，创建它
if [ ! -f "$IP_LIST_FILE" ]; then
    touch "$IP_LIST_FILE"
fi

# 显示帮助信息
show_help() {
    echo -e "${BLUE}SOCKS5代理服务器IP管理工具${NC}"
    echo -e "${YELLOW}用法:${NC}"
    echo -e "  $0 ${GREEN}add${NC} <IP地址> [端口]     - 添加新IP地址和端口(默认1080)"
    echo -e "  $0 ${GREEN}del${NC} <IP地址> [端口]     - 删除指定IP地址和端口"
    echo -e "  $0 ${GREEN}list${NC}                    - 列出所有IP配置"
    echo -e "  $0 ${GREEN}check${NC} <IP地址>          - 检查IP状态"
    echo -e "  $0 ${GREEN}reload${NC}                  - 重新加载配置"
    echo -e "  $0 ${GREEN}help${NC}                    - 显示此帮助信息"
}

# 验证IP地址格式
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    local IFS='.'
    local -a ip_parts=($ip)
    
    for part in "${ip_parts[@]}"; do
        if [ "$part" -lt 0 ] || [ "$part" -gt 255 ]; then
            return 1
        fi
    done
    
    return 0
}

# 验证端口号
validate_port() {
    local port=$1
    if [[ ! $port =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# 检查IP是否已存在
check_ip_exists() {
    local ip=$1
    local port=$2
    grep -q "^${ip}:${port}$" "$IP_LIST_FILE"
    return $?
}

# 添加新IP
add_ip() {
    local ip=$1
    local port=${2:-1080}
    
    # 验证IP地址
    if ! validate_ip "$ip"; then
        echo -e "${RED}错误: 无效的IP地址格式${NC}"
        return 1
    fi
    
    # 验证端口号
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 无效的端口号${NC}"
        return 1
    fi
    
    # 检查IP:端口组合是否已存在
    if check_ip_exists "$ip" "$port"; then
        echo -e "${YELLOW}警告: IP:端口 $ip:$port 已存在${NC}"
        return 1
    fi
    
    # 添加IP到列表
    echo "${ip}:${port}" >> "$IP_LIST_FILE"
    
    # 更新配置文件
    update_config
    
    echo -e "${GREEN}已添加IP配置: $ip:$port${NC}"
    
    # 提示重启服务
    echo -e "${YELLOW}请运行 'systemctl restart sockd' 使更改生效${NC}"
}

# 删除IP
del_ip() {
    local ip=$1
    local port=${2:-1080}
    
    # 验证IP地址
    if ! validate_ip "$ip"; then
        echo -e "${RED}错误: 无效的IP地址格式${NC}"
        return 1
    fi
    
    # 验证端口号
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 无效的端口号${NC}"
        return 1
    fi
    
    # 检查IP是否存在
    if ! check_ip_exists "$ip" "$port"; then
        echo -e "${RED}错误: IP:端口 $ip:$port 不存在${NC}"
        return 1
    fi
    
    # 从列表中删除IP
    sed -i "/^${ip}:${port}$/d" "$IP_LIST_FILE"
    
    # 更新配置文件
    update_config
    
    echo -e "${GREEN}已删除IP配置: $ip:$port${NC}"
    
    # 提示重启服务
    echo -e "${YELLOW}请运行 'systemctl restart sockd' 使更改生效${NC}"
}

# 列出所有IP
list_ips() {
    echo -e "${BLUE}当前配置的IP地址列表:${NC}"
    echo -e "${YELLOW}IP地址\t\t端口${NC}"
    echo "----------------------------------------"
    
    if [ -s "$IP_LIST_FILE" ]; then
        while IFS=: read -r ip port; do
            echo -e "${GREEN}$ip\t$port${NC}"
        done < "$IP_LIST_FILE"
    else
        echo -e "${YELLOW}暂无配置的IP地址${NC}"
    fi
}

# 检查IP状态
check_ip() {
    local ip=$1
    
    # 验证IP地址
    if ! validate_ip "$ip"; then
        echo -e "${RED}错误: 无效的IP地址格式${NC}"
        return 1
    fi
    
    echo -e "${BLUE}检查IP $ip 的状态:${NC}"
    
    # 检查IP是否配置
    local configured=false
    while IFS=: read -r conf_ip port; do
        if [ "$conf_ip" = "$ip" ]; then
            configured=true
            echo -e "${GREEN}已配置: $ip:$port${NC}"
            
            # 检查IP是否在线
            if ip addr show | grep -q "$ip"; then
                echo -e "${GREEN}状态: 在线${NC}"
                
                # 检查端口是否在监听
                if ss -tln | grep -q ":$port"; then
                    echo -e "${GREEN}端口 $port: 正在监听${NC}"
                else
                    echo -e "${RED}端口 $port: 未监听${NC}"
                fi
            else
                echo -e "${RED}状态: 离线${NC}"
            fi
        fi
    done < "$IP_LIST_FILE"
    
    if [ "$configured" = false ]; then
        echo -e "${RED}IP未配置${NC}"
    fi
}

# 更新配置文件
update_config() {
    # 创建临时配置文件
    cp "$CONF_FILE" "$TEMP_CONF"
    
    # 删除旧的internal配置
    sed -i '/^internal:/d' "$TEMP_CONF"
    
    # 添加新的internal配置
    while IFS=: read -r ip port; do
        echo "internal: $ip port = $port" >> "$TEMP_CONF"
    done < "$IP_LIST_FILE"
    
    # 如果IP列表为空，添加默认配置
    if [ ! -s "$IP_LIST_FILE" ]; then
        echo "internal: 0.0.0.0 port = 1080" >> "$TEMP_CONF"
    fi
    
    # 替换原配置文件
    mv "$TEMP_CONF" "$CONF_FILE"
}

# 重新加载配置
reload_config() {
    echo -e "${BLUE}重新加载配置...${NC}"
    
    # 更新配置文件
    update_config
    
    # 重启服务
    if systemctl is-active --quiet sockd; then
        systemctl restart sockd
        echo -e "${GREEN}配置已重新加载，服务已重启${NC}"
    else
        echo -e "${YELLOW}配置已重新加载，但服务未运行${NC}"
    fi
}

# 主逻辑
case "$1" in
    add)
        add_ip "$2" "$3"
        ;;
    del)
        del_ip "$2" "$3"
        ;;
    list)
        list_ips
        ;;
    check)
        check_ip "$2"
        ;;
    reload)
        reload_config
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