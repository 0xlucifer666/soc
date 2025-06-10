#!/bin/bash

# SOCKS5代理服务器性能监控和优化脚本
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

# 检查必要的工具是否安装
check_tools() {
    local missing_tools=()
    
    for tool in ss netstat lsof tcpdump sysctl; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}警告: 以下工具未安装: ${missing_tools[*]}${NC}"
        echo -e "${GREEN}正在安装缺失的工具...${NC}"
        
        # 安装缺失的工具
        dnf -y install iproute procps-ng lsof tcpdump
        
        echo -e "${GREEN}工具安装完成${NC}"
    fi
}

# 显示帮助信息
show_help() {
    echo -e "${BLUE}SOCKS5代理服务器性能监控和优化工具${NC}"
    echo -e "${YELLOW}用法:${NC}"
    echo -e "  $0 ${GREEN}status${NC}              - 显示当前服务状态"
    echo -e "  $0 ${GREEN}connections${NC}         - 显示当前连接信息"
    echo -e "  $0 ${GREEN}optimize${NC}            - 优化系统参数"
    echo -e "  $0 ${GREEN}log${NC} [行数]          - 显示日志(默认20行)"
    echo -e "  $0 ${GREEN}top-users${NC}           - 显示最活跃的用户"
    echo -e "  $0 ${GREEN}top-destinations${NC}    - 显示最常访问的目标"
    echo -e "  $0 ${GREEN}help${NC}                - 显示此帮助信息"
}

# 显示服务状态
show_status() {
    echo -e "${BLUE}SOCKS5代理服务器状态:${NC}"
    
    # 检查服务状态
    if systemctl is-active --quiet sockd; then
        echo -e "${GREEN}服务状态: 运行中${NC}"
    else
        echo -e "${RED}服务状态: 未运行${NC}"
    fi
    
    # 显示进程信息
    echo -e "\n${YELLOW}进程信息:${NC}"
    ps aux | grep sockd | grep -v grep
    
    # 显示端口监听状态
    echo -e "\n${YELLOW}端口监听状态:${NC}"
    ss -tulpn | grep sockd
    
    # 显示系统资源使用情况
    echo -e "\n${YELLOW}系统资源使用情况:${NC}"
    echo -e "CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
    echo -e "内存使用率: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
    echo -e "磁盘使用率: $(df -h / | awk 'NR==2{print $5}')"
    
    # 显示网络接口状态
    echo -e "\n${YELLOW}网络接口状态:${NC}"
    ip -s link | grep -A 5 eth
}

# 显示当前连接信息
show_connections() {
    echo -e "${BLUE}当前SOCKS5连接信息:${NC}"
    
    # 显示总连接数
    local conn_count=$(ss -tan | grep ":1080" | wc -l)
    echo -e "${YELLOW}总连接数: ${GREEN}$conn_count${NC}"
    
    # 显示连接状态统计
    echo -e "\n${YELLOW}连接状态统计:${NC}"
    ss -tan | grep ":1080" | awk '{print $1}' | sort | uniq -c | sort -nr
    
    # 显示客户端IP统计
    echo -e "\n${YELLOW}客户端IP统计(前10):${NC}"
    ss -tan | grep ":1080" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
    
    # 显示UDP连接
    echo -e "\n${YELLOW}UDP连接:${NC}"
    ss -uan | grep ":1080"
    
    # 显示连接详情
    echo -e "\n${YELLOW}连接详情(最新20个):${NC}"
    ss -tan | grep ":1080" | head -20
}

# 优化系统参数
optimize_system() {
    echo -e "${BLUE}正在优化系统参数...${NC}"
    
    # 备份当前系统参数
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 添加优化参数
    cat >> /etc/sysctl.conf << 'EOL'

# SOCKS5代理服务器性能优化参数
# 添加时间: $(date +%Y-%m-%d)

# 增加最大文件描述符数量
fs.file-max = 1000000

# 增加本地端口范围
net.ipv4.ip_local_port_range = 1024 65535

# TCP优化
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0

# 内存优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 32768

# UDP优化
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOL
    
    # 应用新参数
    sysctl -p
    
    # 优化系统限制
    cat > /etc/security/limits.d/99-sockd.conf << 'EOL'
# 增加SOCKS5代理服务器系统限制
# 添加时间: $(date +%Y-%m-%d)

*               soft    nofile          1000000
*               hard    nofile          1000000
root            soft    nofile          1000000
root            hard    nofile          1000000
nobody          soft    nofile          1000000
nobody          hard    nofile          1000000
EOL
    
    echo -e "${GREEN}系统参数优化完成${NC}"
    echo -e "${YELLOW}注意: 部分优化需要重启系统才能生效${NC}"
}

# 显示日志
show_log() {
    local lines=${1:-20}
    
    echo -e "${BLUE}SOCKS5代理服务器日志(最新${lines}行):${NC}"
    
    if [ -f /var/log/sockd.log ]; then
        tail -n $lines /var/log/sockd.log
    else
        echo -e "${RED}错误: 找不到日志文件 /var/log/sockd.log${NC}"
    fi
}

# 显示最活跃的用户
show_top_users() {
    echo -e "${BLUE}最活跃的SOCKS5用户:${NC}"
    
    if [ -f /var/log/sockd.log ]; then
        echo -e "${YELLOW}分析中，请稍候...${NC}"
        
        # 从日志中提取用户名和连接次数
        grep "authentication successful" /var/log/sockd.log | awk '{print $8}' | sort | uniq -c | sort -nr | head -10
    else
        echo -e "${RED}错误: 找不到日志文件 /var/log/sockd.log${NC}"
    fi
}

# 显示最常访问的目标
show_top_destinations() {
    echo -e "${BLUE}最常访问的目标:${NC}"
    
    if [ -f /var/log/sockd.log ]; then
        echo -e "${YELLOW}分析中，请稍候...${NC}"
        
        # 从日志中提取目标地址和端口
        grep "connected to" /var/log/sockd.log | awk '{print $10}' | sort | uniq -c | sort -nr | head -20
    else
        echo -e "${RED}错误: 找不到日志文件 /var/log/sockd.log${NC}"
    fi
}

# 检查工具
check_tools

# 主逻辑
case "$1" in
    status)
        show_status
        ;;
    connections)
        show_connections
        ;;
    optimize)
        optimize_system
        ;;
    log)
        show_log "$2"
        ;;
    top-users)
        show_top_users
        ;;
    top-destinations)
        show_top_destinations
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