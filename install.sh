#!/bin/bash

# 设置严格模式
set -euo pipefail
IFS=$'\n\t'

# 脚本版本
VERSION="1.0.0"

# 设置颜色输出
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# 配置目录
CONF_DIR="/etc"
INSTALL_DIR="/usr/local"
BACKUP_DIR="/var/backups/socks"
LOG_DIR="/var/log"
DANTE_VERSION="1.4.4"
DANTE_SOURCE="dante-${DANTE_VERSION}.tar.gz"
DANTE_URL="https://www.inet.no/dante/files/${DANTE_SOURCE}"

# 智能安装目录
SMART_INSTALL_DIR="/var/lib/socks-smart"

# 错误处理函数
error_handler() {
    local line_no=$1
    local error_code=$2
    echo -e "${RED}错误: 在第 $line_no 行发生错误，错误代码: $error_code${NC}"
    exit "$error_code"
}

# 设置错误处理
trap 'error_handler ${LINENO} $?' ERR

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本必须以root用户身份运行${NC}"
        exit 1
    fi
}

# 检查系统兼容性
check_system() {
    echo -e "${BLUE}检查系统兼容性...${NC}"
    
    # 检查系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS="unknown"
    fi
    
    echo -e "检测到操作系统: ${YELLOW}$OS $VER${NC}"
    
    # 检查系统架构
    ARCH=$(uname -m)
    echo -e "系统架构: ${YELLOW}$ARCH${NC}"
    
    # 检查内存
    MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    MEM_TOTAL_MB=$((MEM_TOTAL / 1024))
    echo -e "系统内存: ${YELLOW}${MEM_TOTAL_MB}MB${NC}"
    
    if [ "$MEM_TOTAL_MB" -lt 512 ]; then
        echo -e "${YELLOW}警告: 系统内存低于推荐值 512MB${NC}"
        read -p "是否继续安装? [y/N]: " continue_install
        if [[ ! "$continue_install" =~ ^[Yy]$ ]]; then
            echo -e "${RED}安装已取消${NC}"
            exit 1
        fi
    fi
    
    # 检查磁盘空间
    DISK_FREE=$(df -m / | awk 'NR==2 {print $4}')
    echo -e "可用磁盘空间: ${YELLOW}${DISK_FREE}MB${NC}"
    
    if [ "$DISK_FREE" -lt 500 ]; then
        echo -e "${YELLOW}警告: 可用磁盘空间低于推荐值 500MB${NC}"
        read -p "是否继续安装? [y/N]: " continue_install
        if [[ ! "$continue_install" =~ ^[Yy]$ ]]; then
            echo -e "${RED}安装已取消${NC}"
            exit 1
        fi
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}安装依赖...${NC}"
    
    case $OS in
        centos|rhel|fedora)
            # 检查是否有可用的包管理器
            if command -v dnf &>/dev/null; then
                PKG_MGR="dnf"
            elif command -v yum &>/dev/null; then
                PKG_MGR="yum"
            else
                echo -e "${RED}错误: 未找到支持的包管理器${NC}"
                exit 1
            fi
            
            # 安装依赖
            $PKG_MGR -y install gcc make wget tar gzip pam-devel openssl-devel
            ;;
        debian|ubuntu)
            apt-get update
            apt-get -y install gcc make wget tar gzip libpam0g-dev libssl-dev
            ;;
        *)
            echo -e "${YELLOW}未知的操作系统类型，尝试安装通用依赖...${NC}"
            # 尝试使用可能存在的包管理器
            if command -v apt-get &>/dev/null; then
                apt-get update
                apt-get -y install gcc make wget tar gzip libpam0g-dev libssl-dev
            elif command -v dnf &>/dev/null; then
                dnf -y install gcc make wget tar gzip pam-devel openssl-devel
            elif command -v yum &>/dev/null; then
                yum -y install gcc make wget tar gzip pam-devel openssl-devel
            elif command -v zypper &>/dev/null; then
                zypper -n install gcc make wget tar gzip pam-devel libopenssl-devel
            else
                echo -e "${RED}错误: 未找到支持的包管理器${NC}"
                echo -e "${YELLOW}请手动安装以下依赖: gcc, make, wget, tar, gzip, pam-devel, openssl-devel${NC}"
                exit 1
            fi
            ;;
    esac
    
    echo -e "${GREEN}依赖安装完成${NC}"
}

# 下载和编译Dante
download_and_compile() {
    echo -e "${BLUE}下载和编译Dante ${DANTE_VERSION}...${NC}"
    
    # 创建临时目录
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR" || exit 1
    
    # 下载源码
    echo -e "${YELLOW}下载源码...${NC}"
    if ! wget -q "$DANTE_URL"; then
        echo -e "${RED}错误: 下载失败${NC}"
        echo -e "${YELLOW}尝试使用备用下载地址...${NC}"
        if ! wget -q "https://www.inet.no/dante/files/old/${DANTE_SOURCE}"; then
            echo -e "${RED}错误: 备用下载也失败${NC}"
            exit 1
        fi
    fi
    
    # 解压源码
    echo -e "${YELLOW}解压源码...${NC}"
    tar -xzf "$DANTE_SOURCE"
    cd "dante-${DANTE_VERSION}" || exit 1
    
    # 配置
    echo -e "${YELLOW}配置...${NC}"
    ./configure --prefix="$INSTALL_DIR" --sysconfdir="$CONF_DIR" --localstatedir=/var --disable-client
    
    # 编译
    echo -e "${YELLOW}编译...${NC}"
    make
    
    # 安装
    echo -e "${YELLOW}安装...${NC}"
    make install
    
    # 清理
    cd / || exit 1
    rm -rf "$TMP_DIR"
    
    echo -e "${GREEN}Dante编译和安装完成${NC}"
}

# 智能检测最佳配置
detect_best_config() {
    echo -e "${BLUE}智能检测最佳配置...${NC}"
    
    # 检测CPU核心数
    local cpu_cores
    cpu_cores=$(nproc)
    echo -e "检测到CPU核心数: ${YELLOW}$cpu_cores${NC}"
    
    # 检测可用内存
    local mem_total_mb
    mem_total_mb=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))
    echo -e "检测到系统内存: ${YELLOW}${mem_total_mb}MB${NC}"
    
    # 检测网络接口
    local main_interface
    main_interface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    echo -e "检测到主网络接口: ${YELLOW}${main_interface}${NC}"
    
    # 检测公网IP
    local public_ip
    public_ip=$(curl -s https://api.ipify.org 2>/dev/null || wget -qO- https://api.ipify.org 2>/dev/null)
    if [ -n "$public_ip" ]; then
        echo -e "检测到公网IP: ${YELLOW}${public_ip}${NC}"
    else
        echo -e "${YELLOW}无法检测公网IP${NC}"
    fi
    
    # 检测系统负载
    local load_avg
    load_avg=$(awk '{print $1}' /proc/loadavg)
    echo -e "当前系统负载: ${YELLOW}${load_avg}${NC}"
    
    # 检测开放端口
    echo -e "${YELLOW}检测可用端口...${NC}"
    local available_port=1080
    while ss -tln | grep -q ":$available_port "; do
        available_port=$((available_port + 1))
    done
    echo -e "推荐使用端口: ${YELLOW}${available_port}${NC}"
    
    # 根据系统配置生成优化参数
    local optimization_level
    if [ "$mem_total_mb" -gt 8192 ] && [ "$cpu_cores" -gt 4 ]; then
        optimization_level="high"
    elif [ "$mem_total_mb" -gt 4096 ] && [ "$cpu_cores" -gt 2 ]; then
        optimization_level="medium"
    else
        optimization_level="low"
    fi
    echo -e "推荐优化级别: ${YELLOW}${optimization_level}${NC}"
    
    # 保存检测结果
    mkdir -p "$SMART_INSTALL_DIR"
    cat > "${SMART_INSTALL_DIR}/system_profile.conf" << EOL
# 系统配置文件 - $(date +"%Y-%m-%d %H:%M:%S")
CPU_CORES=$cpu_cores
MEMORY_MB=$mem_total_mb
MAIN_INTERFACE=$main_interface
PUBLIC_IP=$public_ip
RECOMMENDED_PORT=$available_port
OPTIMIZATION_LEVEL=$optimization_level
EOL
    
    # 询问是否使用推荐配置
    echo
    read -p "是否使用智能推荐的配置? [Y/n]: " use_recommended
    if [[ ! "$use_recommended" =~ ^[Nn]$ ]]; then
        RECOMMENDED_PORT="$available_port"
        OPTIMIZATION_LEVEL="$optimization_level"
        MAIN_INTERFACE="$main_interface"
        echo -e "${GREEN}将使用智能推荐的配置${NC}"
    else
        echo -e "${YELLOW}将使用默认配置${NC}"
    fi
}

# 智能优化配置
apply_smart_config() {
    echo -e "${BLUE}应用智能配置...${NC}"
    
    # 读取系统配置
    if [ -f "${SMART_INSTALL_DIR}/system_profile.conf" ]; then
        # shellcheck disable=SC1090
        source "${SMART_INSTALL_DIR}/system_profile.conf"
    fi
    
    # 创建配置文件
    echo -e "${YELLOW}根据系统配置生成最佳配置...${NC}"
    
    # 备份现有配置（如果存在）
    if [ -f "$CONF_DIR/sockd.conf" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$CONF_DIR/sockd.conf" "$BACKUP_DIR/sockd.conf.$(date +%Y%m%d%H%M%S)"
        echo -e "${YELLOW}已备份现有配置文件${NC}"
    fi
    
    # 根据优化级别设置参数
    local timeout_io=60
    local timeout_connect=30
    local udp_timeout=60
    local socket_bufsize=16384
    
    if [ "${OPTIMIZATION_LEVEL:-medium}" = "high" ]; then
        timeout_io=120
        timeout_connect=60
        udp_timeout=120
        socket_bufsize=32768
    elif [ "${OPTIMIZATION_LEVEL:-medium}" = "low" ]; then
        timeout_io=30
        timeout_connect=15
        udp_timeout=30
        socket_bufsize=8192
    fi
    
    # 创建配置文件
    cat > "$CONF_DIR/sockd.conf" << EOL
# Dante SOCKS5代理服务器配置文件
# 由智能安装程序生成 - $(date +"%Y-%m-%d %H:%M:%S")
# 优化级别: ${OPTIMIZATION_LEVEL:-medium}

# 日志设置
logoutput: /var/log/sockd.log

# 服务器设置
internal: 0.0.0.0 port = ${RECOMMENDED_PORT:-1080}
external: ${MAIN_INTERFACE:-eth0}

# 客户端连接设置
clientmethod: none
socksmethod: pam

# 用户权限设置
user.privileged: root
user.unprivileged: nobody

# 访问控制
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

# SOCKS规则
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: bind connect udpassociate
    log: error connect disconnect
}

# 超时设置 - 根据系统优化
timeout.negotiate: 30
timeout.io: $timeout_io
timeout.connect: $timeout_connect

# UDP设置 - 根据系统优化
udp.timeout: $udp_timeout
udp.connecttimeout: $((timeout_connect / 2))

# 缓冲区设置 - 根据系统优化
socket.bufsize: $socket_bufsize
EOL
    
    # 创建IP列表文件
    touch "$CONF_DIR/sockd.ips"
    echo "0.0.0.0:${RECOMMENDED_PORT:-1080}" > "$CONF_DIR/sockd.ips"
    
    # 创建日志文件
    touch "$LOG_DIR/sockd.log"
    chmod 640 "$LOG_DIR/sockd.log"
    
    echo -e "${GREEN}智能配置文件已创建${NC}"
}

# 智能系统优化
smart_system_optimize() {
    echo -e "${BLUE}执行智能系统优化...${NC}"
    
    # 读取系统配置
    if [ -f "${SMART_INSTALL_DIR}/system_profile.conf" ]; then
        # shellcheck disable=SC1090
        source "${SMART_INSTALL_DIR}/system_profile.conf"
    fi
    
    # 备份sysctl配置
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)"
    fi
    
    # 根据优化级别设置参数
    local params=()
    
    # 基础参数
    params+=(
        "fs.file-max = 1000000"
        "net.ipv4.ip_local_port_range = 1024 65535"
        "net.ipv4.tcp_tw_reuse = 1"
        "net.ipv4.tcp_fastopen = 3"
    )
    
    # 根据优化级别添加参数
    if [ "${OPTIMIZATION_LEVEL:-medium}" = "high" ]; then
        params+=(
            "net.ipv4.tcp_fin_timeout = 15"
            "net.ipv4.tcp_keepalive_time = 600"
            "net.ipv4.tcp_max_syn_backlog = 16384"
            "net.ipv4.tcp_max_tw_buckets = 10000"
            "net.core.rmem_max = 33554432"
            "net.core.wmem_max = 33554432"
            "net.core.netdev_max_backlog = 65536"
            "net.core.somaxconn = 65535"
            "vm.swappiness = 10"
        )
    elif [ "${OPTIMIZATION_LEVEL:-medium}" = "medium" ]; then
        params+=(
            "net.ipv4.tcp_fin_timeout = 30"
            "net.ipv4.tcp_keepalive_time = 1200"
            "net.ipv4.tcp_max_syn_backlog = 8192"
            "net.ipv4.tcp_max_tw_buckets = 5000"
            "net.core.rmem_max = 16777216"
            "net.core.wmem_max = 16777216"
            "net.core.netdev_max_backlog = 16384"
            "net.core.somaxconn = 32768"
            "vm.swappiness = 30"
        )
    else
        params+=(
            "net.ipv4.tcp_fin_timeout = 60"
            "net.ipv4.tcp_keepalive_time = 1800"
            "net.ipv4.tcp_max_syn_backlog = 4096"
            "net.ipv4.tcp_max_tw_buckets = 2000"
            "net.core.rmem_max = 8388608"
            "net.core.wmem_max = 8388608"
            "net.core.netdev_max_backlog = 8192"
            "net.core.somaxconn = 16384"
            "vm.swappiness = 60"
        )
    fi
    
    # 添加优化参数
    echo -e "# SOCKS5代理服务器智能优化参数 - $(date +"%Y-%m-%d")" >> /etc/sysctl.conf
    for param in "${params[@]}"; do
        echo "$param" >> /etc/sysctl.conf
        sysctl -w "${param/= /=}" >/dev/null 2>&1 || {
            echo -e "${YELLOW}警告: 无法设置参数 $param${NC}"
        }
    done
    
    # 应用参数
    sysctl -p >/dev/null 2>&1 || {
        echo -e "${RED}错误: 应用系统参数失败${NC}"
        return 1
    }
    
    echo -e "${GREEN}智能系统优化完成${NC}"
}

# 智能防火墙配置
smart_firewall_config() {
    echo -e "${BLUE}配置智能防火墙规则...${NC}"
    
    # 读取系统配置
    if [ -f "${SMART_INSTALL_DIR}/system_profile.conf" ]; then
        # shellcheck disable=SC1090
        source "${SMART_INSTALL_DIR}/system_profile.conf"
    fi
    
    local port="${RECOMMENDED_PORT:-1080}"
    
    # 检测防火墙类型
    if command -v firewall-cmd &>/dev/null; then
        # FirewallD
        echo -e "${YELLOW}检测到FirewallD防火墙${NC}"
        firewall-cmd --permanent --add-port="${port}/tcp"
        firewall-cmd --permanent --add-port="${port}/udp"
        
        # 添加高级规则
        if [ "${OPTIMIZATION_LEVEL:-medium}" = "high" ]; then
            # 添加直接规则以提高性能
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport "$port" -j ACCEPT
            firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p udp --dport "$port" -j ACCEPT
        fi
        
        firewall-cmd --reload
        echo -e "${GREEN}FirewallD规则已添加${NC}"
    elif command -v ufw &>/dev/null; then
        # UFW
        echo -e "${YELLOW}检测到UFW防火墙${NC}"
        ufw allow "${port}/tcp"
        ufw allow "${port}/udp"
        
        # 检查UFW状态
        if ! ufw status | grep -q "active"; then
            echo -e "${YELLOW}UFW未启用，是否启用? [y/N]: ${NC}"
            read -r enable_ufw
            if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
                ufw --force enable
            fi
        fi
        
        echo -e "${GREEN}UFW规则已添加${NC}"
    elif command -v iptables &>/dev/null; then
        # iptables
        echo -e "${YELLOW}使用iptables配置防火墙${NC}"
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        
        # 添加高级规则
        if [ "${OPTIMIZATION_LEVEL:-medium}" = "high" ]; then
            # 添加连接跟踪规则
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            # 优化UDP处理
            iptables -A INPUT -p udp --dport "$port" -m state --state NEW -j ACCEPT
        fi
        
        # 尝试保存规则（取决于系统）
        if [ -f /etc/debian_version ]; then
            if command -v iptables-save &>/dev/null; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4
            fi
        elif [ -f /etc/redhat-release ]; then
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/sysconfig/iptables
            fi
        fi
        echo -e "${GREEN}iptables规则已添加${NC}"
    else
        echo -e "${YELLOW}未检测到已知的防火墙，请手动配置防火墙规则${NC}"
    fi
}

# 智能安装后配置
smart_post_install() {
    echo -e "${BLUE}执行智能安装后配置...${NC}"
    
    # 读取系统配置
    if [ -f "${SMART_INSTALL_DIR}/system_profile.conf" ]; then
        # shellcheck disable=SC1090
        source "${SMART_INSTALL_DIR}/system_profile.conf"
    fi
    
    # 创建智能服务监控脚本
    cat > "${INSTALL_DIR}/bin/socks-monitor-service" << 'EOL'
#!/bin/bash

# SOCKS5代理服务智能监控脚本
# 自动检测服务状态并在必要时重启

LOG_FILE="/var/log/sockd-monitor.log"
MAX_RESTART=3
RESTART_INTERVAL=3600  # 1小时内最多重启次数

# 记录日志
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 检查服务状态
check_service() {
    if ! systemctl is-active --quiet sockd; then
        log "服务已停止，尝试重启"
        systemctl start sockd
        return 1
    fi
    
    # 检查端口是否在监听
    if ! ss -tln | grep -q ":1080 "; then
        log "服务端口未监听，尝试重启"
        systemctl restart sockd
        return 1
    fi
    
    return 0
}

# 主逻辑
main() {
    log "开始监控检查"
    
    # 检查最近重启次数
    recent_restarts=$(grep "尝试重启" "$LOG_FILE" | grep -c "$(date '+%Y-%m-%d')")
    
    if [ "$recent_restarts" -ge "$MAX_RESTART" ]; then
        log "警告: 今日重启次数已达到上限 ($MAX_RESTART)，跳过自动重启"
        exit 1
    fi
    
    # 检查服务
    if ! check_service; then
        log "服务已重启"
    else
        log "服务运行正常"
    fi
}

# 确保日志目录存在
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# 执行主逻辑
main
EOL
    
    chmod +x "${INSTALL_DIR}/bin/socks-monitor-service"
    
    # 创建定时任务
    if [ "${OPTIMIZATION_LEVEL:-medium}" = "high" ]; then
        # 高级优化：每5分钟检查一次
        (crontab -l 2>/dev/null; echo "*/5 * * * * ${INSTALL_DIR}/bin/socks-monitor-service") | crontab -
    else
        # 标准优化：每15分钟检查一次
        (crontab -l 2>/dev/null; echo "*/15 * * * * ${INSTALL_DIR}/bin/socks-monitor-service") | crontab -
    fi
    
    echo -e "${GREEN}智能监控服务已配置${NC}"
    
    # 创建自动更新脚本
    cat > "${INSTALL_DIR}/bin/socks-auto-update" << 'EOL'
#!/bin/bash

# SOCKS5代理服务自动更新脚本
# 定期检查系统更新并应用

LOG_FILE="/var/log/sockd-update.log"

# 记录日志
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# 更新系统
update_system() {
    log "开始系统更新"
    
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get upgrade -y -qq
    elif command -v dnf &>/dev/null; then
        dnf -y update -q
    elif command -v yum &>/dev/null; then
        yum -y update -q
    else
        log "未找到支持的包管理器"
        return 1
    fi
    
    log "系统更新完成"
    return 0
}

# 优化系统
optimize_system() {
    log "执行系统优化"
    
    # 清理日志
    find /var/log -type f -name "*.gz" -mtime +30 -delete
    find /var/log -type f -name "*.log.*" -mtime +15 -delete
    
    # 清理临时文件
    find /tmp -type f -atime +10 -delete
    
    log "系统优化完成"
}

# 主逻辑
main() {
    log "开始自动维护"
    
    # 更新系统
    update_system
    
    # 优化系统
    optimize_system
    
    log "自动维护完成"
}

# 确保日志目录存在
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# 执行主逻辑
main
EOL
    
    chmod +x "${INSTALL_DIR}/bin/socks-auto-update"
    
    # 创建每周自动更新的定时任务
    (crontab -l 2>/dev/null; echo "0 3 * * 0 ${INSTALL_DIR}/bin/socks-auto-update") | crontab -
    
    echo -e "${GREEN}智能自动更新已配置${NC}"
}

# 创建配置文件
create_config() {
    echo -e "${BLUE}创建配置文件...${NC}"
    
    # 备份现有配置（如果存在）
    if [ -f "$CONF_DIR/sockd.conf" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$CONF_DIR/sockd.conf" "$BACKUP_DIR/sockd.conf.$(date +%Y%m%d%H%M%S)"
        echo -e "${YELLOW}已备份现有配置文件${NC}"
    fi
    
    # 创建配置文件
    cat > "$CONF_DIR/sockd.conf" << 'EOL'
# Dante SOCKS5代理服务器配置文件

# 日志设置
logoutput: /var/log/sockd.log

# 服务器设置
internal: 0.0.0.0 port = 1080
external: eth0

# 客户端连接设置
clientmethod: none
socksmethod: pam

# 用户权限设置
user.privileged: root
user.unprivileged: nobody

# 访问控制
client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
}

# SOCKS规则
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    protocol: tcp udp
    command: bind connect udpassociate
    log: error connect disconnect
}

# 超时设置
timeout.negotiate: 30
timeout.io: 60
timeout.connect: 30

# UDP设置
udp.timeout: 60
udp.connecttimeout: 30
EOL
    
    # 创建IP列表文件
    touch "$CONF_DIR/sockd.ips"
    echo "0.0.0.0:1080" > "$CONF_DIR/sockd.ips"
    
    # 创建日志文件
    touch "$LOG_DIR/sockd.log"
    chmod 640 "$LOG_DIR/sockd.log"
    
    echo -e "${GREEN}配置文件已创建${NC}"
}

# 配置PAM认证
configure_pam() {
    echo -e "${BLUE}配置PAM认证...${NC}"
    
    cat > "$CONF_DIR/pam.d/sockd" << 'EOL'
#%PAM-1.0
auth       required     pam_unix.so
account    required     pam_unix.so
EOL
    
    echo -e "${GREEN}PAM认证已配置${NC}"
}

# 创建systemd服务
create_systemd_service() {
    echo -e "${BLUE}创建systemd服务...${NC}"
    
    cat > /etc/systemd/system/sockd.service << 'EOL'
[Unit]
Description=Dante SOCKS5 Proxy Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/sbin/sockd -D
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    # 启用服务
    systemctl enable sockd
    
    echo -e "${GREEN}systemd服务已创建并启用${NC}"
}

# 配置防火墙
configure_firewall() {
    echo -e "${BLUE}配置防火墙...${NC}"
    
    # 检测防火墙类型
    if command -v firewall-cmd &>/dev/null; then
        # FirewallD
        echo -e "${YELLOW}检测到FirewallD防火墙${NC}"
        firewall-cmd --permanent --add-port=1080/tcp
        firewall-cmd --permanent --add-port=1080/udp
        firewall-cmd --reload
        echo -e "${GREEN}FirewallD规则已添加${NC}"
    elif command -v ufw &>/dev/null; then
        # UFW
        echo -e "${YELLOW}检测到UFW防火墙${NC}"
        ufw allow 1080/tcp
        ufw allow 1080/udp
        echo -e "${GREEN}UFW规则已添加${NC}"
    elif command -v iptables &>/dev/null; then
        # iptables
        echo -e "${YELLOW}使用iptables配置防火墙${NC}"
        iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
        iptables -A INPUT -p udp --dport 1080 -j ACCEPT
        
        # 尝试保存规则（取决于系统）
        if [ -f /etc/debian_version ]; then
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/iptables/rules.v4
            fi
        elif [ -f /etc/redhat-release ]; then
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/sysconfig/iptables
            fi
        fi
        echo -e "${GREEN}iptables规则已添加${NC}"
    else
        echo -e "${YELLOW}未检测到已知的防火墙，请手动配置防火墙规则${NC}"
    fi
}

# 安装管理工具
install_admin_tools() {
    echo -e "${BLUE}安装管理工具...${NC}"
    
    # 复制管理脚本到系统目录
    cp socks-admin.sh "$INSTALL_DIR/bin/socks-admin"
    chmod +x "$INSTALL_DIR/bin/socks-admin"
    
    # 创建软链接
    ln -sf "$INSTALL_DIR/bin/socks-admin" "$INSTALL_DIR/bin/socks-user"
    ln -sf "$INSTALL_DIR/bin/socks-admin" "$INSTALL_DIR/bin/socks-ip"
    ln -sf "$INSTALL_DIR/bin/socks-admin" "$INSTALL_DIR/bin/socks-monitor"
    
    echo -e "${GREEN}管理工具安装完成${NC}"
}

# 系统优化
optimize_system() {
    echo -e "${BLUE}优化系统参数...${NC}"
    
    # 备份sysctl配置
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)"
    fi
    
    # 添加优化参数
    cat >> /etc/sysctl.conf << 'EOL'
# SOCKS5代理服务器性能优化参数
fs.file-max = 1000000
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 32768
EOL
    
    # 应用参数
    sysctl -p
    
    echo -e "${GREEN}系统参数已优化${NC}"
}

# 启动服务
start_service() {
    echo -e "${BLUE}启动服务...${NC}"
    
    systemctl start sockd
    
    # 检查服务状态
    if systemctl is-active --quiet sockd; then
        echo -e "${GREEN}服务已成功启动${NC}"
    else
        echo -e "${RED}服务启动失败${NC}"
        echo -e "${YELLOW}请检查日志: journalctl -u sockd${NC}"
    fi
}

# 显示安装信息
show_info() {
    echo -e "${GREEN}Dante SOCKS5代理服务器安装完成${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo -e "服务状态: $(systemctl is-active sockd)"
    echo -e "配置文件: $CONF_DIR/sockd.conf"
    echo -e "日志文件: $LOG_DIR/sockd.log"
    echo -e "管理工具:"
    echo -e "  - 综合管理: ${GREEN}socks-admin${NC}"
    echo -e "  - 用户管理: ${GREEN}socks-user${NC}"
    echo -e "  - IP管理: ${GREEN}socks-ip${NC}"
    echo -e "  - 系统监控: ${GREEN}socks-monitor${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo -e "如需添加用户，请运行: ${GREEN}socks-user${NC}"
}

# 主程序
main() {
    # 显示欢迎信息
    echo -e "${BLUE}Dante SOCKS5代理服务器智能安装程序 v${VERSION}${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 检查root权限
    check_root
    
    # 检查系统兼容性
    check_system
    
    # 智能检测最佳配置
    detect_best_config
    
    # 安装依赖
    install_dependencies
    
    # 下载和编译Dante
    download_and_compile
    
    # 应用智能配置
    apply_smart_config
    
    # 配置PAM认证
    configure_pam
    
    # 创建systemd服务
    create_systemd_service
    
    # 智能防火墙配置
    smart_firewall_config
    
    # 智能系统优化
    smart_system_optimize
    
    # 安装管理工具
    install_admin_tools
    
    # 创建必要的目录
    mkdir -p "$BACKUP_DIR"
    
    # 智能安装后配置
    smart_post_install
    
    # 启动服务
    start_service
    
    # 显示安装信息
    show_info
}

# 执行主程序
main 