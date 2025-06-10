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

# 配置文件路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR="/etc"
CONF_FILE="${CONF_DIR}/sockd.conf"
IP_LIST_FILE="${CONF_DIR}/sockd.ips"
TEMP_CONF="/tmp/sockd.conf.tmp"
LOG_FILE="/var/log/sockd.log"
BACKUP_DIR="/var/backups/socks"

# 智能配置目录
SMART_DIR="/var/lib/socks-smart"
HISTORY_FILE="${SMART_DIR}/usage_history.json"
LEARN_FILE="${SMART_DIR}/learned_patterns.json"
STATS_FILE="${SMART_DIR}/performance_stats.json"
RECOMMEND_FILE="${SMART_DIR}/recommendations.txt"

# 确保必要的目录存在
ensure_directories() {
    local dirs=("$CONF_DIR" "$(dirname "$LOG_FILE")" "$BACKUP_DIR")
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir" || {
                echo -e "${RED}错误: 无法创建目录 $dir${NC}"
                exit 1
            }
        fi
    done
}

# 检查必要的命令是否存在
check_requirements() {
    local required_cmds=("systemctl" "ss" "ip" "grep" "awk" "sed")
    local missing_cmds=()
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [ ${#missing_cmds[@]} -ne 0 ]; then
        echo -e "${RED}错误: 以下必需命令未找到: ${missing_cmds[*]}${NC}"
        echo -e "${YELLOW}请安装缺失的命令后重试${NC}"
        exit 1
    fi
}

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本必须以root用户身份运行${NC}"
        exit 1
    fi
}

# 错误处理函数
error_handler() {
    local line_no=$1
    local error_code=$2
    echo -e "${RED}错误: 在第 $line_no 行发生错误，错误代码: $error_code${NC}"
    echo -e "${YELLOW}请检查日志文件获取详细信息${NC}"
    exit "$error_code"
}

# 设置错误处理
trap 'error_handler ${LINENO} $?' ERR

# 备份配置文件
backup_config() {
    local backup_file="${BACKUP_DIR}/sockd_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$backup_file" -C "$CONF_DIR" "sockd.conf" "sockd.ips" 2>/dev/null || {
        echo -e "${RED}警告: 配置文件备份失败${NC}"
        return 1
    }
    echo -e "${GREEN}配置已备份到: $backup_file${NC}"
    
    # 清理旧备份，只保留最近10个
    find "$BACKUP_DIR" -name "sockd_*.tar.gz" -type f -printf '%T@ %p\n' | \
        sort -n | head -n -10 | cut -d' ' -f2- | xargs -r rm
}

# 恢复配置文件
restore_config() {
    local backup_files=("$BACKUP_DIR"/sockd_*.tar.gz)
    if [ ${#backup_files[@]} -eq 0 ]; then
        echo -e "${RED}错误: 未找到备份文件${NC}"
        return 1
    fi
    
    echo -e "${BLUE}可用的备份文件:${NC}"
    local i=1
    for file in "${backup_files[@]}"; do
        echo "$i) $(basename "$file")"
        ((i++))
    done
    
    read -p "请选择要恢复的备份文件编号: " choice
    if [ -z "$choice" ] || ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backup_files[@]} ]; then
        echo -e "${RED}错误: 无效的选择${NC}"
        return 1
    fi
    
    local selected_file="${backup_files[$((choice-1))]}"
    tar -xzf "$selected_file" -C "$CONF_DIR" || {
        echo -e "${RED}错误: 恢复配置失败${NC}"
        return 1
    }
    
    echo -e "${GREEN}配置已从 $(basename "$selected_file") 恢复${NC}"
    restart_service
}

# 验证配置文件
validate_config() {
    if [ ! -f "$CONF_FILE" ]; then
        echo -e "${RED}错误: 配置文件 $CONF_FILE 不存在${NC}"
        return 1
    fi
    
    # 检查基本配置项
    local required_configs=("internal:" "external:" "socksmethod:" "user.privileged:" "user.unprivileged:")
    local missing_configs=()
    
    for config in "${required_configs[@]}"; do
        if ! grep -q "^$config" "$CONF_FILE"; then
            missing_configs+=("$config")
        fi
    done
    
    if [ ${#missing_configs[@]} -ne 0 ]; then
        echo -e "${RED}错误: 配置文件缺少以下必需项: ${missing_configs[*]}${NC}"
        return 1
    fi
    
    return 0
}

# 检查系统资源
check_system_resources() {
    local min_memory=$((512*1024)) # 512MB in KB
    local available_memory
    available_memory=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    
    if [ "$available_memory" -lt "$min_memory" ]; then
        echo -e "${YELLOW}警告: 可用内存不足 512MB，这可能影响性能${NC}"
    fi
    
    local cpu_load
    cpu_load=$(awk '{print $1}' /proc/loadavg)
    if [ "$(echo "$cpu_load > 0.8" | bc)" -eq 1 ]; then
        echo -e "${YELLOW}警告: CPU负载较高 ($cpu_load)${NC}"
    fi
    
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$disk_usage" -gt 90 ]; then
        echo -e "${YELLOW}警告: 磁盘使用率超过90% ($disk_usage%)${NC}"
    fi
}

# 日志轮转
rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        local max_size=$((100*1024*1024)) # 100MB
        local file_size
        file_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE")
        
        if [ "$file_size" -gt "$max_size" ]; then
            local timestamp
            timestamp=$(date +%Y%m%d_%H%M%S)
            mv "$LOG_FILE" "${LOG_FILE}.${timestamp}"
            gzip "${LOG_FILE}.${timestamp}"
            touch "$LOG_FILE"
            chmod 640 "$LOG_FILE"
            echo -e "${GREEN}日志文件已轮转${NC}"
        fi
    fi
}

# 性能优化
optimize_system() {
    # 备份当前系统参数
    cp /etc/sysctl.conf "/etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)" || {
        echo -e "${RED}错误: 无法备份系统参数${NC}"
        return 1
    }
    
    # 检测系统架构和内存大小
    local mem_total
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local arch
    arch=$(uname -m)
    
    # 根据系统配置调整参数
    local params=(
        "fs.file-max = 1000000"
        "net.ipv4.ip_local_port_range = 1024 65535"
        "net.ipv4.tcp_fin_timeout = 30"
        "net.ipv4.tcp_keepalive_time = 1200"
        "net.ipv4.tcp_max_syn_backlog = 8192"
        "net.ipv4.tcp_max_tw_buckets = 5000"
        "net.ipv4.tcp_tw_reuse = 1"
        "net.ipv4.tcp_fastopen = 3"
    )
    
    # 根据内存大小调整缓冲区
    if [ "$mem_total" -gt $((8*1024*1024)) ]; then # 8GB以上内存
        params+=(
            "net.core.rmem_max = 33554432"
            "net.core.wmem_max = 33554432"
            "net.core.netdev_max_backlog = 32768"
            "net.core.somaxconn = 65535"
        )
    else
        params+=(
            "net.core.rmem_max = 16777216"
            "net.core.wmem_max = 16777216"
            "net.core.netdev_max_backlog = 16384"
            "net.core.somaxconn = 32768"
        )
    fi
    
    # 应用参数
    for param in "${params[@]}"; do
        sysctl -w "${param/= /=}" >/dev/null || {
            echo -e "${RED}警告: 无法设置参数 $param${NC}"
        }
        echo "$param" >> /etc/sysctl.conf
    done
    
    sysctl -p >/dev/null || {
        echo -e "${RED}错误: 应用系统参数失败${NC}"
        return 1
    }
    
    echo -e "${GREEN}系统参数优化完成${NC}"
}

# 初始化智能系统
init_smart_system() {
    echo -e "${BLUE}初始化智能系统...${NC}"
    
    # 创建智能系统目录
    mkdir -p "$SMART_DIR"
    
    # 初始化历史记录文件
    if [ ! -f "$HISTORY_FILE" ]; then
        echo '{"commands":[],"connections":[],"resources":[],"last_update":""}' > "$HISTORY_FILE"
    fi
    
    # 初始化学习模式文件
    if [ ! -f "$LEARN_FILE" ]; then
        echo '{"patterns":[],"optimizations":[],"last_learn":""}' > "$LEARN_FILE"
    fi
    
    # 初始化性能统计文件
    if [ ! -f "$STATS_FILE" ]; then
        echo '{"cpu":[],"memory":[],"network":[],"connections":[]}' > "$STATS_FILE"
    fi
    
    # 检查依赖
    local smart_deps=("jq" "bc")
    local missing_deps=()
    
    for dep in "${smart_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW}智能系统需要以下依赖: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}是否安装这些依赖? [Y/n]: ${NC}"
        read -r install_deps
        if [[ ! "$install_deps" =~ ^[Nn]$ ]]; then
            if command -v apt-get &>/dev/null; then
                apt-get update && apt-get install -y "${missing_deps[@]}"
            elif command -v dnf &>/dev/null; then
                dnf install -y "${missing_deps[@]}"
            elif command -v yum &>/dev/null; then
                yum install -y "${missing_deps[@]}"
            else
                echo -e "${RED}无法自动安装依赖，请手动安装: ${missing_deps[*]}${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}跳过依赖安装，智能功能将受限${NC}"
        fi
    fi
    
    # 记录初始化时间
    update_history "system" "init" "智能系统初始化"
    
    echo -e "${GREEN}智能系统初始化完成${NC}"
    return 0
}

# 记录历史
update_history() {
    local category="$1"
    local action="$2"
    local description="$3"
    
    if ! command -v jq &>/dev/null; then
        return 0
    fi
    
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 更新历史记录
    case "$category" in
        commands)
            jq --arg ts "$timestamp" --arg act "$action" --arg desc "$description" \
                '.commands += [{"timestamp":$ts,"action":$act,"description":$desc}] | .last_update=$ts' \
                "$HISTORY_FILE" > "${HISTORY_FILE}.tmp"
            ;;
        connections)
            jq --arg ts "$timestamp" --arg act "$action" --arg desc "$description" \
                '.connections += [{"timestamp":$ts,"action":$act,"description":$desc}] | .last_update=$ts' \
                "$HISTORY_FILE" > "${HISTORY_FILE}.tmp"
            ;;
        resources)
            jq --arg ts "$timestamp" --arg act "$action" --arg desc "$description" \
                '.resources += [{"timestamp":$ts,"action":$act,"description":$desc}] | .last_update=$ts' \
                "$HISTORY_FILE" > "${HISTORY_FILE}.tmp"
            ;;
        system)
            jq --arg ts "$timestamp" --arg act "$action" --arg desc "$description" \
                '.last_update=$ts' "$HISTORY_FILE" > "${HISTORY_FILE}.tmp"
            ;;
    esac
    
    # 移动临时文件
    if [ -f "${HISTORY_FILE}.tmp" ]; then
        mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"
    fi
}

# 收集性能统计
collect_performance_stats() {
    if ! command -v jq &>/dev/null; then
        return 0
    fi
    
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 收集CPU使用率
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    
    # 收集内存使用率
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    
    # 收集网络统计
    local net_stats
    net_stats=$(netstat -s | grep "total packets received\|total packets sent" | awk '{print $1}' | paste -sd+ | bc)
    
    # 收集连接数
    local conn_count
    conn_count=$(ss -ant | grep -c ":1080")
    
    # 更新统计文件
    jq --arg ts "$timestamp" --arg cpu "$cpu_usage" --arg mem "$mem_usage" \
       --arg net "$net_stats" --arg conn "$conn_count" \
       '.cpu += [{"timestamp":$ts,"value":$cpu|tonumber}] |
        .memory += [{"timestamp":$ts,"value":$mem|tonumber}] |
        .network += [{"timestamp":$ts,"value":$net|tonumber}] |
        .connections += [{"timestamp":$ts,"value":$conn|tonumber}]' \
        "$STATS_FILE" > "${STATS_FILE}.tmp"
    
    # 移动临时文件
    if [ -f "${STATS_FILE}.tmp" ]; then
        mv "${STATS_FILE}.tmp" "$STATS_FILE"
    fi
}

# 智能学习
smart_learn() {
    if ! command -v jq &>/dev/null; then
        echo -e "${YELLOW}缺少jq依赖，无法执行智能学习${NC}"
        return 1
    fi
    
    echo -e "${BLUE}正在执行智能学习...${NC}"
    
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # 分析连接模式
    local peak_hours
    peak_hours=$(jq -r '.connections | 
        map(.timestamp | split(" ")[1] | split(":")[0]) | 
        group_by(.) | 
        map({hour: .[0], count: length}) | 
        sort_by(.count) | 
        reverse | 
        .[0:3] | 
        map(.hour) | 
        join(",")' "$HISTORY_FILE")
    
    # 分析资源使用模式
    local high_load_pattern
    high_load_pattern=$(jq -r '.resources | 
        map(select(.action=="high_load")) | 
        map(.timestamp | split(" ")[1] | split(":")[0]) | 
        group_by(.) | 
        map({hour: .[0], count: length}) | 
        sort_by(.count) | 
        reverse | 
        .[0:3] | 
        map(.hour) | 
        join(",")' "$HISTORY_FILE")
    
    # 更新学习文件
    jq --arg ts "$timestamp" --arg peak "$peak_hours" --arg load "$high_load_pattern" \
       '.patterns += [{"timestamp":$ts,"peak_hours":$peak,"high_load":$load}] | .last_learn=$ts' \
       "$LEARN_FILE" > "${LEARN_FILE}.tmp"
    
    # 移动临时文件
    if [ -f "${LEARN_FILE}.tmp" ]; then
        mv "${LEARN_FILE}.tmp" "$LEARN_FILE"
    fi
    
    # 生成智能建议
    generate_recommendations
    
    echo -e "${GREEN}智能学习完成${NC}"
    return 0
}

# 生成智能建议
generate_recommendations() {
    echo -e "${BLUE}生成智能建议...${NC}"
    
    # 清空建议文件
    > "$RECOMMEND_FILE"
    
    # 分析性能统计
    local high_cpu_threshold=70
    local high_mem_threshold=80
    local avg_cpu
    local avg_mem
    
    if command -v jq &>/dev/null; then
        avg_cpu=$(jq -r '.cpu[-10:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "0")
        avg_mem=$(jq -r '.memory[-10:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "0")
        
        # CPU使用率建议
        if (( $(echo "$avg_cpu > $high_cpu_threshold" | bc -l) )); then
            echo "- [警告] CPU使用率较高 (${avg_cpu}%)，建议检查系统负载或增加资源" >> "$RECOMMEND_FILE"
            echo "  建议: 运行 'socks-admin' 选择 '5) 性能优化' -> '1) 系统参数优化'" >> "$RECOMMEND_FILE"
        fi
        
        # 内存使用率建议
        if (( $(echo "$avg_mem > $high_mem_threshold" | bc -l) )); then
            echo "- [警告] 内存使用率较高 (${avg_mem}%)，建议检查内存泄漏或增加资源" >> "$RECOMMEND_FILE"
            echo "  建议: 运行 'socks-admin' 选择 '5) 性能优化' -> '3) 内存优化'" >> "$RECOMMEND_FILE"
        fi
        
        # 连接数分析
        local max_conn
        max_conn=$(jq -r '.connections | map(.value) | max' "$STATS_FILE" 2>/dev/null || echo "0")
        local avg_conn
        avg_conn=$(jq -r '.connections[-10:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "0")
        
        if (( $(echo "$max_conn > 100" | bc -l) )); then
            echo "- [信息] 检测到高峰期连接数 ($max_conn)，建议优化连接参数" >> "$RECOMMEND_FILE"
            echo "  建议: 运行 'socks-admin' 选择 '5) 性能优化' -> '6) 连接数优化'" >> "$RECOMMEND_FILE"
        fi
        
        # 分析高峰时段
        local peak_hours
        peak_hours=$(jq -r '.patterns[-1].peak_hours // ""' "$LEARN_FILE" 2>/dev/null)
        
        if [ -n "$peak_hours" ]; then
            echo "- [信息] 检测到高峰使用时段: $peak_hours 点，建议在这些时段前进行系统优化" >> "$RECOMMEND_FILE"
        fi
    fi
    
    # 检查日志大小
    if [ -f "$LOG_FILE" ]; then
        local log_size
        log_size=$(du -m "$LOG_FILE" | cut -f1)
        
        if [ "$log_size" -gt 100 ]; then
            echo "- [警告] 日志文件较大 (${log_size}MB)，建议进行日志轮转" >> "$RECOMMEND_FILE"
            echo "  建议: 运行 'socks-admin' 选择 '6) 日志查看' -> '8) 清理日志'" >> "$RECOMMEND_FILE"
        fi
    fi
    
    # 检查配置文件备份
    local backup_count
    backup_count=$(find "$BACKUP_DIR" -name "sockd_*.tar.gz" | wc -l)
    
    if [ "$backup_count" -eq 0 ]; then
        echo "- [警告] 未发现配置备份，建议创建配置备份" >> "$RECOMMEND_FILE"
        echo "  建议: 运行 'socks-admin' 选择 '3) 服务管理' -> '7) 备份配置'" >> "$RECOMMEND_FILE"
    fi
    
    echo -e "${GREEN}智能建议生成完成${NC}"
}

# 应用智能优化
apply_smart_optimization() {
    echo -e "${BLUE}应用智能优化...${NC}"
    
    # 检查系统资源
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    
    # 根据资源使用情况调整参数
    if (( $(echo "$cpu_usage > 70" | bc -l) )); then
        echo -e "${YELLOW}检测到CPU使用率较高 (${cpu_usage}%)，优化CPU相关参数${NC}"
        
        # 优化系统参数
        sysctl -w net.core.netdev_max_backlog=32768 >/dev/null 2>&1
        sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1
    fi
    
    if (( $(echo "$mem_usage > 80" | bc -l) )); then
        echo -e "${YELLOW}检测到内存使用率较高 (${mem_usage}%)，优化内存相关参数${NC}"
        
        # 优化内存参数
        sysctl -w vm.swappiness=10 >/dev/null 2>&1
    fi
    
    # 检查连接数并优化
    local conn_count
    conn_count=$(ss -ant | grep -c ":1080")
    
    if [ "$conn_count" -gt 100 ]; then
        echo -e "${YELLOW}检测到高连接数 ($conn_count)，优化连接参数${NC}"
        
        # 优化连接参数
        sysctl -w net.ipv4.tcp_fin_timeout=15 >/dev/null 2>&1
        sysctl -w net.ipv4.tcp_keepalive_time=600 >/dev/null 2>&1
    fi
    
    # 记录优化操作
    update_history "resources" "optimize" "应用智能优化，CPU: ${cpu_usage}%, 内存: ${mem_usage}%, 连接数: ${conn_count}"
    
    echo -e "${GREEN}智能优化应用完成${NC}"
}

# 显示智能仪表板
show_smart_dashboard() {
    clear
    echo -e "${BLUE}智能系统仪表板${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 显示系统状态
    echo -e "${YELLOW}系统状态:${NC}"
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    local mem_usage
    mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    local disk_usage
    disk_usage=$(df -h / | awk 'NR==2 {print $5}')
    local conn_count
    conn_count=$(ss -ant | grep -c ":1080")
    
    echo -e "CPU使用率: $(colorize_value "$cpu_usage" 50 80)%"
    echo -e "内存使用率: $(colorize_value "$mem_usage" 60 85)%"
    echo -e "磁盘使用率: $disk_usage"
    echo -e "当前连接数: $conn_count"
    
    # 显示智能建议
    echo -e "\n${YELLOW}智能建议:${NC}"
    if [ -f "$RECOMMEND_FILE" ] && [ -s "$RECOMMEND_FILE" ]; then
        cat "$RECOMMEND_FILE"
    else
        echo "暂无智能建议"
    fi
    
    # 显示学习状态
    echo -e "\n${YELLOW}学习状态:${NC}"
    if command -v jq &>/dev/null && [ -f "$LEARN_FILE" ]; then
        local last_learn
        last_learn=$(jq -r '.last_learn // "从未"' "$LEARN_FILE")
        echo "上次学习时间: $last_learn"
        
        local pattern_count
        pattern_count=$(jq -r '.patterns | length' "$LEARN_FILE")
        echo "已学习模式数: $pattern_count"
    else
        echo "智能学习未启用或缺少依赖"
    fi
    
    # 显示性能趋势
    echo -e "\n${YELLOW}性能趋势 (最近24小时):${NC}"
    if command -v jq &>/dev/null && [ -f "$STATS_FILE" ]; then
        local cpu_trend
        cpu_trend=$(jq -r '.cpu[-24:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "N/A")
        local mem_trend
        mem_trend=$(jq -r '.memory[-24:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "N/A")
        local conn_trend
        conn_trend=$(jq -r '.connections[-24:] | map(.value) | add / length' "$STATS_FILE" 2>/dev/null || echo "N/A")
        
        echo -e "平均CPU使用率: $(colorize_value "$cpu_trend" 50 80)%"
        echo -e "平均内存使用率: $(colorize_value "$mem_trend" 60 85)%"
        echo -e "平均连接数: $conn_trend"
    else
        echo "性能统计未启用或缺少依赖"
    fi
    
    read -p "按回车键继续..."
}

# 根据值的范围返回颜色
colorize_value() {
    local value="$1"
    local warn_threshold="$2"
    local crit_threshold="$3"
    
    if (( $(echo "$value > $crit_threshold" | bc -l) )); then
        echo -e "${RED}$value${NC}"
    elif (( $(echo "$value > $warn_threshold" | bc -l) )); then
        echo -e "${YELLOW}$value${NC}"
    else
        echo -e "${GREEN}$value${NC}"
    fi
}

# 智能菜单
smart_menu() {
    while true; do
        clear
        echo -e "${BLUE}智能系统管理${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 查看智能仪表板"
        echo -e "2) 执行智能学习"
        echo -e "3) 应用智能优化"
        echo -e "4) 查看智能建议"
        echo -e "5) 查看性能统计"
        echo -e "6) 查看使用历史"
        echo -e "7) 配置智能系统"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-7]: " choice
        
        case $choice in
            1) show_smart_dashboard ;;
            2) smart_learn ;;
            3) apply_smart_optimization ;;
            4) 
                clear
                echo -e "${BLUE}智能建议${NC}"
                echo -e "${YELLOW}================================${NC}"
                if [ -f "$RECOMMEND_FILE" ] && [ -s "$RECOMMEND_FILE" ]; then
                    cat "$RECOMMEND_FILE"
                else
                    echo "暂无智能建议"
                fi
                read -p "按回车键继续..."
                ;;
            5) 
                clear
                echo -e "${BLUE}性能统计${NC}"
                echo -e "${YELLOW}================================${NC}"
                if command -v jq &>/dev/null && [ -f "$STATS_FILE" ]; then
                    echo -e "CPU使用率 (最近10次采样):"
                    jq -r '.cpu[-10:] | map(.timestamp + ": " + (.value|tostring) + "%") | .[]' "$STATS_FILE" 2>/dev/null
                    echo -e "\n内存使用率 (最近10次采样):"
                    jq -r '.memory[-10:] | map(.timestamp + ": " + (.value|tostring) + "%") | .[]' "$STATS_FILE" 2>/dev/null
                    echo -e "\n连接数 (最近10次采样):"
                    jq -r '.connections[-10:] | map(.timestamp + ": " + (.value|tostring)) | .[]' "$STATS_FILE" 2>/dev/null
                else
                    echo "性能统计未启用或缺少依赖"
                fi
                read -p "按回车键继续..."
                ;;
            6) 
                clear
                echo -e "${BLUE}使用历史${NC}"
                echo -e "${YELLOW}================================${NC}"
                if command -v jq &>/dev/null && [ -f "$HISTORY_FILE" ]; then
                    echo -e "最近10次操作:"
                    jq -r '.commands[-10:] | map(.timestamp + " - " + .action + ": " + .description) | .[]' "$HISTORY_FILE" 2>/dev/null
                else
                    echo "使用历史未启用或缺少依赖"
                fi
                read -p "按回车键继续..."
                ;;
            7) 
                clear
                echo -e "${BLUE}配置智能系统${NC}"
                echo -e "${YELLOW}================================${NC}"
                echo -e "1) 启用/禁用性能统计收集"
                echo -e "2) 启用/禁用智能学习"
                echo -e "3) 清除历史数据"
                echo -e "4) 返回"
                read -p "请选择操作 [1-4]: " config_choice
                case $config_choice in
                    1) echo "功能开发中..." ;;
                    2) echo "功能开发中..." ;;
                    3) 
                        read -p "确定要清除所有历史数据吗? [y/N]: " confirm
                        if [[ "$confirm" =~ ^[Yy]$ ]]; then
                            rm -f "$HISTORY_FILE" "$STATS_FILE" "$LEARN_FILE" "$RECOMMEND_FILE"
                            init_smart_system
                            echo -e "${GREEN}历史数据已清除${NC}"
                        fi
                        ;;
                    *) ;;
                esac
                ;;
            0) return ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# 主程序初始化
init() {
    check_root
    check_requirements
    ensure_directories
    validate_config || {
        echo -e "${RED}错误: 配置验证失败${NC}"
        exit 1
    }
    check_system_resources
    rotate_logs
    
    # 初始化智能系统
    init_smart_system
    
    # 收集初始性能统计
    collect_performance_stats
}

# Dante SOCKS5代理服务器综合管理工具
# 整合用户管理、IP管理、服务管理和监控功能

# 显示主菜单
show_main_menu() {
    clear
    echo -e "${BLUE}Dante SOCKS5代理服务器管理系统${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo -e "1) 用户管理"
    echo -e "2) IP管理"
    echo -e "3) 服务管理"
    echo -e "4) 系统监控"
    echo -e "5) 性能优化"
    echo -e "6) 日志查看"
    echo -e "7) 智能系统"
    echo -e "0) 退出"
    echo
    read -p "请选择操作 [0-7]: " choice
    
    case $choice in
        1) user_management_menu ;;
        2) ip_management_menu ;;
        3) service_management_menu ;;
        4) monitoring_menu ;;
        5) optimization_menu ;;
        6) log_menu ;;
        7) smart_menu ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ; show_main_menu ;;
    esac
}

# 用户管理菜单
user_management_menu() {
    while true; do
        clear
        echo -e "${BLUE}用户管理${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 添加用户"
        echo -e "2) 删除用户"
        echo -e "3) 修改密码"
        echo -e "4) 列出所有用户"
        echo -e "5) 查看用户状态"
        echo -e "6) 批量导入用户"
        echo -e "7) 导出用户列表"
        echo -e "8) 设置用户限制"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) add_user ;;
            2) delete_user ;;
            3) change_password ;;
            4) list_users ;;
            5) check_user_status ;;
            6) bulk_import_users ;;
            7) export_users ;;
            8) set_user_limits ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# IP管理菜单
ip_management_menu() {
    while true; do
        clear
        echo -e "${BLUE}IP管理${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 添加IP"
        echo -e "2) 删除IP"
        echo -e "3) 列出所有IP"
        echo -e "4) 检查IP状态"
        echo -e "5) 修改IP端口"
        echo -e "6) IP流量统计"
        echo -e "7) IP访问控制"
        echo -e "8) 重载IP配置"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) add_ip ;;
            2) delete_ip ;;
            3) list_ips ;;
            4) check_ip_status ;;
            5) modify_ip_port ;;
            6) ip_traffic_stats ;;
            7) ip_access_control ;;
            8) reload_ip_config ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# 服务管理菜单
service_management_menu() {
    while true; do
        clear
        echo -e "${BLUE}服务管理${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 启动服务"
        echo -e "2) 停止服务"
        echo -e "3) 重启服务"
        echo -e "4) 查看服务状态"
        echo -e "5) 查看连接信息"
        echo -e "6) 配置自动重启"
        echo -e "7) 备份配置"
        echo -e "8) 恢复配置"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) start_service ;;
            2) stop_service ;;
            3) restart_service ;;
            4) check_service_status ;;
            5) show_connections ;;
            6) configure_auto_restart ;;
            7) backup_config ;;
            8) restore_config ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# 系统监控菜单
monitoring_menu() {
    while true; do
        clear
        echo -e "${BLUE}系统监控${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 实时连接监控"
        echo -e "2) 资源使用统计"
        echo -e "3) 流量统计"
        echo -e "4) 用户活动记录"
        echo -e "5) 异常检测"
        echo -e "6) 性能报告"
        echo -e "7) 导出统计数据"
        echo -e "8) 设置告警规则"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) monitor_connections ;;
            2) resource_usage_stats ;;
            3) traffic_stats ;;
            4) user_activity_log ;;
            5) anomaly_detection ;;
            6) performance_report ;;
            7) export_statistics ;;
            8) set_alert_rules ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# 性能优化菜单
optimization_menu() {
    while true; do
        clear
        echo -e "${BLUE}性能优化${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 系统参数优化"
        echo -e "2) 网络参数优化"
        echo -e "3) 内存优化"
        echo -e "4) TCP优化"
        echo -e "5) UDP优化"
        echo -e "6) 连接数优化"
        echo -e "7) 自动优化"
        echo -e "8) 还原默认设置"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) optimize_system ;;
            2) optimize_network ;;
            3) optimize_memory ;;
            4) optimize_tcp ;;
            5) optimize_udp ;;
            6) optimize_connections ;;
            7) auto_optimize ;;
            8) restore_defaults ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

# 日志查看菜单
log_menu() {
    while true; do
        clear
        echo -e "${BLUE}日志查看${NC}"
        echo -e "${YELLOW}================================${NC}"
        echo -e "1) 实时日志"
        echo -e "2) 错误日志"
        echo -e "3) 访问日志"
        echo -e "4) 系统日志"
        echo -e "5) 搜索日志"
        echo -e "6) 导出日志"
        echo -e "7) 日志分析"
        echo -e "8) 清理日志"
        echo -e "0) 返回主菜单"
        echo
        read -p "请选择操作 [0-8]: " choice
        
        case $choice in
            1) view_realtime_log ;;
            2) view_error_log ;;
            3) view_access_log ;;
            4) view_system_log ;;
            5) search_log ;;
            6) export_log ;;
            7) analyze_log ;;
            8) clean_log ;;
            0) show_main_menu ;;
            *) echo -e "${RED}无效的选择${NC}" ; sleep 2 ;;
        esac
    done
}

### 用户管理功能 ###

# 添加用户
add_user() {
    clear
    echo -e "${BLUE}添加新用户${NC}"
    echo -e "${YELLOW}================================${NC}"
    read -p "请输入用户名: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}错误: 用户名不能为空${NC}"
        sleep 2
        return
    fi
    
    if id "$username" &>/dev/null; then
        echo -e "${RED}错误: 用户 $username 已存在${NC}"
        sleep 2
        return
    fi
    
    useradd -M -s /sbin/nologin "$username"
    passwd "$username"
    echo -e "${GREEN}用户 $username 已添加${NC}"
    sleep 2
}

# 删除用户
delete_user() {
    clear
    echo -e "${BLUE}删除用户${NC}"
    echo -e "${YELLOW}================================${NC}"
    read -p "请输入要删除的用户名: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}错误: 用户名不能为空${NC}"
        sleep 2
        return
    fi
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}错误: 用户 $username 不存在${NC}"
        sleep 2
        return
    fi
    
    userdel -r "$username"
    echo -e "${GREEN}用户 $username 已删除${NC}"
    sleep 2
}

# 修改密码
change_password() {
    clear
    echo -e "${BLUE}修改用户密码${NC}"
    echo -e "${YELLOW}================================${NC}"
    read -p "请输入用户名: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}错误: 用户名不能为空${NC}"
        sleep 2
        return
    fi
    
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}错误: 用户 $username 不存在${NC}"
        sleep 2
        return
    fi
    
    passwd "$username"
    echo -e "${GREEN}用户 $username 的密码已更新${NC}"
    sleep 2
}

# 列出所有用户
list_users() {
    clear
    echo -e "${BLUE}用户列表${NC}"
    echo -e "${YELLOW}================================${NC}"
    echo -e "${YELLOW}用户名\t\t最后密码修改时间${NC}"
    echo "----------------------------------------"
    
    for user in $(awk -F: '$3 >= 1000 && $7 == "/sbin/nologin" {print $1}' /etc/passwd); do
        last_change=$(chage -l "$user" | grep "最近更改" | awk -F: '{print $2}')
        if [ -z "$last_change" ]; then
            last_change=$(chage -l "$user" | grep "Last password change" | awk -F: '{print $2}')
        fi
        echo -e "${GREEN}$user${NC}\t\t$last_change"
    done
    
    read -p "按回车键继续..."
}

### IP管理功能 ###

# 列出所有IP
list_ips() {
    echo -e "${BLUE}当前配置的IP地址列表:${NC}"
    echo -e "${YELLOW}IP地址\t\t端口\t\t状态${NC}"
    echo "----------------------------------------"
    
    if [ -s "$IP_LIST_FILE" ]; then
        while IFS=: read -r ip port; do
            # 检查IP状态
            local status="未知"
            if ip -br addr show | grep -q "$ip"; then
                if ss -tln | grep -q ":$port"; then
                    status="${GREEN}活跃${NC}"
                else
                    status="${YELLOW}IP在线，端口未监听${NC}"
                fi
            else
                status="${RED}离线${NC}"
            fi
            
            # 使用printf确保对齐
            printf "%-15s %-8s %s\n" "$ip" "$port" "$status"
        done < "$IP_LIST_FILE"
    else
        echo -e "${YELLOW}暂无配置的IP地址，使用默认配置 0.0.0.0:1080${NC}"
    fi
}

# 添加IP
add_ip() {
    clear
    echo -e "${BLUE}添加新IP${NC}"
    echo -e "${YELLOW}================================${NC}"
    read -p "请输入IP地址: " ip
    read -p "请输入端口号 [1080]: " port
    
    port=${port:-1080}
    
    # 支持特殊IP格式
    if [ "$ip" = "all" ] || [ "$ip" = "ANY" ] || [ "$ip" = "any" ]; then
        ip="0.0.0.0"
        echo -e "${YELLOW}将使用 0.0.0.0 (所有接口)${NC}"
    fi
    
    if ! validate_ip "$ip"; then
        echo -e "${RED}错误: 无效的IP地址格式${NC}"
        sleep 2
        return 1
    fi
    
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 无效的端口号${NC}"
        sleep 2
        return 1
    fi
    
    # 检查端口冲突
    if ss -tln | grep -q ":$port " && ! grep -q ":$port$" "$IP_LIST_FILE"; then
        echo -e "${YELLOW}警告: 端口 $port 已被其他服务使用${NC}"
        read -p "是否仍要继续? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            sleep 2
            return 0
        fi
    fi
    
    if check_ip_exists "$ip" "$port"; then
        echo -e "${RED}错误: IP:端口 $ip:$port 已存在${NC}"
        sleep 2
        return 1
    fi
    
    # 检查IP是否存在于系统中
    if ! ip -br addr show | grep -q "$ip" && [ "$ip" != "0.0.0.0" ]; then
        echo -e "${YELLOW}警告: IP地址 $ip 不存在于任何网络接口${NC}"
        read -p "是否仍要继续? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            sleep 2
            return 0
        fi
    fi
    
    # 备份配置
    backup_config
    
    echo "${ip}:${port}" >> "$IP_LIST_FILE"
    update_config
    echo -e "${GREEN}已添加IP配置: $ip:$port${NC}"
    
    # 检查服务状态并提示重启
    if systemctl is-active --quiet sockd; then
        read -p "是否立即重启服务以应用更改? [Y/n]: " restart
        if [[ ! "$restart" =~ ^[Nn]$ ]]; then
            restart_service
        else
            echo -e "${YELLOW}请记得稍后重启服务以应用更改${NC}"
        fi
    fi
    
    sleep 2
}

# 删除IP
delete_ip() {
    clear
    echo -e "${BLUE}删除IP${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    if [ ! -s "$IP_LIST_FILE" ]; then
        echo -e "${YELLOW}IP列表为空${NC}"
        sleep 2
        return 0
    fi
    
    echo -e "${YELLOW}当前配置的IP:${NC}"
    local i=1
    local ip_list=()
    while IFS=: read -r ip port; do
        echo "$i) $ip:$port"
        ip_list+=("$ip:$port")
        ((i++))
    done < "$IP_LIST_FILE"
    
    if [ ${#ip_list[@]} -eq 0 ]; then
        echo -e "${YELLOW}IP列表为空${NC}"
        sleep 2
        return 0
    fi
    
    read -p "请选择要删除的IP编号 [1-${#ip_list[@]}]: " choice
    
    if [ -z "$choice" ] || ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#ip_list[@]} ]; then
        echo -e "${RED}错误: 无效的选择${NC}"
        sleep 2
        return 1
    fi
    
    local selected_ip="${ip_list[$((choice-1))]}"
    IFS=: read -r ip port <<< "$selected_ip"
    
    # 备份配置
    backup_config
    
    sed -i "/^${ip}:${port}$/d" "$IP_LIST_FILE"
    update_config
    echo -e "${GREEN}已删除IP配置: $ip:$port${NC}"
    
    # 检查是否删除了所有IP
    if [ ! -s "$IP_LIST_FILE" ]; then
        echo -e "${YELLOW}警告: 已删除所有IP配置，将使用默认配置 0.0.0.0:1080${NC}"
    fi
    
    # 检查服务状态并提示重启
    if systemctl is-active --quiet sockd; then
        read -p "是否立即重启服务以应用更改? [Y/n]: " restart
        if [[ ! "$restart" =~ ^[Nn]$ ]]; then
            restart_service
        else
            echo -e "${YELLOW}请记得稍后重启服务以应用更改${NC}"
        fi
    fi
    
    sleep 2
}

# 修改IP端口
modify_ip_port() {
    clear
    echo -e "${BLUE}修改IP端口${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    if [ ! -s "$IP_LIST_FILE" ]; then
        echo -e "${YELLOW}IP列表为空${NC}"
        sleep 2
        return 0
    fi
    
    echo -e "${YELLOW}当前配置的IP:${NC}"
    local i=1
    local ip_list=()
    while IFS=: read -r ip port; do
        echo "$i) $ip:$port"
        ip_list+=("$ip:$port")
        ((i++))
    done < "$IP_LIST_FILE"
    
    read -p "请选择要修改的IP编号 [1-${#ip_list[@]}]: " choice
    
    if [ -z "$choice" ] || ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#ip_list[@]} ]; then
        echo -e "${RED}错误: 无效的选择${NC}"
        sleep 2
        return 1
    fi
    
    local selected_ip="${ip_list[$((choice-1))]}"
    IFS=: read -r ip port <<< "$selected_ip"
    
    read -p "请输入新端口号: " new_port
    
    if ! validate_port "$new_port"; then
        echo -e "${RED}错误: 无效的端口号${NC}"
        sleep 2
        return 1
    fi
    
    # 检查端口冲突
    if ss -tln | grep -q ":$new_port " && ! grep -q ":$new_port$" "$IP_LIST_FILE"; then
        echo -e "${YELLOW}警告: 端口 $new_port 已被其他服务使用${NC}"
        read -p "是否仍要继续? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            sleep 2
            return 0
        fi
    fi
    
    if check_ip_exists "$ip" "$new_port"; then
        echo -e "${RED}错误: IP:端口 $ip:$new_port 已存在${NC}"
        sleep 2
        return 1
    fi
    
    # 备份配置
    backup_config
    
    # 更新IP列表文件
    sed -i "s/^${ip}:${port}$/${ip}:${new_port}/" "$IP_LIST_FILE"
    update_config
    echo -e "${GREEN}已将 $ip 的端口从 $port 修改为 $new_port${NC}"
    
    # 检查服务状态并提示重启
    if systemctl is-active --quiet sockd; then
        read -p "是否立即重启服务以应用更改? [Y/n]: " restart
        if [[ ! "$restart" =~ ^[Nn]$ ]]; then
            restart_service
        else
            echo -e "${YELLOW}请记得稍后重启服务以应用更改${NC}"
        fi
    fi
    
    sleep 2
}

# 检查IP状态
check_ip_status() {
    clear
    echo -e "${BLUE}检查IP状态${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    if [ ! -s "$IP_LIST_FILE" ]; then
        echo -e "${YELLOW}IP列表为空，使用默认配置 0.0.0.0:1080${NC}"
        
        # 检查默认配置
        if ss -tln | grep -q ":1080 "; then
            echo -e "${GREEN}默认端口 1080 正在监听${NC}"
        else
            echo -e "${RED}默认端口 1080 未监听${NC}"
        fi
        
        read -p "按回车键继续..."
        return 0
    fi
    
    echo -e "${YELLOW}IP地址\t\t端口\t\t状态\t\t连接数${NC}"
    echo "--------------------------------------------------------------"
    
    while IFS=: read -r ip port; do
        # 检查IP状态
        local status="未知"
        local conn_count=0
        
        if [ "$ip" = "0.0.0.0" ]; then
            if ss -tln | grep -q ":$port "; then
                status="${GREEN}活跃${NC}"
                conn_count=$(ss -ant | grep ":$port " | wc -l)
            else
                status="${RED}未监听${NC}"
            fi
        elif ip -br addr show | grep -q "$ip"; then
            if ss -tln | grep -q ":$port "; then
                status="${GREEN}活跃${NC}"
                conn_count=$(ss -ant | grep "$ip:$port " | wc -l)
            else
                status="${YELLOW}IP在线，端口未监听${NC}"
            fi
        else
            status="${RED}离线${NC}"
        fi
        
        # 使用printf确保对齐
        printf "%-15s %-8s %-20s %s\n" "$ip" "$port" "$status" "$conn_count"
    done < "$IP_LIST_FILE"
    
    echo -e "\n${YELLOW}系统网络接口:${NC}"
    ip -br addr show
    
    read -p "按回车键继续..."
}

# IP流量统计
ip_traffic_stats() {
    clear
    echo -e "${BLUE}IP流量统计${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 检查是否安装了必要的工具
    if ! command -v vnstat &>/dev/null; then
        echo -e "${YELLOW}未检测到vnstat工具，是否安装? [Y/n]: ${NC}"
        read -p "" install
        if [[ ! "$install" =~ ^[Nn]$ ]]; then
            if command -v apt &>/dev/null; then
                apt update && apt install -y vnstat
            elif command -v yum &>/dev/null; then
                yum install -y vnstat
            elif command -v dnf &>/dev/null; then
                dnf install -y vnstat
            else
                echo -e "${RED}无法确定包管理器，请手动安装vnstat${NC}"
                sleep 2
                return 1
            fi
            
            # 启动vnstat服务
            systemctl enable --now vnstat
        else
            echo -e "${YELLOW}跳过安装，将使用基本统计方法${NC}"
        fi
    fi
    
    # 显示IP列表
    echo -e "${YELLOW}选择要查看的IP:${NC}"
    echo "0) 所有IP"
    
    local i=1
    local ip_list=()
    while IFS=: read -r ip port; do
        echo "$i) $ip:$port"
        ip_list+=("$ip:$port")
        ((i++))
    done < "$IP_LIST_FILE"
    
    read -p "请选择 [0-${#ip_list[@]}]: " choice
    
    if [ -z "$choice" ] || ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt ${#ip_list[@]} ]; then
        echo -e "${RED}错误: 无效的选择${NC}"
        sleep 2
        return 1
    fi
    
    clear
    if [ "$choice" = "0" ]; then
        echo -e "${BLUE}所有IP的流量统计${NC}"
        if command -v vnstat &>/dev/null; then
            vnstat
        else
            echo -e "${YELLOW}未安装vnstat，显示基本连接统计${NC}"
            ss -s
            echo -e "\n${YELLOW}当前SOCKS连接:${NC}"
            ss -ant | grep -E ":(1080|$(awk -F: '{print $2}' "$IP_LIST_FILE" | tr '\n' '|' | sed 's/|$//'))" | wc -l
        fi
    else
        local selected_ip="${ip_list[$((choice-1))]}"
        IFS=: read -r ip port <<< "$selected_ip"
        
        echo -e "${BLUE}IP $ip:$port 的流量统计${NC}"
        if command -v vnstat &>/dev/null && [ "$ip" != "0.0.0.0" ]; then
            # 查找对应的网络接口
            local interface
            interface=$(ip -br addr show | grep "$ip" | awk '{print $1}')
            if [ -n "$interface" ]; then
                vnstat -i "$interface"
            else
                echo -e "${YELLOW}找不到IP $ip 对应的网络接口${NC}"
            fi
        else
            echo -e "${YELLOW}显示基本连接统计${NC}"
            if [ "$ip" = "0.0.0.0" ]; then
                echo -e "\n${YELLOW}端口 $port 的当前连接数:${NC}"
                ss -ant | grep ":$port " | wc -l
            else
                echo -e "\n${YELLOW}IP:端口 $ip:$port 的当前连接数:${NC}"
                ss -ant | grep "$ip:$port " | wc -l
            fi
        fi
    fi
    
    read -p "按回车键继续..."
}

# 验证IP地址格式
validate_ip() {
    local ip=$1
    
    # 特殊情况: 0.0.0.0表示所有接口
    if [ "$ip" = "0.0.0.0" ]; then
        return 0
    fi
    
    # IPv4地址验证
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

# 检查IP是否存在
check_ip_exists() {
    local ip=$1
    local port=$2
    grep -q "^${ip}:${port}$" "$IP_LIST_FILE"
    return $?
}

# 更新配置文件
update_config() {
    # 创建临时配置文件
    cp "$CONF_FILE" "$TEMP_CONF" || {
        echo -e "${RED}错误: 无法创建临时配置文件${NC}"
        return 1
    }
    
    # 删除旧的internal配置
    sed -i '/^internal:/d' "$TEMP_CONF"
    
    # 添加新的internal配置
    if [ -s "$IP_LIST_FILE" ]; then
        while IFS=: read -r ip port; do
            echo "internal: $ip port = $port" >> "$TEMP_CONF"
        done < "$IP_LIST_FILE"
    else
        # 如果IP列表为空，添加默认配置
        echo "internal: 0.0.0.0 port = 1080" >> "$TEMP_CONF"
    fi
    
    # 替换原配置文件
    mv "$TEMP_CONF" "$CONF_FILE" || {
        echo -e "${RED}错误: 无法更新配置文件${NC}"
        return 1
    }
    
    echo -e "${GREEN}配置文件已更新${NC}"
    return 0
}

# 重载IP配置
reload_ip_config() {
    clear
    echo -e "${BLUE}重载IP配置${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 备份配置
    backup_config
    
    # 更新配置文件
    if update_config; then
        # 重启服务
        if systemctl is-active --quiet sockd; then
            systemctl restart sockd || {
                echo -e "${RED}错误: 重启服务失败${NC}"
                sleep 2
                return 1
            }
            echo -e "${GREEN}配置已重新加载，服务已重启${NC}"
        else
            echo -e "${YELLOW}配置已重新加载，但服务未运行${NC}"
            read -p "是否立即启动服务? [Y/n]: " start
            if [[ ! "$start" =~ ^[Nn]$ ]]; then
                systemctl start sockd || {
                    echo -e "${RED}错误: 启动服务失败${NC}"
                    sleep 2
                    return 1
                }
                echo -e "${GREEN}服务已启动${NC}"
            fi
        fi
    fi
    
    sleep 2
}

# 服务管理功能

# 启动服务
start_service() {
    echo -e "${BLUE}正在启动服务...${NC}"
    
    # 检查服务是否已经运行
    if systemctl is-active --quiet sockd; then
        echo -e "${YELLOW}服务已经在运行中${NC}"
        return 0
    fi
    
    # 检查配置文件
    if ! validate_config; then
        echo -e "${RED}错误: 配置文件验证失败，服务可能无法正常启动${NC}"
        read -p "是否仍要尝试启动服务? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            return 1
        fi
    fi
    
    # 尝试启动服务
    if systemctl start sockd; then
        echo -e "${GREEN}服务已成功启动${NC}"
        
        # 等待服务完全启动
        sleep 2
        
        # 检查服务状态
        if systemctl is-active --quiet sockd; then
            # 检查端口是否正在监听
            local listening=false
            if [ -s "$IP_LIST_FILE" ]; then
                while IFS=: read -r _ port; do
                    if ss -tln | grep -q ":$port "; then
                        listening=true
                        break
                    fi
                done < "$IP_LIST_FILE"
            else
                if ss -tln | grep -q ":1080 "; then
                    listening=true
                fi
            fi
            
            if [ "$listening" = true ]; then
                echo -e "${GREEN}服务正在监听端口${NC}"
            else
                echo -e "${YELLOW}警告: 服务已启动但未检测到监听端口${NC}"
            fi
        else
            echo -e "${YELLOW}警告: 服务可能未完全启动，请检查日志${NC}"
        fi
    else
        echo -e "${RED}错误: 服务启动失败${NC}"
        echo -e "${YELLOW}请检查日志获取详细信息: journalctl -u sockd${NC}"
        return 1
    fi
    
    return 0
}

# 停止服务
stop_service() {
    echo -e "${BLUE}正在停止服务...${NC}"
    
    # 检查服务是否正在运行
    if ! systemctl is-active --quiet sockd; then
        echo -e "${YELLOW}服务未在运行${NC}"
        return 0
    fi
    
    # 检查活动连接
    local active_conn
    active_conn=$(ss -ant | grep -E ":(1080|$(awk -F: '{print $2}' "$IP_LIST_FILE" 2>/dev/null | tr '\n' '|' | sed 's/|$//'))" | wc -l)
    
    if [ "$active_conn" -gt 0 ]; then
        echo -e "${YELLOW}警告: 当前有 $active_conn 个活动连接${NC}"
        read -p "是否仍要停止服务? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            return 0
        fi
    fi
    
    # 尝试停止服务
    if systemctl stop sockd; then
        echo -e "${GREEN}服务已成功停止${NC}"
        
        # 确认服务已停止
        if ! systemctl is-active --quiet sockd; then
            # 检查端口是否已关闭
            local ports_closed=true
            if [ -s "$IP_LIST_FILE" ]; then
                while IFS=: read -r _ port; do
                    if ss -tln | grep -q ":$port "; then
                        ports_closed=false
                        echo -e "${YELLOW}警告: 端口 $port 仍在监听${NC}"
                    fi
                done < "$IP_LIST_FILE"
            else
                if ss -tln | grep -q ":1080 "; then
                    ports_closed=false
                    echo -e "${YELLOW}警告: 端口 1080 仍在监听${NC}"
                fi
            fi
            
            if [ "$ports_closed" = true ]; then
                echo -e "${GREEN}所有端口已关闭${NC}"
            fi
        else
            echo -e "${RED}错误: 服务可能未完全停止${NC}"
        fi
    else
        echo -e "${RED}错误: 服务停止失败${NC}"
        echo -e "${YELLOW}请检查日志获取详细信息: journalctl -u sockd${NC}"
        return 1
    fi
    
    return 0
}

# 重启服务
restart_service() {
    echo -e "${BLUE}正在重启服务...${NC}"
    
    # 检查配置文件
    if ! validate_config; then
        echo -e "${RED}错误: 配置文件验证失败，服务可能无法正常重启${NC}"
        read -p "是否仍要尝试重启服务? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            return 1
        fi
    fi
    
    # 尝试重启服务
    if systemctl restart sockd; then
        echo -e "${GREEN}服务已成功重启${NC}"
        
        # 等待服务完全启动
        sleep 2
        
        # 检查服务状态
        if systemctl is-active --quiet sockd; then
            # 检查端口是否正在监听
            local listening=false
            if [ -s "$IP_LIST_FILE" ]; then
                while IFS=: read -r _ port; do
                    if ss -tln | grep -q ":$port "; then
                        listening=true
                        break
                    fi
                done < "$IP_LIST_FILE"
            else
                if ss -tln | grep -q ":1080 "; then
                    listening=true
                fi
            fi
            
            if [ "$listening" = true ]; then
                echo -e "${GREEN}服务正在监听端口${NC}"
            else
                echo -e "${YELLOW}警告: 服务已重启但未检测到监听端口${NC}"
            fi
        else
            echo -e "${RED}错误: 服务重启失败${NC}"
        fi
    else
        echo -e "${RED}错误: 服务重启失败${NC}"
        echo -e "${YELLOW}请检查日志获取详细信息: journalctl -u sockd${NC}"
        return 1
    fi
    
    return 0
}

# 检查服务状态
check_service_status() {
    clear
    echo -e "${BLUE}服务状态${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 检查服务是否安装
    if ! systemctl list-unit-files | grep -q sockd.service; then
        echo -e "${RED}错误: sockd 服务未安装${NC}"
        read -p "按回车键继续..."
        return 1
    fi
    
    # 获取服务状态
    local service_status
    service_status=$(systemctl is-active sockd)
    local service_enabled
    service_enabled=$(systemctl is-enabled sockd)
    
    echo -e "服务状态: $(if [ "$service_status" = "active" ]; then echo "${GREEN}运行中${NC}"; else echo "${RED}已停止${NC}"; fi)"
    echo -e "开机启动: $(if [ "$service_enabled" = "enabled" ]; then echo "${GREEN}已启用${NC}"; else echo "${YELLOW}未启用${NC}"; fi)"
    
    # 显示进程信息
    echo -e "\n${YELLOW}进程信息:${NC}"
    if pgrep -x sockd >/dev/null; then
        ps -o pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,cmd -p "$(pgrep -x sockd)"
    else
        echo -e "${RED}未找到 sockd 进程${NC}"
    fi
    
    # 显示端口监听状态
    echo -e "\n${YELLOW}端口监听状态:${NC}"
    if [ -s "$IP_LIST_FILE" ]; then
        while IFS=: read -r ip port; do
            local status
            if ss -tln | grep -q ":$port "; then
                status="${GREEN}监听中${NC}"
            else
                status="${RED}未监听${NC}"
            fi
            echo -e "IP: $ip, 端口: $port - $status"
        done < "$IP_LIST_FILE"
    else
        local status
        if ss -tln | grep -q ":1080 "; then
            status="${GREEN}监听中${NC}"
        else
            status="${RED}未监听${NC}"
        fi
        echo -e "IP: 0.0.0.0, 端口: 1080 - $status"
    fi
    
    # 显示最近日志
    echo -e "\n${YELLOW}最近日志:${NC}"
    if [ -f "$LOG_FILE" ]; then
        tail -n 10 "$LOG_FILE"
    else
        echo -e "${RED}日志文件不存在${NC}"
    fi
    
    # 显示系统日志
    echo -e "\n${YELLOW}系统日志:${NC}"
    journalctl -u sockd --no-pager -n 10
    
    read -p "按回车键继续..."
}

# 查看连接信息
show_connections() {
    clear
    echo -e "${BLUE}当前连接信息${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 获取端口列表
    local ports
    if [ -s "$IP_LIST_FILE" ]; then
        ports=$(awk -F: '{print $2}' "$IP_LIST_FILE" | tr '\n' '|' | sed 's/|$//')
    else
        ports="1080"
    fi
    
    # 检查是否有连接
    local conn_count
    conn_count=$(ss -ant | grep -E ":(${ports})" | wc -l)
    
    if [ "$conn_count" -eq 0 ]; then
        echo -e "${YELLOW}当前没有活动连接${NC}"
    else
        echo -e "${GREEN}当前活动连接数: $conn_count${NC}"
        
        echo -e "\n${YELLOW}连接详情:${NC}"
        echo -e "本地地址:端口\t\t远程地址:端口\t\t状态\t\t已建立时间"
        echo "--------------------------------------------------------------------------------"
        
        # 获取连接信息并排序
        ss -ant | grep -E ":(${ports})" | sort -k4 | while read -r line; do
            local local_addr
            local_addr=$(echo "$line" | awk '{print $4}')
            local remote_addr
            remote_addr=$(echo "$line" | awk '{print $5}')
            local state
            state=$(echo "$line" | awk '{print $2}')
            local timer
            timer=$(echo "$line" | awk '{print $6}')
            
            # 格式化状态
            case "$state" in
                ESTAB)
                    state="${GREEN}已建立${NC}"
                    ;;
                TIME-WAIT)
                    state="${YELLOW}等待关闭${NC}"
                    ;;
                CLOSE-WAIT)
                    state="${RED}等待关闭${NC}"
                    ;;
                *)
                    state="${BLUE}$state${NC}"
                    ;;
            esac
            
            printf "%-20s\t%-20s\t%-15s\t%s\n" "$local_addr" "$remote_addr" "$state" "$timer"
        done
        
        # 显示连接统计
        echo -e "\n${YELLOW}连接状态统计:${NC}"
        ss -s | grep -A 4 "TCP:"
    fi
    
    # 显示连接速率（如果可用）
    if command -v iftop &>/dev/null; then
        echo -e "\n${YELLOW}是否查看实时网络流量? [Y/n]: ${NC}"
        read -p "" show_traffic
        if [[ ! "$show_traffic" =~ ^[Nn]$ ]]; then
            # 获取主要网络接口
            local interface
            interface=$(ip route | grep default | awk '{print $5}' | head -n 1)
            if [ -n "$interface" ]; then
                iftop -i "$interface" -P -N -f "port (${ports})"
            else
                echo -e "${RED}无法确定主要网络接口${NC}"
            fi
        fi
    else
        echo -e "\n${YELLOW}提示: 安装 iftop 可以查看实时网络流量${NC}"
    fi
    
    read -p "按回车键继续..."
}

# 配置自动重启
configure_auto_restart() {
    clear
    echo -e "${BLUE}配置服务自动重启${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 检查当前设置
    local restart_enabled
    if systemctl show -p Restart sockd | grep -q "Restart=always"; then
        restart_enabled=true
        echo -e "${GREEN}服务已配置为自动重启${NC}"
    else
        restart_enabled=false
        echo -e "${YELLOW}服务未配置自动重启${NC}"
    fi
    
    echo -e "\n${YELLOW}选择操作:${NC}"
    echo "1) 启用自动重启"
    echo "2) 禁用自动重启"
    echo "3) 返回"
    
    read -p "请选择 [1-3]: " choice
    
    case $choice in
        1)
            if [ "$restart_enabled" = true ]; then
                echo -e "${YELLOW}自动重启已经启用${NC}"
            else
                # 创建临时override目录
                mkdir -p /etc/systemd/system/sockd.service.d/
                
                # 创建override配置
                cat > /etc/systemd/system/sockd.service.d/override.conf << 'EOL'
[Service]
Restart=always
RestartSec=5
EOL
                
                # 重新加载systemd配置
                systemctl daemon-reload
                
                echo -e "${GREEN}自动重启已启用${NC}"
                echo -e "${YELLOW}服务将在崩溃后5秒自动重启${NC}"
            fi
            ;;
        2)
            if [ "$restart_enabled" = false ]; then
                echo -e "${YELLOW}自动重启已经禁用${NC}"
            else
                # 删除override配置
                rm -rf /etc/systemd/system/sockd.service.d/
                
                # 重新加载systemd配置
                systemctl daemon-reload
                
                echo -e "${GREEN}自动重启已禁用${NC}"
            fi
            ;;
        3)
            return 0
            ;;
        *)
            echo -e "${RED}无效的选择${NC}"
            ;;
    esac
    
    sleep 2
}

# 监控功能

# 实时连接监控
monitor_connections() {
    clear
    echo -e "${BLUE}实时连接监控${NC}"
    echo -e "${YELLOW}按 Ctrl+C 退出监控${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 获取端口列表
    local ports
    if [ -s "$IP_LIST_FILE" ]; then
        ports=$(awk -F: '{print $2}' "$IP_LIST_FILE" | tr '\n' '|' | sed 's/|$//')
    else
        ports="1080"
    fi
    
    # 检查是否安装了watch命令
    if ! command -v watch &>/dev/null; then
        echo -e "${YELLOW}未检测到watch命令，将使用基本监控${NC}"
        echo -e "${YELLOW}按 Ctrl+C 退出${NC}"
        
        while true; do
            clear
            local conn_count
            conn_count=$(ss -ant | grep -E ":(${ports})" | wc -l)
            echo -e "${BLUE}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
            echo -e "${GREEN}当前连接数: $conn_count${NC}"
            echo -e "${YELLOW}详细连接信息:${NC}"
            ss -ant | grep -E ":(${ports})" | awk '{printf "%-20s %-20s %-10s\n", $4, $5, $2}'
            sleep 2
        done
    else
        # 使用watch命令进行实时监控
        watch -n 2 "echo '当前连接数: ' && ss -ant | grep -E ':(${ports})' | wc -l && echo '详细连接信息:' && ss -ant | grep -E ':(${ports})' | awk '{printf \"%-20s %-20s %-10s\\n\", \$4, \$5, \$2}'"
    fi
}

# 资源使用统计
resource_usage_stats() {
    clear
    echo -e "${BLUE}资源使用统计${NC}"
    echo -e "${YELLOW}================================${NC}"
    
    # 检查是否安装了必要的工具
    local missing_tools=()
    for tool in top free df; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}以下必要工具未安装: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}请安装缺失的工具后重试${NC}"
        read -p "按回车键继续..."
        return 1
    fi
    
    # 显示系统负载
    echo -e "${YELLOW}系统负载:${NC}"
    uptime
    
    # 显示CPU使用情况
    echo -e "\n${YELLOW}CPU使用情况:${NC}"
    top -bn1 | head -n 5
    
    # 显示内存使用情况
    echo -e "\n${YELLOW}内存使用情况:${NC}"
    free -h
    
    # 显示磁盘使用情况
    echo -e "\n${YELLOW}磁盘使用情况:${NC}"
    df -h
    
    # 显示sockd进程资源使用情况
    echo -e "\n${YELLOW}SOCKS服务资源使用情况:${NC}"
    if pgrep -x sockd >/dev/null; then
        top -bn1 -p "$(pgrep -x sockd | tr '\n' ',' | sed 's/,$//')" | tail -n +7
    else
        echo -e "${RED}未找到sockd进程${NC}"
    fi
    
    # 显示网络连接统计
    echo -e "\n${YELLOW}网络连接统计:${NC}"
    ss -s
    
    # 显示网络接口统计
    echo -e "\n${YELLOW}网络接口统计:${NC}"
    ip -s link
    
    read -p "按回车键继续..."
}

# 启动主程序
show_main_menu 