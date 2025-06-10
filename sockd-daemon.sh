#!/bin/bash

# Dante SOCKS5代理服务器守护进程启动脚本
# 使用start-stop-daemon管理

### 配置信息 ###
NAME=sockd
DESC="Dante SOCKS5代理服务器"
DAEMON=/usr/sbin/sockd
PIDFILE=/var/run/sockd.pid
CONFFILE=/etc/sockd.conf
DAEMON_OPTS="-D -f ${CONFFILE}"
USER=root
GROUP=root

# 确保start-stop-daemon可用
if ! command -v start-stop-daemon >/dev/null; then
    echo "错误: start-stop-daemon未安装"
    exit 1
fi

# 确保sockd程序存在
if [ ! -x "$DAEMON" ]; then
    echo "错误: $DAEMON 不存在或不可执行"
    exit 1
fi

# 确保配置文件存在
if [ ! -f "$CONFFILE" ]; then
    echo "错误: 配置文件 $CONFFILE 不存在"
    exit 1
fi

### 函数定义 ###

# 启动服务
do_start() {
    echo "正在启动 $DESC..."
    
    # 检查是否已经运行
    if [ -f "$PIDFILE" ]; then
        if kill -0 $(cat "$PIDFILE") 2>/dev/null; then
            echo "$DESC 已经在运行"
            return 1
        else
            rm -f "$PIDFILE"
        fi
    fi
    
    # 使用start-stop-daemon启动服务
    start-stop-daemon --start \
        --quiet \
        --pidfile "$PIDFILE" \
        --exec "$DAEMON" \
        --chuid "$USER:$GROUP" \
        --background \
        --make-pidfile \
        -- $DAEMON_OPTS
    
    # 检查启动状态
    if [ $? -eq 0 ]; then
        echo "$DESC 启动成功"
        return 0
    else
        echo "$DESC 启动失败"
        return 1
    fi
}

# 停止服务
do_stop() {
    echo "正在停止 $DESC..."
    
    # 使用start-stop-daemon停止服务
    start-stop-daemon --stop \
        --quiet \
        --pidfile "$PIDFILE" \
        --exec "$DAEMON" \
        --retry=TERM/30/KILL/5
    
    # 检查停止状态
    if [ $? -eq 0 ]; then
        rm -f "$PIDFILE"
        echo "$DESC 已停止"
        return 0
    else
        echo "$DESC 停止失败"
        return 1
    fi
}

# 重启服务
do_restart() {
    echo "正在重启 $DESC..."
    do_stop
    sleep 1
    do_start
}

# 检查状态
do_status() {
    if [ -f "$PIDFILE" ]; then
        if kill -0 $(cat "$PIDFILE") 2>/dev/null; then
            echo "$DESC 正在运行，PID: $(cat $PIDFILE)"
            return 0
        else
            echo "$DESC 未运行，但PID文件存在"
            return 1
        fi
    else
        echo "$DESC 未运行"
        return 3
    fi
}

### 主逻辑 ###
case "$1" in
    start)
        do_start
        ;;
    stop)
        do_stop
        ;;
    restart)
        do_restart
        ;;
    status)
        do_status
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0 