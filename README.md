# Dante SOCKS5代理服务器管理系统

这是一个基于Dante 1.4.4的SOCKS5代理服务器管理系统，提供完整的服务器管理、监控和优化解决方案。本系统专为Linux系统设计，已在CentOS 8+、Ubuntu 18.04+等系统上经过测试。

## 系统特性

### 核心功能
- 完整的用户认证和访问控制系统
- 多IP支持和智能端口管理
- 自动化的系统性能优化
- 实时监控和详细的日志分析
- 完整的服务生命周期管理
- 用户友好的命令行管理界面
- 自动化的备份和恢复机制

### 安全特性
- 严格的错误处理机制
- 自动配置文件备份
- 实时服务状态验证
- 资源使用监控和告警
- 自动化的日志管理和分析
- 防暴力破解保护

## 安装说明

### 系统要求
- Linux操作系统（CentOS 8+/Ubuntu 18.04+/Debian 10+）
- 最小1GB内存
- 10GB可用磁盘空间
- root或sudo权限

### 安装步骤
```bash
git clone https://github.com/0xlucifer666/soc.git
cd socks-server
chmod +x install.sh
./install.sh
```

安装过程会自动：
- 检查系统兼容性
- 安装必要的依赖
- 配置系统参数
- 设置服务自启动
- 创建管理工具软链接

## 管理工具使用指南

### 1. 综合管理工具（socks-admin）

主要管理界面，提供所有功能的统一入口：

```bash
socks-admin
```

功能菜单：
- 1) 用户管理
  - 添加/删除用户
  - 修改用户密码
  - 设置访问权限
  - 用户状态查看
  
- 2) IP管理
  - 添加/删除IP
  - 端口配置
  - IP状态监控
  - 流量统计
  
- 3) 服务管理
  - 启动/停止服务
  - 重启服务
  - 查看服务状态
  - 自动重启配置
  
- 4) 系统监控
  - 实时连接监控
  - 资源使用统计
  - 性能分析
  - 流量监控
  
- 5) 性能优化
  - 系统参数优化
  - 内存管理
  - 连接数优化
  - 网络参数调优
  
- 6) 日志管理
  - 实时日志查看
  - 错误日志分析
  - 日志导出
  - 日志清理

### 2. 快捷命令工具

#### 用户管理（socks-user）
```bash
socks-user add <用户名>    # 添加新用户
socks-user del <用户名>    # 删除用户
socks-user passwd <用户名> # 修改密码
socks-user list           # 列出所有用户
socks-user status <用户名> # 查看用户状态
```

#### IP管理（socks-ip）
```bash
socks-ip add <IP> <端口>   # 添加IP和端口
socks-ip del <IP>         # 删除IP配置
socks-ip list            # 列出所有IP
socks-ip status <IP>     # 查看IP状态
```

#### 监控工具（socks-monitor）
```bash
socks-monitor conn       # 查看当前连接
socks-monitor res       # 查看资源使用
socks-monitor log       # 查看实时日志
socks-monitor stat      # 查看统计信息
```

## 配置管理

### 1. 配置文件位置
- 主配置文件：`/etc/sockd.conf`
- 用户配置：`/etc/sockd/users/`
- IP配置：`/etc/sockd/ips/`
- 日志配置：`/etc/sockd/logs/`

### 2. 备份和恢复
```bash
socks-admin
# 选择"7) 系统维护" -> "1) 创建备份"
# 选择"7) 系统维护" -> "2) 恢复备份"
```

## 性能调优

### 1. 自动优化
```bash
socks-admin
# 选择"5) 性能优化" -> "1) 自动优化"
```

### 2. 手动优化
- 连接数优化：
```bash
socks-admin
# 选择"5) 性能优化" -> "2) 连接数优化"
```
- 内存优化：
```bash
socks-admin
# 选择"5) 性能优化" -> "3) 内存优化"
```

## 监控和维护

### 1. 实时监控
```bash
socks-monitor conn  # 实时连接监控
socks-monitor res   # 资源使用监控
```

### 2. 日志分析
```bash
socks-admin
# 选择"6) 日志管理" -> "2) 日志分析"
```

### 3. 性能报告
```bash
socks-admin
# 选择"4) 系统监控" -> "4) 生成报告"
```

## 故障排除指南

### 1. 服务无法启动
1. 检查服务状态：
```bash
socks-admin
# 选择"3) 服务管理" -> "4) 查看状态"
```

2. 查看错误日志：
```bash
socks-admin
# 选择"6) 日志管理" -> "2) 错误日志"
```

### 2. 连接问题
1. 检查网络配置：
```bash
socks-ip status
```

2. 检查用户状态：
```bash
socks-user status <用户名>
```

### 3. 性能问题
1. 查看系统负载：
```bash
socks-monitor res
```

2. 执行自动优化：
```bash
socks-admin
# 选择"5) 性能优化" -> "1) 自动优化"
```

## 安全建议

1. 系统安全
   - 定期更新系统和软件包
   - 使用强密码策略
   - 定期检查系统日志
   - 限制登录IP范围

2. 用户安全
   - 定期更改用户密码
   - 设置访问权限限制
   - 监控异常访问行为
   - 定期清理无效用户

3. 监控安全
   - 启用自动化监控
   - 设置资源使用告警
   - 定期备份配置文件
   - 保持日志记录完整

## 技术支持

如果遇到问题：

1. 检查日志文件
2. 查看系统状态
3. 运行自动诊断：
```bash
socks-admin
# 选择"7) 系统维护" -> "3) 系统诊断"
```

4. 提交Issue到项目仓库

## 许可证

本项目采用 MIT 许可证 
