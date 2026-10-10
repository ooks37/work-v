#!/usr/bin/env bash
# ==============================================================================
# Work-V 分布式网络与订阅中枢 · 全环境自适应智能部署引擎 (v2.0)
# 特性：国内/海外镜像自适应、1h1g低配小鸡Swap自适应、BBR加速自适应、NAT端口自适应、防火墙自动放行
# ==============================================================================
set -e

COLOR_RED="\033[31m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_BLUE="\033[34m"
COLOR_CYAN="\033[36m"
COLOR_BOLD="\033[1m"
COLOR_RESET="\033[0m"

DEFAULT_SERVER=""
SERVER="${DEFAULT_SERVER}"
TOKEN=""
ROLE=""
PORT=8080
SAFE_PATH="/safe_entry"
CUSTOM_PORT=""
DOMAIN=""
SETUP_NGINX=0
FORCE_MIRROR=0
DISABLE_SWAP=0
DISABLE_BBR=0

# 通用输入读取器 (完美支持 curl ... | bash 管道交互与无 tty 环境)
read_input() {
    local prompt="$1"
    local var_name="$2"
    local default_val="$3"
    local val=""

    if [ -t 0 ]; then
        read -r -p "$prompt" val
    elif (exec 3< /dev/tty) 2>/dev/null; then
        read -r -p "$prompt" val < /dev/tty
    else
        read -r -p "$prompt" val 2>/dev/null || val=""
    fi

    if [ -z "$val" ] && [ -n "$default_val" ]; then
        val="$default_val"
    fi
    # 用 printf -v 赋值: eval 会把用户输入里的引号/$(...) 当代码执行
    printf -v "$var_name" '%s' "$val"
}

detect_env() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$NAME $VERSION_ID"
    else
        OS_NAME=$(uname -s)
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)   GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        *) echo -e "${COLOR_RED}❌ 不支持的系统架构: $ARCH${COLOR_RESET}"; exit 1 ;;
    esac

    LOCAL_IP=$(curl -s4 --max-time 3 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 3 https://ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
    INT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    IS_NAT=0
    if [[ "$INT_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]] && [ "$INT_IP" != "$LOCAL_IP" ]; then
        IS_NAT=1
    fi

    # 智能探测当前主机网络环境 (国内 vs 海外)
    IS_CHINA=0
    if [ "$FORCE_MIRROR" -eq 1 ] || ! curl -s4 --connect-timeout 2 -I https://github.com &>/dev/null; then
        IS_CHINA=1
    fi
}

detect_installed() {
    HAS_MASTER=0
    HAS_AGENT=0
    if [ -f /etc/systemd/system/work-v-master.service ] || [ -f /opt/work-v-master/work-v-master ]; then
        HAS_MASTER=1
    fi
    if [ -f /etc/systemd/system/work-v-agent.service ] || [ -f /opt/work-v-agent/work-v-agent ]; then
        HAS_AGENT=1
    fi
}

show_header() {
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
    echo -e "       ${COLOR_GREEN}${COLOR_BOLD}Work-V 分布式网络与订阅中枢 · 全环境自适应安装引擎 (v2.0)${COLOR_RESET}        "
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
    echo -e " 系统环境: ${COLOR_YELLOW}${OS_NAME}${COLOR_RESET} | 架构: ${COLOR_YELLOW}${ARCH} (${GO_ARCH})${COLOR_RESET} | 公网 IP: ${COLOR_YELLOW}${LOCAL_IP}${COLOR_RESET}"
    if [ "$IS_NAT" -eq 1 ]; then
        echo -e " 架构特征: ${COLOR_CYAN}⚡ NAT 端口映射机器${COLOR_RESET} (内网 IP: ${INT_IP})"
    else
        echo -e " 架构特征: ${COLOR_GREEN}🌐 独立公网 IP 主机${COLOR_RESET}"
    fi
    if [ "$IS_CHINA" -eq 1 ]; then
        echo -e " 网络链路: ${COLOR_YELLOW}🇨🇳 中国大陆网络环境 (已自动启用 CDN 镜像极速加速)${COLOR_RESET}"
    else
        echo -e " 网络链路: ${COLOR_GREEN}🌍 海外全球高速直连网络${COLOR_RESET}"
    fi
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
}

# 硬件与网络自适应调节器 (低配小鸡优化、BBR启用、系统并发限制)
tune_server_system() {
    echo -e "\n${COLOR_CYAN}🔧 [环境自适应检查与系统性能调优]...${COLOR_RESET}"

    # 1. 低配小鸡 Swap 自适应 (防 OOM 崩溃)
    if [ "$DISABLE_SWAP" -eq 0 ]; then
        local mem_mb=$(free -m 2>/dev/null | awk '/Mem:/ {print $2}')
        local swap_mb=$(free -m 2>/dev/null | awk '/Swap:/ {print $2}')
        if [ -n "$mem_mb" ] && [ "$mem_mb" -lt 1500 ] && [ "$swap_mb" -lt 512 ]; then
            echo -e "💡 ${COLOR_YELLOW}[硬件自适应] 检测到低配小鸡 (物理内存 ${mem_mb}MB < 1.5GB 且无 Swap)，正在自动挂载 1GB 虚拟 Swap 内存，防止 OOM 崩溃...${COLOR_RESET}"
            if [ ! -f /swapfile ]; then
                fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null
                chmod 600 /swapfile
                mkswap /swapfile 2>/dev/null || true
                swapon /swapfile 2>/dev/null || true
                if ! grep -q "/swapfile" /etc/fstab 2>/dev/null; then
                    echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
                fi
                echo -e "✅ ${COLOR_GREEN}1GB Swap 虚拟内存挂载成功！${COLOR_RESET}"
            fi
        fi
    fi

    # 2. 内核网络加速 BBR 自适应
    if [ "$DISABLE_BBR" -eq 0 ]; then
        local current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
        if [ "$current_cc" != "bbr" ]; then
            echo -e "🚀 ${COLOR_YELLOW}[内核自适应] 正在为系统自动开启 TCP BBR 极速拥塞控制算法...${COLOR_RESET}"
            if modprobe tcp_bbr 2>/dev/null; then
                sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
                sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
                echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
                echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
                sysctl -p 2>/dev/null || true
                echo -e "✅ ${COLOR_GREEN}TCP BBR 加速算法已成功激活！${COLOR_RESET}"
            fi
        fi
    fi

    # 3. 高并发文件描述符限制优化
    ulimit -n 1048576 2>/dev/null || true
    if ! grep -q "1048576" /etc/security/limits.conf 2>/dev/null; then
        echo "* soft nofile 1048576" >> /etc/security/limits.conf
        echo "* hard nofile 1048576" >> /etc/security/limits.conf
    fi
}

# 自动放行防火墙端口 (支持 UFW / Firewalld / iptables)
open_firewall_ports() {
    local p="$1"
    [ -z "$p" ] && return 0

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "🛡️ ${COLOR_YELLOW}[防火墙自适应] 检测到 UFW 活跃，正在自动放行端口 ${p}...${COLOR_RESET}"
        ufw allow "${p}/tcp" 2>/dev/null || true
        ufw allow "${p}/udp" 2>/dev/null || true
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        echo -e "🛡️ ${COLOR_YELLOW}[防火墙自适应] 检测到 Firewalld 活跃，正在自动放行端口 ${p}...${COLOR_RESET}"
        firewall-cmd --zone=public --add-port="${p}/tcp" --permanent 2>/dev/null || true
        firewall-cmd --zone=public --add-port="${p}/udp" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || true
    fi
}

# 智能配置 Nginx 反向代理与 WebSocket 升级
configure_nginx() {
    local dom="$1"
    local prt="$2"
    [ -z "$dom" ] && return 0

    local nginx_conf_dir=""
    if [ -d "/etc/nginx/conf.d" ]; then
        nginx_conf_dir="/etc/nginx/conf.d"
    elif [ -d "/www/server/panel/vhost/nginx" ]; then
        nginx_conf_dir="/www/server/panel/vhost/nginx"
    elif [ -d "/etc/nginx/sites-available" ]; then
        nginx_conf_dir="/etc/nginx/sites-available"
    fi

    if [ -z "$nginx_conf_dir" ] && ! command -v nginx &>/dev/null; then
        echo -e "💡 ${COLOR_YELLOW}提示: 未检测到系统 Nginx，已跳过 Nginx 配置文件自动生成。${COLOR_RESET}"
        echo -e "   后续如需配置反代，可将域名反代至 127.0.0.1:${prt} 并开启 WebSocket 升级转发。"
        return 0
    fi

    local do_nginx="Y"
    if [ "$SETUP_NGINX" -ne 1 ]; then
        read_input "检测到当前服务器具备 Nginx，是否自动生成反向代理配置文件？[Y/n]: " do_nginx "Y"
    fi
    if [[ "$do_nginx" =~ ^[nN]$ ]]; then
        return 0
    fi

    [ -z "$nginx_conf_dir" ] && nginx_conf_dir="/etc/nginx/conf.d"
    mkdir -p "$nginx_conf_dir"

    local conf_file="${nginx_conf_dir}/work-v.conf"
    cat > "$conf_file" <<EOF
server {
    listen 80;
    server_name ${dom};

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:${prt};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket 协议升级支持 (长连心跳与下发通道)
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }
}
EOF

    if [ "$nginx_conf_dir" = "/etc/nginx/sites-available" ]; then
        mkdir -p /etc/nginx/sites-enabled
        ln -sf "$conf_file" /etc/nginx/sites-enabled/work-v.conf 2>/dev/null || true
    fi

    open_firewall_ports 80
    open_firewall_ports 443

    if command -v nginx &>/dev/null; then
        if nginx -t &>/dev/null; then
            systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
            echo -e "✅ ${COLOR_GREEN}Nginx 反代配置已就绪并已重载: ${conf_file}${COLOR_RESET}"
            echo -e "💡 ${COLOR_CYAN}若需配置免费 SSL 证书，可执行: certbot --nginx -d ${dom}${COLOR_RESET}"
        else
            echo -e "⚠️ ${COLOR_YELLOW}Nginx 反代配置已生成 (${conf_file})，请检查主配置后执行 nginx -s reload${COLOR_RESET}"
        fi
    else
        echo -e "✅ ${COLOR_GREEN}Nginx 配置文件已就绪: ${conf_file}${COLOR_RESET}"
    fi
}

install_master() {
    echo -e "\n${COLOR_YELLOW}🚀 开始部署【主节点 (Master Hub)】...${COLOR_RESET}"
    tune_server_system
    open_firewall_ports "$PORT"

    INSTALL_DIR="/opt/work-v-master"
    mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$INSTALL_DIR/scripts"

    # 如果未指定域名，且是终端交互环境，询问是否配置外网域名
    if [ -z "$DOMAIN" ]; then
        echo -e "\n${COLOR_CYAN}🌐 [域名与访问方式配置]${COLOR_RESET}"
        echo -e "Work-V 支持两种访问模式："
        echo -e "  1. ${COLOR_GREEN}纯 IP 模式${COLOR_RESET}：无需域名，通过 IP:端口 + 安全入口 直接访问 (适合内网或个人轻量使用)"
        echo -e "  2. ${COLOR_GREEN}域名绑定模式${COLOR_RESET}：绑定自定义域名，可自动生成 Nginx 反向代理配置并支持 SSL"
        read_input "是否需要绑定自定义域名？[y/N]: " use_domain "N"
        if [[ "$use_domain" =~ ^[yY]$ ]]; then
            read_input "请输入您的外网域名 (例如 panel.example.com): " DOMAIN ""
            DOMAIN=$(echo "$DOMAIN" | tr -d ' ' | sed -E 's|^https?://||; s|/$||')
        fi
    fi

    echo -e "📦 准备 Master 二进制运行文件..."
    if [ -f "./work-v-master" ]; then
        cp -f ./work-v-master "$INSTALL_DIR/"
    elif [ -f "./work-v-master-linux" ]; then
        cp -f ./work-v-master-linux "$INSTALL_DIR/work-v-master"
    else
        echo "正在从主控/源拉取预编译 Master 产物: $SERVER/download/master-$GO_ARCH ..."
        curl -fsSL "$SERVER/download/master-$GO_ARCH" -o "$INSTALL_DIR/work-v-master" 2>/dev/null || {
            echo -e "${COLOR_YELLOW}⚠️ 从本地主控直接拉取失败，尝试从备用仓库镜像获取...${COLOR_RESET}"
            curl -fsSL "https://github.com/ooks37/work-v/releases/latest/download/work-v-master-$GO_ARCH" -o "$INSTALL_DIR/work-v-master" 2>/dev/null || true
        }
    fi

    if [ ! -f "$INSTALL_DIR/work-v-master" ]; then
        echo -e "${COLOR_RED}❌ 未能获取到 work-v-master 二进制文件，请确认网络连接或主控分发接口${COLOR_RESET}"
        exit 1
    fi
    chmod +x "$INSTALL_DIR/work-v-master"

    # 安装管理工具
    if [ -f "./scripts/work-v" ]; then
        cp -f ./scripts/work-v "$INSTALL_DIR/scripts/work-v"
        cp -f ./scripts/work-v /usr/local/bin/work-v
    elif [ -f "$INSTALL_DIR/scripts/work-v" ]; then
        cp -f "$INSTALL_DIR/scripts/work-v" /usr/local/bin/work-v
    else
        curl -fsSL "$SERVER/download/work-v" -o /usr/local/bin/work-v 2>/dev/null || true
    fi
    chmod +x /usr/local/bin/work-v 2>/dev/null || true
    ln -sf /usr/local/bin/work-v /usr/local/bin/workv 2>/dev/null || true
    ln -sf /usr/local/bin/work-v /usr/local/bin/bt-v 2>/dev/null || true

    # 构建启动命令
    local exec_cmd="$INSTALL_DIR/work-v-master -port $PORT -db $INSTALL_DIR/data/work-v.db"
    if [ -n "$DOMAIN" ]; then
        exec_cmd="$exec_cmd -domain $DOMAIN"
    fi

    # 注册 systemd 服务
    cat > /etc/systemd/system/work-v-master.service <<EOF
[Unit]
Description=Work-V Master Hub Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$exec_cmd
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # 应用命令行指定的自定义安全入口 (历史实现只解析 --entry 却从未写入主控配置)
    if [ -n "$SAFE_PATH" ] && [ "$SAFE_PATH" != "/safe_entry" ]; then
        if "$INSTALL_DIR/work-v-master" -db "$INSTALL_DIR/data/work-v.db" -set-entry "$SAFE_PATH" >/dev/null 2>&1; then
            echo -e "🔐 已设置自定义安全入口: ${COLOR_GREEN}${SAFE_PATH}${COLOR_RESET}"
        else
            echo -e "${COLOR_YELLOW}⚠️ 自定义安全入口设置失败, 将使用默认值 /safe_entry${COLOR_RESET}"
            SAFE_PATH="/safe_entry"
        fi
    fi

    systemctl daemon-reload
    systemctl enable work-v-master
    systemctl restart work-v-master
    sleep 2

    # 若配置了域名，自动适配或引导 Nginx 反代配置
    if [ -n "$DOMAIN" ]; then
        configure_nginx "$DOMAIN" "$PORT"
    fi

    echo -e "${COLOR_GREEN}================================================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}🎉 Work-V 主控端已成功部署并启动！${COLOR_RESET}"
    echo -e "${COLOR_GREEN}================================================================================${COLOR_RESET}"
    # 读取主控实际生成的安全入口路径 (宝塔风格随机入口, 不再硬编码 /safe_entry)
    ENTRY_PATH=$("$INSTALL_DIR/work-v-master" -db "$INSTALL_DIR/data/work-v.db" -port "$PORT" -entry 2>/dev/null | grep -m1 '安全入口路径' | sed -E 's/.*: *//' | tr -d '\r')
    [ -z "$ENTRY_PATH" ] && ENTRY_PATH="$SAFE_PATH"

    if [ -n "$DOMAIN" ]; then
        echo -e "• 外网访问域名: ${COLOR_CYAN}$DOMAIN${COLOR_RESET}"
        echo -e "• 控制台入口:   ${COLOR_GREEN}https://$DOMAIN$ENTRY_PATH${COLOR_RESET}"
    else
        echo -e "• 访问方式:     ${COLOR_YELLOW}原生 IP + 端口直连${COLOR_RESET}"
        echo -e "• 控制台入口:   ${COLOR_GREEN}http://$LOCAL_IP:$PORT$ENTRY_PATH${COLOR_RESET}"
    fi
    echo -e "• 随机安全入口会写入数据库, 随时可用 ${COLOR_CYAN}work-v default${COLOR_RESET} 查询"
    if [ -x /usr/local/bin/work-v ]; then
        /usr/local/bin/work-v default 2>/dev/null || true
    else
        echo "• 监听端口: $PORT"
        echo "• 管理账号: admin"
        echo "• 默认密码: admin123456"
    fi
    echo -e "• 终端运维命令: ${COLOR_CYAN}work-v${COLOR_RESET} (类似宝塔 bt 指令，支持域名、状态、节点、密码、安全入口管理)"
    echo -e "${COLOR_GREEN}================================================================================${COLOR_RESET}"
}

install_agent() {
    echo -e "\n${COLOR_YELLOW}🚀 开始部署【从节点 / 副节点 (Agent Node)】...${COLOR_RESET}"
    tune_server_system

    if [ -z "$SERVER" ]; then
        local def_srv="$DEFAULT_SERVER"
        if [ -z "$def_srv" ]; then
            if [ -n "$LOCAL_IP" ]; then
                def_srv="http://$LOCAL_IP:$PORT"
            else
                def_srv="http://127.0.0.1:8080"
            fi
        fi
        read_input "请输入主控端地址 [默认 $def_srv]: " SERVER "$def_srv"
    fi
    if [ -z "$TOKEN" ]; then
        read_input "请输入副节点连接令牌 Token (从主控后台复制): " TOKEN ""
    fi

    if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
        echo -e "${COLOR_RED}❌ 主控地址与节点令牌均不能为空！${COLOR_RESET}"
        exit 1
    fi

    SERVER="${SERVER%/}"
    echo -e "  主控地址: ${COLOR_CYAN}$SERVER${COLOR_RESET}"
    # 令牌不回显完整值 (自动部署模式下该输出会写入主控的部署日志/数据库)
    echo -e "  节点令牌: ${COLOR_CYAN}${TOKEN:0:12}***${COLOR_RESET}"

    # NAT 机器模式处理
    # 说明: 端口无法由本脚本改变。节点实际监听端口由主控下发 (默认 2083/tcp, 2053/tcp,
    # 8445/tcp, 8443/udp, 8444/udp), NAT 机器必须自行把这些端口映射到公网。
    # 这里只做"放行 + 提示", 不再假装 --port 能改写节点监听端口。
    if [ -n "$CUSTOM_PORT" ]; then
        echo -e "  外部映射端口: ${COLOR_CYAN}$CUSTOM_PORT${COLOR_RESET} (NAT 机器模式)"
        echo -e "  ${COLOR_YELLOW}提示: 该端口仅用于防火墙放行/记录, 节点监听端口由主控下发。${COLOR_RESET}"
        open_firewall_ports "$CUSTOM_PORT"
    fi
    echo -e "  ${COLOR_CYAN}正在放行节点默认协议端口 (2083/2053/8445 TCP, 8443/8444 UDP)...${COLOR_RESET}"
    for _np in 2083 2053 8445 8443 8444; do
        open_firewall_ports "$_np"
    done

    INSTALL_DIR="/opt/work-v-agent"
    mkdir -p "$INSTALL_DIR"

    echo -e "📦 准备 Agent 二进制运行文件..."
    if [ -f "./work-v-agent" ]; then
        cp -f ./work-v-agent "$INSTALL_DIR/"
    elif [ -f "./work-v-agent-linux" ]; then
        cp -f ./work-v-agent-linux "$INSTALL_DIR/work-v-agent"
    elif [ -f "/opt/work-v-master/work-v-agent" ]; then
        cp -f /opt/work-v-master/work-v-agent "$INSTALL_DIR/work-v-agent"
    else
        echo "正在从主控拉取 prebuilt Agent 二进制: $SERVER/download/agent-$GO_ARCH ..."
        curl -fsSL "$SERVER/download/agent-$GO_ARCH" -o "$INSTALL_DIR/work-v-agent" 2>/dev/null || {
            echo -e "${COLOR_YELLOW}⚠️ 从主控直接拉取失败，尝试通用包...${COLOR_RESET}"
            curl -fsSL "$SERVER/download/work-v-agent" -o "$INSTALL_DIR/work-v-agent" 2>/dev/null || true
        }
    fi

    if [ ! -f "$INSTALL_DIR/work-v-agent" ]; then
        echo -e "${COLOR_RED}❌ 未能获取到 work-v-agent 客户端二进制，请检查主控是否在线${COLOR_RESET}"
        exit 1
    fi
    chmod +x "$INSTALL_DIR/work-v-agent"

    # 检查并自动安装 Sing-box 官方最新核心
    if ! command -v sing-box &> /dev/null && [ ! -f "/usr/local/bin/sing-box" ]; then
        echo -e "⚡ 正在下载安装 Sing-box 官方最新核心..."
        SB_VER="1.13.12"
        SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-${GO_ARCH}.tar.gz"
        SB_MIRROR="https://ghfast.top/${SB_URL}"

        if [ "$IS_CHINA" -eq 1 ]; then
            echo -e "⚡ ${COLOR_CYAN}使用国内加速 CDN 节点下载内核产物...${COLOR_RESET}"
            curl -fsSL --connect-timeout 8 "$SB_MIRROR" -o /tmp/sb.tar.gz 2>/dev/null || \
            curl -fsSL --connect-timeout 8 "$SB_URL" -o /tmp/sb.tar.gz
        else
            curl -fsSL --connect-timeout 8 "$SB_URL" -o /tmp/sb.tar.gz 2>/dev/null || \
            curl -fsSL --connect-timeout 8 "$SB_MIRROR" -o /tmp/sb.tar.gz
        fi

        if [ -f /tmp/sb.tar.gz ]; then
            tar -zxvf /tmp/sb.tar.gz -C /tmp
            mv -f /tmp/sing-box-*/sing-box /usr/local/bin/sing-box 2>/dev/null || true
            chmod +x /usr/local/bin/sing-box 2>/dev/null || true
            rm -rf /tmp/sb* /tmp/sing-box-*
        fi
    fi

    # 写入配置文件
    cat > "$INSTALL_DIR/config.json" <<EOF
{
  "server": "$SERVER",
  "token": "$TOKEN",
  "custom_port": "$CUSTOM_PORT",
  "singbox_path": "/usr/local/bin/sing-box"
}
EOF
    chmod 600 "$INSTALL_DIR/config.json"   # 含令牌, 仅 root 可读

    # 令牌单独存放到 0600 的环境文件, 避免出现在 world-readable 的 systemd 单元里
    mkdir -p /etc/work-v && chmod 700 /etc/work-v
    cat > /etc/work-v/agent.env <<EOF
WORKV_TOKEN=$TOKEN
EOF
    chmod 600 /etc/work-v/agent.env

    # 注册 systemd 服务
    cat > /etc/systemd/system/work-v-agent.service <<EOF
[Unit]
Description=Work-V Agent Node Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=-/etc/work-v/agent.env
ExecStart=$INSTALL_DIR/work-v-agent --server $SERVER --token ${WORKV_TOKEN}
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable work-v-agent
    systemctl restart work-v-agent
    sleep 2

    if systemctl is-active work-v-agent &>/dev/null; then
        echo -e "${COLOR_GREEN}================================================================================${COLOR_RESET}"
        echo -e "${COLOR_GREEN}✅【从节点 Agent】部署成功并已正常运行！${COLOR_RESET}"
        echo -e "已自动通过加密反向通道长连接至主控: ${COLOR_CYAN}$SERVER${COLOR_RESET}"
        echo -e "主控后台将实时展示当前节点的在线状态、呼吸心跳与网络系统指标。"
        echo -e "${COLOR_GREEN}================================================================================${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}❌ Agent 服务启动失败，请检查 journalctl -u work-v-agent -n 30 日志${COLOR_RESET}"
        exit 1
    fi
}

uninstall_all() {
    echo -e "${COLOR_YELLOW}正在卸载 Work-V 服务...${COLOR_RESET}"
    systemctl stop work-v-master 2>/dev/null || true
    systemctl disable work-v-master 2>/dev/null || true
    systemctl stop work-v-agent 2>/dev/null || true
    systemctl disable work-v-agent 2>/dev/null || true
    rm -f /etc/systemd/system/work-v-master.service /etc/systemd/system/work-v-agent.service
    rm -f /usr/local/bin/work-v /usr/local/bin/workv /usr/local/bin/bt-v
    systemctl daemon-reload
    echo -e "${COLOR_GREEN}✅ 服务与守护已移除！数据文件保留在 /opt/work-v-*。${COLOR_RESET}"
}

# 域名与 Nginx 反代配置向导
configure_domain_menu() {
    echo -e "\n${COLOR_CYAN}================================================================================${COLOR_RESET}"
    echo -e "                ${COLOR_GREEN}Work-V 主控外网访问域名与反代管理${COLOR_RESET}                "
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
    echo "当前支持绑定自定义域名（自动生成 Nginx 反代），或输入 none 恢复原生 IP:端口 直连模式。"
    read_input "请输入域名 (例如 panel.example.com，输入 none 或留空清除域名): " new_dom ""
    new_dom=$(echo "$new_dom" | tr -d ' ' | sed -E 's|^https?://||; s|/$||')

    if [ -f "/opt/work-v-master/work-v-master" ]; then
        if [ "$new_dom" = "none" ] || [ "$new_dom" = "clear" ] || [ -z "$new_dom" ]; then
            /opt/work-v-master/work-v-master -domain "none" -db "/opt/work-v-master/data/work-v.db"
            if [ -f "/etc/systemd/system/work-v-master.service" ]; then
                sed -i "s| -domain [^ ]*||g" /etc/systemd/system/work-v-master.service 2>/dev/null || true
                systemctl daemon-reload 2>/dev/null || true
            fi
            systemctl restart work-v-master 2>/dev/null || true
            echo -e "${COLOR_GREEN}✅ 已清除域名绑定，恢复为纯 IP 直连访问模式！${COLOR_RESET}"
        else
            /opt/work-v-master/work-v-master -domain "$new_dom" -db "/opt/work-v-master/data/work-v.db"
            if [ -f "/etc/systemd/system/work-v-master.service" ]; then
                sed -i "s| -domain [^ ]*||g" /etc/systemd/system/work-v-master.service 2>/dev/null || true
                sed -i "s|work-v.db|work-v.db -domain $new_dom|g" /etc/systemd/system/work-v-master.service 2>/dev/null || true
                systemctl daemon-reload 2>/dev/null || true
            fi
            systemctl restart work-v-master 2>/dev/null || true
            configure_nginx "$new_dom" "$PORT"
            echo -e "${COLOR_GREEN}✅ 域名配置已保存并已重启主控服务！${COLOR_RESET}"
        fi
        if [ -x /usr/local/bin/work-v ]; then
            /usr/local/bin/work-v default 2>/dev/null || true
        fi
    else
        echo -e "${COLOR_RED}❌ 未检测到 /opt/work-v-master/work-v-master 二进制${COLOR_RESET}"
    fi
}

# 智能交互向导菜单
interactive_menu() {
    detect_installed
    show_header

    # 1. 已安装主控的处理逻辑
    if [ "$HAS_MASTER" -eq 1 ] && [ "$HAS_AGENT" -eq 0 ]; then
        echo -e " 💡 ${COLOR_GREEN}自动识别当前机器角色: 【主控端 (Master Hub)】${COLOR_RESET}"
        echo -e "    服务状态: ${COLOR_GREEN}$(systemctl is-active work-v-master 2>/dev/null || echo '未运行')${COLOR_RESET}"
        echo -e "${COLOR_CYAN}--------------------------------------------------------------------------------${COLOR_RESET}"
        echo -e " 请选择操作选项："
        echo -e "   [1] 升级 / 覆盖安装【主控端 (Master Hub)】"
        echo -e "   [2] 重启 主控端服务"
        echo -e "   [3] 查看 主控端实时运行日志"
        echo -e "   [4] 查看 管理凭据与安全入口地址"
        echo -e "   [5] 绑定 / 修改外网自定义域名与 Nginx 反代"
        echo -e "   [6] 一键开启 TCP BBR 极速拥塞控制"
        echo -e "   [7] 卸载 主控端服务"
        echo -e "   [0] 退出"
        echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
        read_input "请输入编号 [默认 1]: " choice "1"
        case "$choice" in
            1) install_master ;;
            2) systemctl restart work-v-master; echo -e "${COLOR_GREEN}✅ 已重启！${COLOR_RESET}" ;;
            3) journalctl -u work-v-master -f -n 40 ;;
            4) /usr/local/bin/work-v default 2>/dev/null || echo "请在浏览器访问: $SAFE_PATH" ;;
            5) configure_domain_menu ;;
            6) tune_server_system ;;
            7) uninstall_all ;;
            0) exit 0 ;;
            *) echo -e "${COLOR_RED}无效输入${COLOR_RESET}" ;;
        esac
        return
    fi

    # 2. 已安装从节点的处理逻辑
    if [ "$HAS_AGENT" -eq 1 ] && [ "$HAS_MASTER" -eq 0 ]; then
        echo -e " 💡 ${COLOR_GREEN}自动识别当前机器角色: 【从节点 (Agent Node)】${COLOR_RESET}"
        echo -e "    服务状态: ${COLOR_GREEN}$(systemctl is-active work-v-agent 2>/dev/null || echo '未运行')${COLOR_RESET}"
        echo -e "${COLOR_CYAN}--------------------------------------------------------------------------------${COLOR_RESET}"
        echo -e " 请选择操作选项："
        echo -e "   [1] 升级 / 重新安装【从节点 (Agent Node)】"
        echo -e "   [2] 重启 从节点服务"
        echo -e "   [3] 查看 从节点实时运行日志"
        echo -e "   [4] 一键开启 TCP BBR 极速拥塞控制"
        echo -e "   [5] 卸载 从节点服务"
        echo -e "   [0] 退出"
        echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"
        read_input "请输入编号 [默认 1]: " choice "1"
        case "$choice" in
            1) install_agent ;;
            2) systemctl restart work-v-agent; echo -e "${COLOR_GREEN}✅ 已重启！${COLOR_RESET}" ;;
            3) journalctl -u work-v-agent -f -n 40 ;;
            4) tune_server_system ;;
            5) uninstall_all ;;
            0) exit 0 ;;
            *) echo -e "${COLOR_RED}无效输入${COLOR_RESET}" ;;
        esac
        return
    fi

    # 3. 全新机器：智能网络探测推断
    SERVER_HOST=$(echo "$SERVER" | awk -F[/:] '{print $4}')
    SERVER_IP=""
    [ -n "$SERVER_HOST" ] && SERVER_IP=$(getent ahostsv4 "$SERVER_HOST" 2>/dev/null | awk '{print $1}' | head -n 1 || true)
    RECOMMENDED_ROLE="master"
    DEFAULT_NUM="1"

    if [ -n "$SERVER_IP" ] && [ -n "$LOCAL_IP" ] && [ "$LOCAL_IP" != "$SERVER_IP" ]; then
        RECOMMENDED_ROLE="agent"
        DEFAULT_NUM="2"
        echo -e " 💡 ${COLOR_GREEN}智能推断: 本机为外部从属服务器 (IP: $LOCAL_IP，主控 IP: $SERVER_IP)${COLOR_RESET}"
        echo -e "    推荐安装角色: ${COLOR_BOLD}${COLOR_GREEN}【从属节点 (Agent Node)】${COLOR_RESET}"
    else
        echo -e " 💡 ${COLOR_GREEN}智能推断: 本机主机环境 (公网 IP: ${LOCAL_IP:-检测中})${COLOR_RESET}"
        echo -e "    推荐安装角色: ${COLOR_BOLD}${COLOR_GREEN}【主节点 (Master Hub)】${COLOR_RESET}"
    fi
    echo -e "${COLOR_CYAN}--------------------------------------------------------------------------------${COLOR_RESET}"

    echo -e " 请选择安装角色："
    if [ "$DEFAULT_NUM" = "1" ]; then
        echo -e "   [1] 部署【主节点 (Master Hub)】 ${COLOR_YELLOW}(推荐)${COLOR_RESET}"
        echo -e "   [2] 部署【从节点 (Agent Node)】"
    else
        echo -e "   [1] 部署【主节点 (Master Hub)】"
        echo -e "   [2] 部署【从节点 (Agent Node)】 ${COLOR_YELLOW}(推荐)${COLOR_RESET}"
    fi
    echo -e "   [3] 卸载清理"
    echo -e "   [0] 退出脚本"
    echo -e "${COLOR_CYAN}================================================================================${COLOR_RESET}"

    read_input "请输入编号 [默认 $DEFAULT_NUM]: " choice "$DEFAULT_NUM"
    case "$choice" in
        1) install_master ;;
        2) install_agent ;;
        3) uninstall_all ;;
        0) exit 0 ;;
        *) echo -e "${COLOR_RED}无效输入${COLOR_RESET}" ;;
    esac
}

# ==============================================================================
# 脚本主执行入口 (参数自适应 & 环境自检测)
# ==============================================================================
# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --master|--hub|-m)
            ROLE="master"
            shift ;;
        --agent|--node|-a)
            ROLE="agent"
            shift ;;
        --token|-t)
            TOKEN="$2"
            ROLE="agent"
            shift 2 ;;
        --domain|-d)
            DOMAIN="$2"
            shift 2 ;;
        --nginx)
            SETUP_NGINX=1
            shift ;;
        --server|-s)
            SERVER="$2"
            shift 2 ;;
        --port|-p)
            CUSTOM_PORT="$2"
            PORT="$2"
            shift 2 ;;
        --mirror|--cn)
            FORCE_MIRROR=1
            shift ;;
        --no-swap)
            DISABLE_SWAP=1
            shift ;;
        --no-bbr)
            DISABLE_BBR=1
            shift ;;
        --entry)
            SAFE_PATH="$2"
            shift 2 ;;
        --uninstall|-u)
            ROLE="uninstall"
            shift ;;
        --help|-h)
            echo "Work-V 全环境自适应安装引擎 (v2.0)"
            echo "用法: curl -fsSL <URL>/install.sh | bash -s -- [选项]"
            echo ""
            echo "模式选项:"
            echo "  --master, -m          自动部署为 主控端 (Master Hub)"
            echo "  --agent, -a           自动部署为 从属节点 (Agent Node)"
            echo "  --token, -t <TOKEN>   指定从节点接入凭证并自动纳管"
            echo "  --uninstall, -u       卸载清理本机 Work-V 服务"
            echo ""
            echo "域名与网络选项:"
            echo "  --domain, -d <DOMAIN> 指定主控外网访问域名 (可选，留空则使用纯 IP 访问)"
            echo "  --nginx               自动配置 Nginx 反向代理与 WebSocket 转发"
            echo "  --server, -s <URL>    指定主控端地址 (从节点安装时使用)"
            echo "  --port, -p <PORT>     主控: 监听端口 (默认 8080); 从节点: NAT 映射端口(仅放行/记录)"
            echo "                        节点实际监听端口由主控下发(2083/2053/8445 TCP, 8443/8444 UDP)"
            echo "  --entry <PATH>        指定主控安全入口路径 (默认: /safe_entry)"
            echo ""
            echo "性能与加速选项:"
            echo "  --mirror, --cn        强制使用国内 CDN 镜像加速下载"
            echo "  --no-swap             禁用低内存 VPS 自动 Swap 挂载"
            echo "  --no-bbr              禁用 TCP BBR 极速拥塞控制算法"
            echo "  --help, -h            显示本帮助信息"
            exit 0
            ;;
        *)
            shift ;;
    esac
done

detect_env
detect_installed

# 根据角色参数自动执行，无需二次确认
if [ "$ROLE" = "master" ]; then
    show_header
    echo -e "${COLOR_GREEN}🎯 命令行参数命中: 自动识别为【主节点 (Master Hub)】部署模式${COLOR_RESET}"
    install_master
    exit 0
elif [ "$ROLE" = "agent" ]; then
    show_header
    echo -e "${COLOR_GREEN}🎯 命令行参数命中: 自动识别为【副节点 (Agent Node)】纳管模式${COLOR_RESET}"
    install_agent
    exit 0
elif [ "$ROLE" = "uninstall" ]; then
    uninstall_all
    exit 0
fi

# 若未指定任何参数，进入智能向导菜单 (自动探测现有组件与硬件角色)
interactive_menu
