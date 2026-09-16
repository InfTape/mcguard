# MCGuard: 纯用户态独立 Minecraft 安全审计与网络防护系统 (MCGuard.exe)

> **100% 独立单文件 EXE，零自研内核驱动，免 Java Agent，零配置开箱即用。**  
> 基于 Windows 原生 **WFP (Windows 过滤平台) ALE 用户态 API**、**ETW (内核事件跟踪)** 与 **Native 模块载入审计**，实现对 Minecraft 的网络白名单硬核阻断与文件/底层 I/O 穿透审计。

---

## 核心架构与原理

```
                     +---------------------------------------+
                     |         Minecraft javaw.exe           |
                     |       (无须添加任何 -javaagent)        |
                     +-------------------+-------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                [Java 业务层]                       [JNI Native 模块]
            Mod 逻辑 / 游戏网络连接                第三方 native_mod.dll
                       |                                   |
                       +-----------------+-----------------+
                                         |
                                         v (系统底层 I/O / Winsock)
             =========================================================
                           MCGuard.exe (纯用户态独立程序)
             =========================================================
                 |                       |                       |
                 v                       v                       v
    [网络层: 用户态 WFP ALE]     [存储层: ETW 内核审计]    [模块层: DLL 载入追踪]
     - FwpmEngineOpen0           - Kernel-File 提供者      - Toolhelp32 模块快照
     - 动态会话 (异常自动销毁)   - 穿透 Java 抽象层        - 区分 JRE/Win32/Mod DLL
     - 白名单目标 -> ALLOW       - 捕获 CreateFile/Read    - 侦测临时目录释放的
     - 其余全部 -> 内核硬阻断    - 敏感文件 -> [ALERT]       可疑 DLL -> [ALERT]
       (返回 WSAEACCES 10013)
```

---

## 功能与能力矩阵

| 防护 / 审计维度 | 传统纯 Java 方案 | 传统驱动方案 | MCGuard.exe (本项目) |
| :--- | :---: | :---: | :---: |
| **安装与配置成本** | 需配置 `-javaagent` | 需签名证书/测试模式/蓝屏风险 | **极简：直接双击或运行单个 EXE** |
| **驱动开发/签名门槛** | 无驱动 | 极高 (WDK/EV证书/微软认证) | **零驱动：纯用户态 Win32 API** |
| **Native 网络强制阻断** | ❌ 无法阻断 | ✅ | **✅ (WFP ALE 用户态规则，内核直接拒绝)** |
| **Native DLL 文件窃取审计**| ❌ 无法感知 | ✅ | **✅ (ETW 内核 I/O 穿透记录)** |
| **第三方原生模块预警** | ❌ | ⚠️ 需注册回调 | **✅ (自动快照分析非 JRE 动态链接库)** |
| **敏感凭证防盗告警** | ❌ | ✅ | **✅ (实时告警 .ssh, Cookies, Token 等访问)** |
| **崩溃网络自愈性** | 良好 | 极差 (可能全盘死机) | **完美 (FWPM_SESSION_FLAG_DYNAMIC 自动回滚)** |

---

## 快速开始

### 1. 编译构建
本项目仅依赖 MSVC C++ 编译器（无须安装 JDK，无须配置 Java 环境）：
```cmd
build.bat
```
执行后即在根目录生成单文件原生二进制制品：
- **`MCGuard.exe`** (原生 Win32 C++ 独立程序)
- **`config\mcguard.json`** (默认策略配置文件)

### 2. 运行内置演示 (Demo)
一键模拟 Minecraft 启动、网络放行、未授权 Native 连接阻断、可疑 DLL 加载与敏感文件访问告警：
```cmd
MCGuard.exe demo
```

终端实时输出 ANSI 彩色审计表：
```
========================================================================================
             MCGuard - Standalone Pure User-Mode Minecraft Sandbox Auditor              
     [WFP ALE Engine: Active] [ETW Kernel I/O: Active] [Native Module Audit: Active]    
========================================================================================
TIME       PID     TYPE         TARGET                               ACTION   SOURCE
----------------------------------------------------------------------------------------
13:22:48   18432   TCP_OUT      127.0.0.1:25565                       ALLOW   Minecraft Network
13:22:48   18432   FILE_WRITE   C:\Users\Admin\.minecraft\options...  AUDIT   Minecraft Game Data
13:22:48   18432   DLL_LOAD     native_stealer.dll                    ALERT   Third-Party Native DLL
13:22:49   18432   TCP_OUT      104.18.1.2:443                        BLOCK   Native/JNI (WFP Blocked)
13:22:49   18432   FILE_READ    C:\Users\Admin\.ssh\id_rsa            ALERT   Suspicious File Access
13:22:50   18432   FILE_WRITE   C:\Users\Admin\.minecraft\logs\la...  AUDIT   Minecraft Logs
```

### 3. 监控实际 Minecraft 游戏 (Watch 模式)
在任何启动器（Prism Launcher、Modrinth、CurseForge、官方启动器）启动游戏即可，**游戏端无须做任何改动**：

```cmd
# 以管理员权限启动监控 (推荐)
MCGuard.exe watch

# 或使用 --elevate 自动拉起 Windows UAC 提权：
MCGuard.exe watch --elevate
```

当 Minecraft (`javaw.exe`) 启动时，`MCGuard.exe` 会：
1. 自动捕获进程 PID 与完整二进制路径。
2. 将 WFP ALE 出站规则动态附加至该 `javaw.exe`：仅放行白名单端口/IP，其余所有出站网络无论来自 Java 还是 native DLL 均被内核直接阻断。
3. 挂载 ETW 内核跟踪，审计所有文件与网络读写并写入 `mcguard_audit.jsonl`。
4. 游戏退出时，Windows 自动注销所有防火墙规则，绝不残留。

### 4. 自定义网络白名单
允许游戏连接指定的目标服务器（IP 与端口）：
```cmd
MCGuard.exe watch --whitelist 1.2.3.4:25565 --whitelist 114.114.114.114:53
```

---

## 配置文件说明 (`config/mcguard.json`)

```json
{
  "network": {
    "default_policy": "BLOCK",
    "allow_localhost": true,
    "allow_dns": true,
    "allow_mojang_auth": true,
    "whitelist": [
      {
        "description": "Target Minecraft Server",
        "ip": "1.2.3.4",
        "port": 25565,
        "protocol": "TCP"
      }
    ]
  },
  "file_audit": {
    "enabled": true,
    "sensitive_patterns": [
      ".ssh", "id_rsa", "servers.dat", "launcher_profiles.json",
      "Cookies", "Login Data", "Local State", "tokens.json", "Discord"
    ]
  },
  "logging": {
    "jsonl_output": "mcguard_audit.jsonl"
  }
}
```
