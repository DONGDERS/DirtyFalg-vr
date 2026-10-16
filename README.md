# DirtyFrag（vivo/iQOO 适配版）

基于 [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)（CVE-2026-43284）与 [mitschud/DirtyFrag](https://github.com/mitschud/DirtyFrag) 的 **vivo / iQOO 免解锁适配分支**。

利用内核 ESP 页缓存写入原语（CVE-2026-43284）在 **不解锁 BootLoader、不刷自定义内核** 的前提下加载内核模块并获取 root。已在 iQOO Z10 Turbo（vivo V2452A / mt6899 / Android 15 / 内核 6.6）上验证。

> [!IMPORTANT]
> Root 是**临时的**。重启后内核模块、`su` 与已加载的模块全部消失，设备回到干净的未 root 状态——这也是出错时最稳妥的恢复路径。

## 安装

1. 从 [Releases](https://github.com/DONGDERS/DirtyFrag/releases/latest) 下载安装 APK。
2. 安装一个**自带 `libksud.so`** 的 SU 管理器：
   - [KernelSU](https://github.com/tiann/KernelSU/releases/latest)
   - [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)
   - [KowSU](https://github.com/KOWX712/KernelSU/releases/latest)
   - [BakaSU](https://github.com/Baka-SU/BakaSU/releases/latest)
3. 打开 DirtyFrag，在 **SU Manager** 卡片里选中你的管理器，按 **Run exploit**。

## 特性

- **vivo / iQOO 免解锁 root**（含 vivo 的 vr 内核防护拆除，见下）
- 内置 8 个 KMI 的预编译内核模块：`android12-5.10` ~ `android17-6.18`，按设备内核自动匹配
- **W1c 偏移卡（去除 Vr）**：针对 vivo 的 vr 防护内核模块，支持
  - 从 OTA 升级链接 / boot.img 自动解析 `sys_exit` 函数表偏移（vrext 引擎）
  - 手动输入偏移
- **KernelSU Modules** 开/关（无需 root 即可生效，模块崩溃时的逃生通道）
- 运行日志分级展示，一键保存到 Downloads
- 故障取证自动化：运行快照自动写入公共目录，可选常驻内核日志跟随器（逐条落盘），复现崩溃不再依赖手动抓 logcat
- Autorun / Auto reboot（继承上游，见 FAQ）

## 常见问题

**Q：日志提示补丁失败 / 设备不受影响**

A：无解。内核太新、厂商已回移植官方缓解、或命中误打误撞的缓解（常见于 6.1 内核）。

**Q：日志显示 SUCCESS 但没有 root**

A：检查 SU 管理器是否为最新 release 且自带 `libksud.so`；重装 DirtyFrag 会更换 Android UID，需要在管理器里重新授权。

**Q：进度条一直 0%**

A：这是日志标记映射，不是漏洞失败。运行窗口 70 秒，不要因为"慢"就重跑，守护进程可能还在工作。

**Q：怎么干净地移除 root？**

A：用应用内的 **Remove KSU/KSUD** 入口。不要在 DirtyFrag 流程旁边手动执行 `ksud uninstall`——它会尝试恢复一个从未生成过的 boot 备份，可能直接重启设备。

## 工作原理

Android 内核会把 AES-CBC ESP 解密结果直接写进处于 `splice()` 状态文件的页缓存。构造 `IV = AES_ECB_DEC(key, 当前内容) XOR 目标内容`，即可对内存映射共享库中任意 16 字节对齐的块做无写权限、无写时复制的覆写。

利用链：

1. **IpSec transform** —— 通过 `IpSecManager` 分配 `UdpEncapsulationSocket` + SPI，构造 AES-CBC/HMAC-SHA256 ESP transform。
2. **splicehelper → crash_dump64** —— 用 CBC 原语把 splicehelper 写入 `crash_dump64` 的页缓存；`crash_dump` SELinux 域可读 `vendor_file`，是越权的桥。
3. **dfroot.ko → vendor_file** —— 内核模块经该桥写入 `vendor_file` 标签的文件。
4. **libc++ 钩子**（init 进程触发，uid=0, tid=1）—— `std::ostream::sentry::sentry()` 处的 shellcode，检查 uid/tid 后创建 `/dev/df` 一次性互斥，防止重入，再在 `vendor_modprobe` 域 exec `insmod`。
5. **dfroot.ko init** —— SELinux 置 permissive（有 DEFEX 时经 kprobes 绕过），随后 `call_usermodehelper` 启动引导。
6. **bootstrap** —— 读取应用设备侧配置、继承 zygote 环境、分区回只读、按需停用模块，最后拉起所选 SU 管理器的守护进程。
7. **vivo W1c** —— 针对带 vr 防护的 vivo 内核，模块在引导前按配置偏移拆除 vr 的 sys_exit 探针，避免装载后报复性重启。

## 构建

```sh
JAVA_HOME="<Android Studio jbr>" ./gradlew assembleRelease
```

产物在 `app/build/outputs/apk/release/dirtyfrag.apk`。

内核模块（`app/src/main/jni/ko/`）由本仓库 `Build` workflow 的 `LKMs / <kmi>` 任务从 `lkm/dfroot.c` 现编，改动该文件后需重跑 workflow 并回填产物。

## Credits

- 上游项目与漏洞利用链：https://github.com/diabl0w/DFRoot
- 原始 PoC 与部分代码：https://github.com/lsposed/lspromise
- SELinux permissive 内核模块与部分代码：https://github.com/polygraphene/DFReroot
- 无特权 XFRM socket 方法：https://github.com/combeng6th/DirtyInit
- Samsung 适配参考：https://github.com/mitschud/DirtyFrag
