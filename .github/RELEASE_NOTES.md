NetQuota：GL.iNet / OpenWrt 本地账号认证与共享月度流量配额。

本版新增 **全局流量计费倍率**：在 **结算设置 → 流量计费** 设置 1.00–5.00 倍，默认 1.00。倍率修改仅影响后续流量，实际流量与计费用量分别保留，内核按换算后的共享额度断网。

升级会将账本迁移至 schema v2，保留原有账号、用量与结算日期；降级需要恢复升级前备份。升级后请按 **Ctrl+F5** 刷新管理页，避免旧版浏览器缓存与新版页面混用。

| 设备包管理器 | 安装文件 |
| --- | --- |
| opkg | `netquota_*_all.ipk` 和 `luci-app-netquota_*_all.ipk` |
| apk v3 | `netquota-*-r1.apk` 和 `luci-app-netquota-*-r1.apk` |

请安装同一 Release 中的后端和 LuCI 两个包，先后端、后界面。新安装默认 HTTP、接管关闭；进入 **服务 → NetQuota → 接管设置** 完成图形化配置。

- 已实测：GL-MT3000 原厂 GL.iNet 4.11.0，opkg / fw3。
- MT6000、其他固件和 APK 设备运行仍需单独验证；生成 APK 不代表完成新版 OpenWrt 防火墙兼容性验收。
- APK 是 OpenWrt APKv3 无签名本地包，安装时需选择允许未签名包。不要作为 Android 应用安装。
- 配置 HTTPS 证书后可启用 HTTPS；HTTP 不提供认证凭据的传输加密。

使用步骤与截图见 [README](https://github.com/XIAOZHAOXSXH/luci-app-netquota#readme)。`SHA256SUMS` 用于校验文件，`BUILDINFO.json` 记录源码提交、构建记录与产物摘要。
