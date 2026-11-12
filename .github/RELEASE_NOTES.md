NetQuota：GL.iNet / OpenWrt 本地账号认证与共享月度流量配额。

本版改进流量展示：**总览、账号管理、流量统计**并列展示本周期实际总量与计费总量；账号列表以计费用量为主，并附实际用量。总量为所有账号各自当前周期的账本合计，不按当前倍率重算历史用量。

访客门户仅展示已用流量、剩余额度与进度，已用值与后台计费用量一致；倍率及实际用量对照仅对管理员开放，访客接口不再返回这些管理字段。计费、断网和结算逻辑保持不变。

从 0.6.0 升级无需迁移账本；更早版本升级会迁移至 schema v2，保留原有账号、用量与结算日期，降级至旧 schema 需要恢复备份。升级后请按 **Ctrl+F5** 刷新管理页，避免旧版浏览器缓存与新版页面混用。

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
