# IPK / APK 构建与 GitHub Release 实施计划

**目标：** 发布完整项目源码、实机图文 README，并自动构建两种 OpenWrt 包格式。

**方案：** 项目全部为 Lua、Shell、JS 和静态资源，无需为 CPU 架构重复编译。IPK 沿用已在 GL-MT3000 安装验证的确定性构建器；APK 复用相同的受限文件清单，由固定版本 OpenWrt ImageBuilder 内的官方 apk v3 工具生成 noarch 包。构建格式与设备运行兼容性分开验收。

**工具：** Python 3、OpenWrt apk mkpkg、GitHub Actions、GitHub CLI、Playwright。

1. 审核发布文件清单。保留源码、完整构建脚本、测试与相关文档；生成包只进入 Release。原始设备转储、本地测试状态、凭据不进入公开提交。本地历史保留，空远程仓库使用清理后内容的首次提交。
2. 增加 `tools/build_apk.py`、校验过 SHA256 的官方打包工具下载器、包内容和生命周期测试。复用现有 IPK 文件许可范围、执行权限和维护脚本，处理 APK 独立的安装/升级/删除 hook 以及配置备份元数据。
3. 增加 Actions：Python/JS 检查、IPK/APK 并行构建、真实工具校验、汇总 SHA256 与来源信息，全部成功后上传 Release。PR 仅验证；main/手动构建发布预览版，版本 tag 发布正式版。发布写权限仅授予发布 job。
4. 更新 README、构建说明与 GPL-2.0-only 许可证。使用真实路由器截图，写清图形化部署、HTTP/HTTPS、GL 固件前提、APK 未经实机验证及已知边界。
5. 按指定的临时提交身份提交并推送。观察实际 Actions，修复失败直到构建、包校验和 Release 附件完整；确认提交未遗漏后交付仓库、运行记录和下载链接。
