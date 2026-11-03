# 构建与发布

## 软件包格式

项目没有需要交叉编译的原生模块。后端为 Lua / Shell，前端为 LuCI JavaScript / CSS / HTML。IPK 使用本地确定性构建器；APK 使用 OpenWrt 官方 ImageBuilder 内的 apk v3 主机工具。两者的业务文件、权限与维护脚本来源相同。

APK 构建格式参考 [OpenWrt package-pack.mk](https://github.com/openwrt/openwrt/blob/openwrt-25.12/include/package-pack.mk)。工具固定为 [OpenWrt ImageBuilder 25.12.2 x86_64](https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/)，下载后校验固定 SHA256，只提取主机构建工具；不会下载或运行目标路由器固件。使用 x86_64 主机工具不限制生成包安装设备的 CPU 架构。

| 输出 | 版本示例 | 架构字段 |
| --- | --- | --- |
| IPK | `netquota_0.5.1_all.ipk` | `all` |
| APKv3 | `netquota-0.5.1-r1.apk` | `noarch` |

构建 APK 不等于完成新版 OpenWrt / fw4 的运行适配。当前设备验收仍限于 README 中列出的固件。

## GitHub Actions

工作流：`.github/workflows/build-release.yml`。

1. 校验后端、两个 Makefile 和构建器版本一致；版本 tag 必须为 `v<源码版本>`。
2. 运行 Python 测试及 JS 语法检查。
3. 并行构建两种格式。APK 在 fakeroot 环境生成，确保文件属主为 root:root；由官方工具校验完整性、解包后逐个比对 IPK 的业务文件及权限。
4. 两种格式均成功后下载四个产物，检查数量与版本，生成 SHA256SUMS 与 BUILDINFO.json。
5. PR 只保存构建产物；main、手动运行发布预览版；版本 tag 发布正式版。只有发布 job 获取 `contents: write` 权限。

包为无签名本地安装包。SHA256SUMS 可校验下载完整性，不等同于独立的发布者签名；APK 设备安装需允许未签名包。CI 不注入路由器密码或证书。

## 发布正式版

将两个包 Makefile、`tools/build_ipk.py` 的版本、`netquota/files/usr/lib/lua/netquota/util.lua` 运行版本及门户资源版本统一更新，完成测试并提交到 main。然后推送对应标签，例如：

```sh
git tag v0.5.1
git push origin v0.5.1
```

不要将不同源码重用同一个正式版本标签。修订源码应增加版本号再发布。构建产物保存在 Release / Actions，不进入 Git 源码。

## 本地构建

IPK 在 Windows、Linux 和 macOS 上使用 Python 3 标准库构建：

```sh
python tools/build_ipk.py
```

APK 需要 Linux x86_64、Python 3.12+、tar、zstd 与 fakeroot。默认工具下载缓存为 `.build/openwrt-apk/`：

```sh
sudo apt-get install fakeroot zstd
python tools/fetch_apk_tool.py
# 将下载器打印的路径代入，或设置 APK_TOOL 环境变量
fakeroot python tools/build_apk.py --apk-tool /path/to/staging_dir/host/bin/apk
fakeroot python tools/verify_apk.py --apk-tool /path/to/staging_dir/host/bin/apk
```

修改维护脚本时，应同步 `tools/packaging/scripts/` 与 Makefile 内的标准 OpenWrt 包定义。APK 包装同一组维护脚本，分别处理安装、升级前后与卸载前后；升级前建立守卫，保留当前接管设置与账本。卸载仍要求先停止接管。

## 验证

```sh
python -m unittest discover -s tests -p 'test_*.py'
```

Python 测试包含源码白名单、包权限、配置保留与 APK 生命周期。Windows 没有 POSIX shell 时，Shell hook 执行测试跳过；GitHub 的 Linux runner 会实际执行。

开发者实机测试可使用 `tools/router.py` 与 `tools/test_on_router.py`。工作站需安装 paramiko，密码通过环境变量 `NETQUOTA_SSH_PASSWORD` 或交互输入，设备 SSH 主机密钥必须校验。

```sh
python tools/test_on_router.py --fingerprint <设备SSH指纹>
```

`--network`、`tests/router-guest-client.sh` 等夹具会创建临时网络，必须在专用测试设备上明确运行并清理。浏览器脚本使用真实 LuCI / RPC，需要先登录管理页面。CI 不连接路由器，也不将静态构建成功当成设备验收。

原始设备转储、本机测试状态与生成包保留在被 Git 忽略的目录中；公开的兼容性结论见 `docs/compatibility/` 与测试修订记录。
