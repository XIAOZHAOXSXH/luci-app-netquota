# 可选 HTTPS 与默认 HTTP

用户明确要求：新安装默认 HTTP，免证书即可认证；保留 HTTPS，配置证书成功后切换到 HTTPS。

1. 增加 portal_mode=http|https；统一 URL、监听、Origin、Cookie 和就绪检查。HTTP 使用独立 Cookie 名，不与旧 Secure Cookie 冲突；HTTPS 保留 Secure。
2. 新安装默认 HTTP。旧版无 portal_mode 的配置在升级时写入 https，避免静默降级；本机再按用户要求通过页面显式切至 HTTP。
3. 接管设置增加模式选择。HTTP 不要求证书，HTTPS 才显示证书为必要检查；成功生成/导入证书自动选 HTTPS，原有证书可保留并显式切回 HTTP。
4. 协议切换撤销旧门户及网络会话，保留账户、账本和用量；来源检查、CSRF、限流继续执行。HTTP 模式准确显示无传输加密。
5. 验证默认无证书 HTTP、HTTPS 回归、两模式 Cookie 隔离、切换旧会话失效、真实浏览器 HTTP 登录与计量，及 GUI 全流程。
