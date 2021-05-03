# Android Https Test App

本仓库包含一个app:com.example.httpstest, 该app用作https证书校验和证书绑定的验证, 以及对其及进行hook解除证书验证和证书绑定的demo

## 目录结构

- certs 存储证书 域名www.test.com

- https_server.py 启动用于双向认证的https服务器
