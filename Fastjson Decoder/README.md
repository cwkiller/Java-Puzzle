# 前言
Java Puzzle 系列第三题，本题为`lu2ker`师傅投稿。

# Fastjson Decoder



### 题目说明
目标服务器运行着一个`Java Web`应用，使用了存在漏洞的`Fastjson`版本。

你需要突破重重限制，最终获取到系统权限。

请勿进行扫描爆破等操作

### 环境搭建

本地环境搭建：

下载CVE-2022-25845-In-Spring-1.0-SNAPSHOT.jar、Dockerfile

构建image

```shell
docker build -t fj_test .
```

启动容器

```shell
docker run -d -p 8078:8078 <image_id>
```

请求http://127.0.0.1:8078/json

远程访问地址：

*http://119.45.93.131:8078/*
远程环境在某些情况下会自动重启恢复初始状态。
