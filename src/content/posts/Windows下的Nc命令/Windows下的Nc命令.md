---
title: Windows下的Nc命令
published: 2026-08-09
description: ''
image: ''
tags: [Pwn]
category: ''
draft: false

---

不同于liunx，windows没有原生的nc命令，本文将介绍如何在windows环境下安装nc命令

在这个网站(https://eternallybored.org/misc/netcat/)
![](Windows下的Nc命令.assets/file-20260809111017239.png)
点击这个netcat 1.12即可下载
下载完成后，解压缩这个压缩包，将其解压至例如D盘等其他盘符中，且包含的文件夹中，最好不要有中文名
![](Windows下的Nc命令.assets/file-20260809111129204.png)
选中这个路径，并复制
![](Windows下的Nc命令.assets/file-20260809111312475.png)
使用任务栏的搜索框，搜索环境变量，并点击打开
![](Windows下的Nc命令.assets/file-20260809111358252.png)
从左到右的顺序，依次点击环境变量-Path-新建
![](Windows下的Nc命令.assets/file-20260809111708968.png)
会在最后一栏新建一个框，我们把将复制的路径粘贴进去
![](Windows下的Nc命令.assets/file-20260809111840273.png)最后依次确认退出即可
在这之后，鼠标任意右键文件夹或是桌面
![](Windows下的Nc命令.assets/file-20260809112017625.png)
点击在终端中打开
![](Windows下的Nc命令.assets/file-20260809112041833.png)
输入nc -h，如果与上图一样的输出，说明nc已经添加到环境变量了
之后即可正常使用nc命令