# No-FTP-XXE
如何利用下面代码中的XXE外带多行文件，JDK>=8u131，服务部署在Windows上

代码如下
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
                    System.err.println("配置处理错误: " + e.getMessage());
                }
            });
            response.put("status", "success");
            response.put("message", "配置更新请求已提交，正在后台处理");
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "配置更新请求失败");
            response.put("error", "系统内部错误"); 
            
            return ResponseEntity.internalServerError().body(response);
        }
    }
    

    private void processConfigDocument(Document document) {
        try {
            Element root = document.getRootElement();
            List<Element> settings = root.elements("setting");
            for (Element setting : settings) {
                String name = setting.attributeValue("name");
                String value = setting.getTextTrim();
                System.out.println("更新配置: " + name + " = " + value);
            }
            
            System.out.println("配置处理完成，共处理 " + settings.size() + " 个配置项");
            
        } catch (Exception e) {
            System.err.println("配置处理异常: " + e.getMessage());
        }
    }
}
```

