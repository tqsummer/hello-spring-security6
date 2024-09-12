package com.study.hello.springcloud.security.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Enumeration;

/**
 * @author fangxiangqian
 */
@RestController
@RequestMapping("/stock")
public class TestMessageController {
    @Value("${server.port}")
    private Integer port;

    @RequestMapping("/deduct")
    public String deduct(HttpServletRequest request, HttpServletResponse response) {
        Enumeration<String> enumerate = request.getHeaderNames();
        while (enumerate.hasMoreElements()) {
            String key = enumerate.nextElement();
            System.out.println(key + ":" + request.getHeader(key));
        }
        System.out.println("扣减1个库存");
        return "扣减1个库存,server.port:" + port;
    }
}
