package com.study.hello.springcloud.security6.oauth2.server.framework.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@RestController
public class CustomErrorController implements ErrorController {

    private final ErrorAttributes errorAttributes;

    public CustomErrorController(ErrorAttributes errorAttributes) {
        this.errorAttributes = errorAttributes;
    }

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> handleError(HttpServletRequest request) {
        WebRequest webRequest = new org.springframework.web.context.request.ServletWebRequest(request);

        // 获取错误属性，包含堆栈跟踪信息
        Map<String, Object> errorDetails = errorAttributes.getErrorAttributes(webRequest,
                ErrorAttributeOptions.of(ErrorAttributeOptions.Include.STACK_TRACE));

        // 获取状态码
        int status = (int) errorDetails.getOrDefault("status", HttpStatus.INTERNAL_SERVER_ERROR.value());

        // 返回 JSON 响应
        return ResponseEntity.status(status).body(errorDetails);
    }

    public String getErrorPath() {
        return "/error";
    }
}