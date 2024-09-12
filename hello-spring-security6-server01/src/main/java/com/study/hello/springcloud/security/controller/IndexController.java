package com.study.hello.springcloud.security.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String home() {
        return "home page";
    }

    @GetMapping("/index")
    public String index() {
        return "index";
    }


    @GetMapping("/index2")
    public String index2() {
        return "index2";
    }

    @GetMapping("/user/index3")
    public String index3() {
        return "index3";
    }

    @GetMapping("/order/index4")
    public String index4() {
        return "index4";
    }


    @RolesAllowed({"ROLE_user"})  //配置访问此方法时应该具有的角色
    @GetMapping("/index5")
    public String index5() {
        return "index5";
    }

    @Secured("ROLE_admin")    //配置访问此方法时应该具有的角色
    @GetMapping("/index6")
    public String index6() {
        return "index6";
    }

    @PreAuthorize("hasRole('ROLE_admin') and #id<10 ") //访问此方法需要具有admin角色，同时限制只能查询id小于10的用户
    @GetMapping("/findUserById")
    public String findById(long id) {
        //TODO 查询数据库获取用户信息
        return "success";
    }

}
