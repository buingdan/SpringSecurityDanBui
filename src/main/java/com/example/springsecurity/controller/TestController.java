package com.example.springsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test/dandev")
@RequiredArgsConstructor
public class TestController {
    @GetMapping("/id")
    public  String sayHello(){
        return "Hello World";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public  String sayHelloAdmin(){
        return "Hello Admin";
    }

    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public  String sayHelloManager(){
        return "Hello Manager";
    }

    @GetMapping("")
    public  String sayHelloDanBui(){
        return "Hello DanBui";
    }

}
