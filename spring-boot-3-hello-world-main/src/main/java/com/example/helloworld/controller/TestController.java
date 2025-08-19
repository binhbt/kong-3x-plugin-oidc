package com.example.helloworld.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Enumeration;

@RestController
public class TestController {

    @GetMapping("/public/hello")
    public String publicHello(HttpServletRequest request) {
        logHeaders(request);
        return "Hello from public endpoint!";
    }

    @GetMapping("/private/hello")
    public String privateHello() {
        return "Hello from protected endpoint!";
    }

    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('manager')")
    public String adminOnly() {
        return "Only admin (alice) can see this!";
    }

    private void logHeaders(HttpServletRequest request){
        Enumeration<String> headerNames = request.getHeaderNames();
        System.out.println("---- Request Headers ----");
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            String value = request.getHeader(name);
            System.out.println(name + ": " + value);
        }
    }
}
