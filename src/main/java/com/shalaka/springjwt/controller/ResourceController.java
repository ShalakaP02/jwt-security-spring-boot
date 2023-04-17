package com.shalaka.springjwt.controller;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/getAdmin")
    public String getAdmin(){
        return "Hello Admin";
    }

    @GetMapping("/getUser")
    public String getUser(){
        return "Hello User";
    }
}
