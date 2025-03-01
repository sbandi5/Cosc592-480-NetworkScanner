package com.cybersec.controllers;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class TestController {
    @GetMapping("/test")
    public String testAPI() {
        return "Cyber Security Tool API is running!";
    }
}
