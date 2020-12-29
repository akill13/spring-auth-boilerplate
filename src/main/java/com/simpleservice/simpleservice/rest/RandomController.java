package com.simpleservice.simpleservice.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RandomController {

    @GetMapping("/test")
    public String getSomething() {
        return "hello, world";
    }
}
