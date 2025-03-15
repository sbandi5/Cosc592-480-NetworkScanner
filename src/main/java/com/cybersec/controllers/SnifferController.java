package com.cybersec.controllers;

import com.cybersec.services.SnifferService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/sniff")
public class SnifferController {

    private final SnifferService snifferService;

    public SnifferController(SnifferService snifferService) {
        this.snifferService = snifferService;
    }

    @GetMapping
    public List<String> capturePackets() {
        return snifferService.capturePackets();
    }
}
