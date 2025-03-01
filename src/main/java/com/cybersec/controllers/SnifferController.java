package com.cybersec.controllers;

import com.cybersec.services.SnifferService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sniff")
public class SnifferController {
    private final SnifferService snifferService;

    public SnifferController(SnifferService snifferService) {
        this.snifferService = snifferService;
    }

    @GetMapping
    public String capturePackets() {
        return snifferService.startSniffing();
    }
}
