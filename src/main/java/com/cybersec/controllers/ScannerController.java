package com.cybersec.controllers;

import com.cybersec.services.ScannerService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
public class ScannerController {
    private final ScannerService scannerService;

    public ScannerController(ScannerService scannerService) {
        this.scannerService = scannerService;
    }

    @GetMapping
    public String scan(@RequestParam String target) {
        return scannerService.scanPorts(target);
    }
}
