package com.cybersec.controllers;

import com.cybersec.services.ScannerService;
import com.cybersec.services.SnifferService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scan-sniff")
public class CombinedController {

    private final ScannerService scannerService;
    private final SnifferService snifferService;

    public CombinedController(ScannerService scannerService, SnifferService snifferService) {
        this.scannerService = scannerService;
        this.snifferService = snifferService;
    }

    @GetMapping
    public Map<String, Object> scanAndSniff(@RequestParam String target) {
        Map<String, Object> response = new HashMap<>();
        // 1. Scan for open ports using the ScannerService
        List<Integer> openPorts = scannerService.getOpenPorts(target);
        response.put("openPorts", openPorts);
        System.out.println("The open ports : " + openPorts.toString());
        
        // 2. Capture packets based on target IP and open ports
        List<String> packets = snifferService.capturePackets(target, openPorts);
        response.put("packets", packets);
        
        return response;
    }
}
