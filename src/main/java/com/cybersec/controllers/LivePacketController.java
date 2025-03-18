package com.cybersec.controllers;

import com.cybersec.services.SnifferService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/sniffer")
public class LivePacketController {

    @Autowired
    private SnifferService snifferService;

    @GetMapping("/start")
    public String startSniffing() {
        snifferService.captureLivePackets();
        return "Packet capture started.";
    }
}
