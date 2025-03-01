package com.cybersec.services;

import org.nmap4j.Nmap4j;
import org.springframework.stereotype.Service;

@Service
public class ScannerService {
    public String scanPorts(String target) {
        try {
            Nmap4j nmap4j = new Nmap4j("C:\\Program Files (x86)\\Nmap"); // Path to Nmap installation
            nmap4j.addFlags("-p 1-1000 -sV"); // Scan first 1000 ports and detect services
            nmap4j.addTarget(target);
            nmap4j.execute();
            if (!nmap4j.hasError()) {
                return nmap4j.getOutput();
            } else {
                return "Error: " + nmap4j.getExecutionResults().getErrors();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
