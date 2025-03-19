package com.cybersec.services;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ScannerService {

    public String scanPorts(String target) {
        StringBuilder output = new StringBuilder();
        try {
            String nmapPath = "C:\\Program Files (x86)\\Nmap\\nmap.exe";
            String[] command = { nmapPath, "-p", "1-5000", "-sV", target };

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
        System.out.println(output.toString());
        return output.toString();
    }

    // New method to extract open ports from the Nmap output.
    public List<Integer> getOpenPorts(String target) {
        List<Integer> openPorts = new ArrayList<>();
        String scanOutput = scanPorts(target);
        // Regex to match lines that start with a port number and '/tcp'
        Pattern pattern = Pattern.compile("^(\\d+)/tcp\\s+open", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(scanOutput);
        while (matcher.find()) {
            try {
                int port = Integer.parseInt(matcher.group(1));
                openPorts.add(port);
            } catch (NumberFormatException e) {
                // Skip if parsing fails
            }
        }
        return openPorts;
    }
}
