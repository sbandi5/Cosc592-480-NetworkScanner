package com.cybersec.services;

import org.springframework.stereotype.Service;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

@Service
public class PortScannerService {

    public List<Integer> scanPorts(String target) {
        List<Integer> openPorts = new ArrayList<>();
        // Scan ports 1 to 1000 (adjust as needed)
        for (int port = 1; port <= 1000; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(target, port), 200);
                System.out.println("The open port added: "+openPorts.add(port));
                openPorts.add(port);
            } catch (Exception e) {
                // Port is closed or not responding
            }
        }
        return openPorts;
    }
}
