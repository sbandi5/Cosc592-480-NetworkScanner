package com.cybersec.services;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SnifferService {
    public String startSniffing() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            PcapNetworkInterface nif = interfaces.get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 10; i++) {
                Packet packet = handle.getNextPacket();
                if (packet != null) result.append(packet.toString()).append("\n");
            }
            handle.close();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
