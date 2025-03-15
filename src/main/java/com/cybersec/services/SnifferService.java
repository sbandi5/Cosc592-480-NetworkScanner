package com.cybersec.services;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SnifferService {

    public List<String> capturePackets(String target, List<Integer> openPorts) {
        List<String> packetsList = new ArrayList<>();
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces.isEmpty()) {
                packetsList.add("No network interfaces found.");
                return packetsList;
            }
            
            // Choose an interface (adjust if necessary)
            PcapNetworkInterface nif = interfaces.get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            
            // Build BPF filter based on the target and open ports
            StringBuilder filterBuilder = new StringBuilder("host " + target);
            if (!openPorts.isEmpty()) {
                filterBuilder.append(" and (");
                for (int i = 0; i < openPorts.size(); i++) {
                    filterBuilder.append("port ").append(openPorts.get(i));
                    if (i < openPorts.size() - 1) {
                        filterBuilder.append(" or ");
                    }
                }
                filterBuilder.append(")");
            }
            String filter = filterBuilder.toString();
            System.out.println("Applying filter: " + filter);
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            
            
            // Capture a fixed number of packets (e.g., 10)
            for (int i = 0; i < 10; i++) {
                Packet packet = handle.getNextPacket();
                System.out.println("The packet is : " + handle.getNextRawPacket());
                if (packet != null) {
                    packetsList.add(packet.toString());
                    System.out.println("Captured packet " + i + ": " + packet);
                } else {
                    System.out.println("No packet captured at iteration " + i);
                }
            }
            handle.close();
        } catch (Exception e) {
            packetsList.add("Error: " + e.getMessage());
            e.printStackTrace();
        }
        return packetsList;
    }
}
