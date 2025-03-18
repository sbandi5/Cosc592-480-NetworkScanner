package com.cybersec.services;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class SnifferService {
    @Autowired
    private SimpMessagingTemplate messagingTemplate; // WebSocket Broadcaster

    @Async
    public void captureLivePackets() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces.isEmpty()) {
                messagingTemplate.convertAndSend("/topic/packets", "No network interfaces found.");
                return;
            }

            PcapNetworkInterface nif = interfaces.get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            while (true) { // Continuous Capture
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    messagingTemplate.convertAndSend("/topic/packets", packet.toString());
                }
            }
        } catch (Exception e) {
            messagingTemplate.convertAndSend("/topic/packets", "Error: " + e.getMessage());
        }
    }
    public List<String> capturePackets(String target, List<Integer> openPorts) {
        List<String> packetsList = new ArrayList<>();
        Map<String, Integer> protocolCount = new HashMap<>(); // Track protocol count

        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces.isEmpty()) {
                packetsList.add("No network interfaces found.");
                return packetsList;
            }

            PcapNetworkInterface nif = interfaces.get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            // Build BPF filter
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
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

            // Prepare pcap file for saving packets
            File pcapFile = new File("captured_packets.pcap");
            PcapDumper dumper = handle.dumpOpen(pcapFile.getAbsolutePath());

            // Capture packets
            for (int i = 0; i < 10; i++) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    packetsList.add(analyzePacket(packet, protocolCount));
                    dumper.dump(packet, handle.getTimestamp()); // Save packet to pcap
                }
            }

            dumper.close();
            handle.close();

            // Append protocol statistics to results
            packetsList.add("\nProtocol Statistics:");
            for (Map.Entry<String, Integer> entry : protocolCount.entrySet()) {
                packetsList.add(entry.getKey() + ": " + entry.getValue());
            }

        } catch (Exception e) {
            packetsList.add("Error: " + e.getMessage());
        }

        return packetsList;
    }

    private String analyzePacket(Packet packet, Map<String, Integer> protocolCount) {
        StringBuilder result = new StringBuilder();
        result.append("\n--- Captured Packet ---\n");

        // Check for Ethernet packet
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            result.append("Source MAC: ").append(ethernetPacket.getHeader().getSrcAddr())
                  .append(", Destination MAC: ").append(ethernetPacket.getHeader().getDstAddr()).append("\n");
        }

        // Check for IP packet
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            String srcIp = ipPacket.getHeader().getSrcAddr().toString();
            String dstIp = ipPacket.getHeader().getDstAddr().toString();
            IpNumber protocol = ipPacket.getHeader().getProtocol();

            result.append("Source IP: ").append(srcIp)
                  .append(", Destination IP: ").append(dstIp)
                  .append(", Protocol: ").append(protocol).append("\n");

            // Count protocol occurrences
            protocolCount.put(protocol.toString(), protocolCount.getOrDefault(protocol.toString(), 0) + 1);

            // TCP/UDP Specific
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                TcpPort srcPort = tcpPacket.getHeader().getSrcPort();
                TcpPort dstPort = tcpPacket.getHeader().getDstPort();
                result.append("TCP Packet - Source Port: ").append(srcPort)
                      .append(", Destination Port: ").append(dstPort).append("\n");
            }
            if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                UdpPort srcPort = udpPacket.getHeader().getSrcPort();
                UdpPort dstPort = udpPacket.getHeader().getDstPort();
                result.append("UDP Packet - Source Port: ").append(srcPort)
                      .append(", Destination Port: ").append(dstPort).append("\n");
            }
        }

        // Display raw packet data
        result.append("Raw Packet Data: ").append(packet).append("\n");

        return result.toString();
    }

    public String startSniffing() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            PcapNetworkInterface nif = interfaces.get(0);
            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 10; i++) {
                Packet packet = handle.getNextPacket();
                if (packet != null) result.append(analyzePacket(packet, new HashMap<>())).append("\n");
            }

            handle.close();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
