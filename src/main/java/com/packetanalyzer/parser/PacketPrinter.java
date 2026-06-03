package com.packetanalyzer.parser;

import com.packetanalyzer.types.ParsedPacket;

public class PacketPrinter {
    public static void printPacketSummary(ParsedPacket pkt, byte[] rawData, int packetNum) {
        System.out.println("\n=======================================================");
        System.out.println("Packet #" + packetNum + " | Timestamp: " + pkt.timestampSec + "." + pkt.timestampUsec);
        System.out.println("-------------------------------------------------------");
        System.out.println("[Ethernet] " + pkt.srcMac + " -> " + pkt.destMac + " (Type: 0x" + Integer.toHexString(pkt.etherType) + ")");
        
        if (pkt.hasIp) {
            System.out.println("[IPv" + pkt.ipVersion + "]     " + pkt.srcIp + " -> " + pkt.destIp + " | Proto: " + PacketParser.protocolToString(pkt.protocol) + " | TTL: " + pkt.ttl);
            
            if (pkt.hasTcp) {
                System.out.println("[TCP]      " + pkt.srcPort + " -> " + pkt.destPort + " | Flags: [" + PacketParser.tcpFlagsToString(pkt.tcpFlags) + "]");
                System.out.println("           Seq: " + pkt.seqNumber + " | Ack: " + pkt.ackNumber);
            } else if (pkt.hasUdp) {
                System.out.println("[UDP]      " + pkt.srcPort + " -> " + pkt.destPort);
            }
            
            if (pkt.payloadLength > 0) {
                System.out.println("[Payload]  " + pkt.payloadLength + " bytes");
                System.out.print("           Preview: ");
                int printLen = Math.min(pkt.payloadLength, 16);
                for (int i = 0; i < printLen; i++) {
                    byte b = rawData[pkt.payloadOffset + i];
                    if (b >= 32 && b <= 126) {
                        System.out.print((char) b);
                    } else {
                        System.out.print(".");
                    }
                }
                System.out.println();
            }
        }
        System.out.println("=======================================================");
    }
}
