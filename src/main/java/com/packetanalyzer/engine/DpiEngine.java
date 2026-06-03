package com.packetanalyzer.engine;

import com.packetanalyzer.io.PcapReader;
import com.packetanalyzer.io.PcapWriter;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.tracking.GlobalConnectionTable;
import com.packetanalyzer.types.DPIStats;
import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketAction;
import com.packetanalyzer.types.PacketJob;
import com.packetanalyzer.types.ParsedPacket;
import com.packetanalyzer.types.AppType;
import com.packetanalyzer.io.ByteUtils;
import com.packetanalyzer.analytics.AnalyticsManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class DpiEngine {

    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;

    private final List<FastPathProcessor> fastPathProcessors = new ArrayList<>();
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();

    private final LinkedBlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(10000);
    private Thread outputThread;
    private PcapWriter pcapWriter;

    private final DPIStats stats = new DPIStats();
    private final AtomicBoolean running = new AtomicBoolean(false);

    public DpiEngine(Config config) {
        this.config = config;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println(String.format("║ Configuration:                                                ║"));
        System.out.println(String.format("║   Load Balancers:    %3d                                       ║", config.numLoadBalancers));
        System.out.println(String.format("║   FPs per LB:        %3d                                       ║", config.fpsPerLb));
        System.out.println(String.format("║   Total FP threads:  %3d                                       ║", config.numLoadBalancers * config.fpsPerLb));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        ruleManager = new RuleManager();
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
            
            RuleManager.RuleStats rstats = ruleManager.getStats();
            System.out.println("\n==================================================");
            System.out.println("RULE ENGINE");
            System.out.println("===========\n");
            System.out.println("Rules File:");
            System.out.println(config.rulesFile + "\n");
            System.out.println("Loaded Rules:");
            System.out.println("Domains: " + rstats.blockedDomains);
            System.out.println("IPs: " + rstats.blockedIps);
            System.out.println("Ports: " + rstats.blockedPorts);
            System.out.println("Applications: " + rstats.blockedApps);
            System.out.println("\n==================================================");
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        globalConnTable = new GlobalConnectionTable(totalFps);

        FastPathProcessor.PacketOutputCallback outputCb = (job, action, reason) -> handleOutput(job, action, reason);

        List<LinkedBlockingQueue<PacketJob>> allFpQueues = new ArrayList<>();

        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor fp = new FastPathProcessor(i, ruleManager, stats, config.verbose, outputCb);
            fastPathProcessors.add(fp);
            allFpQueues.add(fp.getInputQueue());
            globalConnTable.registerTracker(i, fp.getConnectionTracker());
        }

        for (int i = 0; i < config.numLoadBalancers; i++) {
            int fpStart = i * config.fpsPerLb;
            List<LinkedBlockingQueue<PacketJob>> lbFpQueues = allFpQueues.subList(fpStart, fpStart + config.fpsPerLb);
            LoadBalancer lb = new LoadBalancer(i, lbFpQueues, fpStart);
            loadBalancers.add(lb);
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);

        outputThread = new Thread(this::outputThreadFunc, "OutputWriter");
        outputThread.start();

        for (FastPathProcessor fp : fastPathProcessors) {
            fp.start();
        }

        for (LoadBalancer lb : loadBalancers) {
            lb.start();
        }

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);

        for (LoadBalancer lb : loadBalancers) {
            lb.stop();
        }

        for (FastPathProcessor fp : fastPathProcessors) {
            fp.stop();
        }

        if (outputThread != null) {
            try {
                outputThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public boolean processFile(String inputFile, String outputFile) {
        long startTime = System.currentTimeMillis();
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        pcapWriter = new PcapWriter(outputFile);
        if (!pcapWriter.open()) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        start();

        Thread readerThread = new Thread(() -> readerThreadFunc(inputFile), "PcapReader");
        readerThread.start();

        try {
            readerThread.join();
            
            // Wait for queues to drain
            while (!allQueuesEmpty()) {
                Thread.sleep(100);
            }
            Thread.sleep(500); // Give FPs a chance to finish last packets
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        stop();

        if (pcapWriter != null) {
            pcapWriter.close();
        }

        System.out.print(generateReport());
        System.out.print(globalConnTable.generateReport());

        long runtimeMs = System.currentTimeMillis() - startTime;
        AnalyticsManager.exportAll(stats, globalConnTable, inputFile, runtimeMs);

        return true;
    }

    private boolean allQueuesEmpty() {
        for (LoadBalancer lb : loadBalancers) {
            if (!lb.getInputQueue().isEmpty()) return false;
        }
        for (FastPathProcessor fp : fastPathProcessors) {
            if (!fp.getInputQueue().isEmpty()) return false;
        }
        return outputQueue.isEmpty();
    }

    private void readerThreadFunc(String inputFile) {
        PcapReader reader = new PcapReader(inputFile);
        if (!reader.open()) {
            System.err.println("[Reader] Error: Cannot open input file");
            return;
        }

        try {
            pcapWriter.writeGlobalHeader(reader.getGlobalHeader());
        } catch (IOException e) {
            System.err.println("[Reader] Error writing PCAP header");
            return;
        }

        ParsedPacket parsed = new ParsedPacket();
        int packetId = 0;

        System.out.println("[Reader] Starting packet processing...");

        PcapReader.RawPacket raw;
        while ((raw = reader.readNextPacket()) != null) {
            if (!PacketParser.parse(raw.data, raw.tsSec, raw.tsUsec, parsed)) {
                continue;
            }

            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                continue;
            }

            PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            int lbIndex = selectLB(job.tuple);
            try {
                loadBalancers.get(lbIndex).getInputQueue().put(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[Reader] Finished reading " + packetId + " packets");
        reader.close();
    }

    private int selectLB(FiveTuple tuple) {
        long hash = tuple.hashCode() & 0xFFFFFFFFL;
        return (int) (hash % loadBalancers.size());
    }

    private PacketJob createPacketJob(PcapReader.RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.tsSec;
        job.tsUsec = raw.tsUsec;
        
        job.tuple.srcIp = ByteUtils.parseIp(parsed.srcIp);
        job.tuple.dstIp = ByteUtils.parseIp(parsed.destIp);
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;
        
        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data;
        
        job.ethOffset = 0;
        job.ipOffset = 14;
        
        if (raw.data.length > 14) {
            int ipIhl = raw.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;
            
            if (parsed.hasTcp && raw.data.length > job.transportOffset) {
                int tcpDataOffset = (raw.data[job.transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = job.transportOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }
            
            if (job.payloadOffset < raw.data.length) {
                job.payloadLength = raw.data.length - job.payloadOffset;
            }
        }
        
        return job;
    }

    private void handleOutput(PacketJob job, PacketAction action, RuleManager.BlockReason reason) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.put(job);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    synchronized (pcapWriter) {
                        pcapWriter.writePacket(job.tsSec, job.tsUsec, job.data);
                    }
                }
            } catch (InterruptedException e) {
                if (!running.get()) break;
                Thread.currentThread().interrupt();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public String generateReport() {
        StringBuilder ss = new StringBuilder();
        
        ss.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        ss.append("║                    DPI ENGINE STATISTICS                      ║\n");
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        
        ss.append("║ PACKET STATISTICS                                             ║\n");
        ss.append(String.format("║   Total Packets:      %12d                        ║\n", stats.totalPackets.get()));
        ss.append(String.format("║   Total Bytes:        %12d                        ║\n", stats.totalBytes.get()));
        ss.append(String.format("║   TCP Packets:        %12d                        ║\n", stats.tcpPackets.get()));
        ss.append(String.format("║   UDP Packets:        %12d                        ║\n", stats.udpPackets.get()));
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FILTERING STATISTICS                                          ║\n");
        ss.append(String.format("║   Forwarded:          %12d                        ║\n", stats.forwardedPackets.get()));
        ss.append(String.format("║   Dropped/Blocked:    %12d                        ║\n", stats.droppedPackets.get()));
        
        long total = stats.totalPackets.get();
        if (total > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / total;
            ss.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n", dropRate));
        }
        
        long lbReceived = 0, lbDispatched = 0;
        for (LoadBalancer lb : loadBalancers) {
            LoadBalancer.LBStats lstats = lb.getStats();
            lbReceived += lstats.packetsReceived;
            lbDispatched += lstats.packetsDispatched;
        }
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ LOAD BALANCER STATISTICS                                      ║\n");
        ss.append(String.format("║   LB Received:        %12d                        ║\n", lbReceived));
        ss.append(String.format("║   LB Dispatched:      %12d                        ║\n", lbDispatched));
        
        long fpProcessed = 0, fpForwarded = 0, fpDropped = 0, connectionsTracked = 0;
        for (FastPathProcessor fp : fastPathProcessors) {
            FastPathProcessor.FPStats fstats = fp.getStats();
            fpProcessed += fstats.packetsProcessed;
            fpForwarded += fstats.packetsForwarded;
            fpDropped += fstats.packetsDropped;
            connectionsTracked += fstats.connectionsTracked;
        }
        
        ss.append("╠══════════════════════════════════════════════════════════════╣\n");
        ss.append("║ FAST PATH STATISTICS                                          ║\n");
        ss.append(String.format("║   FP Processed:       %12d                        ║\n", fpProcessed));
        ss.append(String.format("║   FP Forwarded:       %12d                        ║\n", fpForwarded));
        ss.append(String.format("║   FP Dropped:         %12d                        ║\n", fpDropped));
        ss.append(String.format("║   Active Connections: %12d                        ║\n", connectionsTracked));
        
        if (ruleManager != null) {
            RuleManager.RuleStats rstats = ruleManager.getStats();
            ss.append("╠══════════════════════════════════════════════════════════════╣\n");
            ss.append("║ BLOCKING RULES                                                ║\n");
            ss.append(String.format("║   Blocked IPs:        %12d                        ║\n", rstats.blockedIps));
            ss.append(String.format("║   Blocked Apps:       %12d                        ║\n", rstats.blockedApps));
            ss.append(String.format("║   Blocked Domains:    %12d                        ║\n", rstats.blockedDomains));
            ss.append(String.format("║   Blocked Ports:      %12d                        ║\n", rstats.blockedPorts));
        }
        
        ss.append("╚══════════════════════════════════════════════════════════════╝\n");
        
        ss.append("\n==================================================\n");
        ss.append("RULE STATISTICS\n");
        ss.append("===============\n\n");
        ss.append("Blocked By Domain: ").append(stats.blockedByDomain.get()).append("\n");
        ss.append("Blocked By IP: ").append(stats.blockedByIp.get()).append("\n");
        ss.append("Blocked By Port: ").append(stats.blockedByPort.get()).append("\n");
        ss.append("Blocked By Application: ").append(stats.blockedByApp.get()).append("\n\n");
        
        long totalBlockedFlows = stats.blockedByDomain.get() + stats.blockedByIp.get() + stats.blockedByPort.get() + stats.blockedByApp.get();
        ss.append("Total Blocked Flows: ").append(totalBlockedFlows).append("\n\n");
        ss.append("==================================================\n");
        
        return ss.toString();
    }
}
