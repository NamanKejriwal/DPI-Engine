package com.packetanalyzer.tracking;

import com.packetanalyzer.types.AppType;
import com.packetanalyzer.types.Connection;
import com.packetanalyzer.types.ConnectionState;
import com.packetanalyzer.types.FiveTuple;
import com.packetanalyzer.types.PacketAction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;
    private final HashMap<FiveTuple, Connection> connections = new HashMap<>();
    
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.tuple = tuple;
        
        connections.put(tuple, conn);
        totalSeen++;
        
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;
        
        conn.lastSeen = System.nanoTime();
        
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        
        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;
        
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public int cleanupStale(long timeoutNanos) {
        long now = System.nanoTime();
        int removed = 0;
        
        var it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            Connection conn = entry.getValue();
            
            if ((now - conn.lastSeen) > timeoutNanos || conn.state == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        
        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;
        return stats;
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    public void clear() {
        connections.clear();
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        
        FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;
        
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen < oldestTime) {
                oldestTime = entry.getValue().lastSeen;
                oldestKey = entry.getKey();
            }
        }
        
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }
}
