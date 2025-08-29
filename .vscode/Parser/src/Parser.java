import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import jpcap.packet.ICMPPacket;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Scanner;
import java.util.Date;

public class Parser {

    private static StringBuilder txtContent = new StringBuilder();
    private static StringBuilder jsonContent = new StringBuilder();
    private static int totalPackets = 0;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("请输入pcap文件路径: ");
        String filePath = scanner.nextLine().trim();
        
        try {
            File pcapFile = new File(filePath);
            if (!pcapFile.exists() || !pcapFile.isFile()) {
                System.out.println("错误：文件不存在或不是有效文件！");
                return;
            }
            
            System.out.println("正在分析文件: " + pcapFile.getAbsolutePath());
            
            // 初始化文件内容
            initializeFileContent(pcapFile);
            
            JpcapCaptor captor = JpcapCaptor.openFile(filePath);
            PacketConverter converter = new PacketConverter();
            
            captor.loopPacket(-1, converter);
            
            System.out.println("总共处理了 " + totalPackets + " 个数据包");
            
            // 完成文件内容并保存
            completeAndSaveFiles(pcapFile.getParent());
            
            captor.close();
            
        } catch (Exception e) {
            System.out.println("发生错误: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    // 替代String.repeat()的兼容方法
    private static String repeatString(String str, int count) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            result.append(str);
        }
        return result.toString();
    }
    
    // 格式化时间戳中的微秒部分 - 修复参数类型
    private static String formatMicroseconds(long usec) {
        return String.format("%06d", usec);
    }
    
    static class PacketConverter implements PacketReceiver {
        @Override
        public void receivePacket(Packet packet) {
            totalPackets++;
            
            // 转换为TXT格式
            convertToTxt(packet, totalPackets);
            
            // 转换为JSON格式
            convertToJson(packet, totalPackets);
            
            // 控制台实时显示进度
            if (totalPackets % 100 == 0) {
                System.out.println("已处理 " + totalPackets + " 个数据包...");
            }
        }
    }
    
    private static void initializeFileContent(File pcapFile) {
        // 初始化TXT内容
        txtContent.append("PCAP文件分析报告\n");
        txtContent.append(repeatString("=", 50)).append("\n");
        txtContent.append("文件路径: ").append(pcapFile.getAbsolutePath()).append("\n");
        txtContent.append("分析时间: ").append(new Date()).append("\n");
        txtContent.append(repeatString("=", 50)).append("\n\n");
        
        // 初始化JSON内容
        jsonContent.append("{\n");
        jsonContent.append("  \"analysis_date\": \"").append(new Date()).append("\",\n");
        jsonContent.append("  \"file_path\": \"").append(pcapFile.getAbsolutePath()).append("\",\n");
        jsonContent.append("  \"packets\": [\n");
    }
    
    private static void convertToTxt(Packet packet, int packetNumber) {
        txtContent.append("数据包 #").append(packetNumber).append("\n");
        txtContent.append(repeatString("-", 30)).append("\n");
        txtContent.append("时间戳: ").append(packet.sec).append(".").append(formatMicroseconds(packet.usec)).append("\n");
        txtContent.append("长度: ").append(packet.len).append(" 字节\n");
        txtContent.append("类型: ").append(packet.getClass().getSimpleName()).append("\n");
        
        // 协议特定信息
        if (packet instanceof TCPPacket) {
            TCPPacket tcp = (TCPPacket) packet;
            txtContent.append("协议: TCP\n");
            txtContent.append("源端口: ").append(tcp.src_port).append("\n");
            txtContent.append("目的端口: ").append(tcp.dst_port).append("\n");
        } else if (packet instanceof UDPPacket) {
            UDPPacket udp = (UDPPacket) packet;
            txtContent.append("协议: UDP\n");
            txtContent.append("源端口: ").append(udp.src_port).append("\n");
            txtContent.append("目的端口: ").append(udp.dst_port).append("\n");
        } else if (packet instanceof ICMPPacket) {
            txtContent.append("协议: ICMP\n");
        }
        
        txtContent.append("原始数据: ").append(packet.toString()).append("\n\n");
    }
    
    private static void convertToJson(Packet packet, int packetNumber) {
        if (packetNumber > 1) {
            jsonContent.append(",\n");
        }
        
        jsonContent.append("    {\n");
        jsonContent.append("      \"packet_number\": ").append(packetNumber).append(",\n");
        jsonContent.append("      \"timestamp_sec\": ").append(packet.sec).append(",\n");
        jsonContent.append("      \"timestamp_usec\": ").append(packet.usec).append(",\n");
        jsonContent.append("      \"length_bytes\": ").append(packet.len).append(",\n");
        jsonContent.append("      \"packet_type\": \"").append(packet.getClass().getSimpleName()).append("\"");
        
        // 协议特定字段
        if (packet instanceof TCPPacket) {
            TCPPacket tcp = (TCPPacket) packet;
            jsonContent.append(",\n");
            jsonContent.append("      \"protocol\": \"TCP\",\n");
            jsonContent.append("      \"source_port\": ").append(tcp.src_port).append(",\n");
            jsonContent.append("      \"destination_port\": ").append(tcp.dst_port).append("\n");
        } else if (packet instanceof UDPPacket) {
            UDPPacket udp = (UDPPacket) packet;
            jsonContent.append(",\n");
            jsonContent.append("      \"protocol\": \"UDP\",\n");
            jsonContent.append("      \"source_port\": ").append(udp.src_port).append(",\n");
            jsonContent.append("      \"destination_port\": ").append(udp.dst_port).append("\n");
        } else if (packet instanceof ICMPPacket) {
            jsonContent.append(",\n");
            jsonContent.append("      \"protocol\": \"ICMP\"\n");
        } else {
            jsonContent.append(",\n");
            jsonContent.append("      \"protocol\": \"OTHER\"\n");
        }
        
        jsonContent.append("    }");
    }
    
    private static void completeAndSaveFiles(String directoryPath) {
        // 完成JSON内容
        jsonContent.append("\n  ],\n");
        jsonContent.append("  \"total_packets\": ").append(totalPackets).append("\n");
        jsonContent.append("}");
        
        // 保存文件
        saveToTxtFile(directoryPath);
        saveToJsonFile(directoryPath);
    }
    
    private static void saveToTxtFile(String directoryPath) {
        try {
            String txtFilePath = directoryPath + File.separator + "pcap_analysis.txt";
            try (PrintWriter writer = new PrintWriter(new FileWriter(txtFilePath))) {
                writer.write(txtContent.toString());
                writer.println("\n" + repeatString("=", 50));
                writer.println("分析完成时间: " + new Date());
                writer.println("总共分析数据包: " + totalPackets);
            }
            System.out.println("TXT文件已保存: " + txtFilePath);
        } catch (Exception e) {
            System.out.println("保存TXT文件时出错: " + e.getMessage());
        }
    }
    
    private static void saveToJsonFile(String directoryPath) {
        try {
            String jsonFilePath = directoryPath + File.separator + "pcap_analysis.json";
            try (PrintWriter writer = new PrintWriter(new FileWriter(jsonFilePath))) {
                writer.write(jsonContent.toString());
            }
            System.out.println("JSON文件已保存: " + jsonFilePath);
        } catch (Exception e) {
            System.out.println("保存JSON文件时出错: " + e.getMessage());
        }
    }
}