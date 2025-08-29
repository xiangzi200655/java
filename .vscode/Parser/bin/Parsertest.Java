import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import java.io.File;
import java.util.Scanner;

public class Parsertest {

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
            
            JpcapCaptor captor = JpcapCaptor.openFile(filePath);
            PacketCounter counter = new PacketCounter();
            
            captor.loopPacket(-1, counter);
            
            System.out.println("总共处理了 " + counter.count + " 个数据包");
            
            captor.close();
            
        } catch (Exception e) {
            System.out.println("发生错误: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
    
    static class PacketCounter implements PacketReceiver {
        int count = 0;
        
        @Override
        public void receivePacket(Packet packet) {
            count++;
            System.out.println("数据包 #" + count + ": " + packet);
        }
    }
}