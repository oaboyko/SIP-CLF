import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;

public class Capturer {

	public static void main(String[] args) {
		List<PcapIf> allDevs = new ArrayList<PcapIf>();
		StringBuilder errBuf = new StringBuilder();
		
		int r = Pcap.findAllDevs(allDevs, errBuf);
		if(r == Pcap.NOT_OK || allDevs.isEmpty()){
			System.err.printf("Can't read list of devices, error is %s", errBuf.toString());
			return;
		}
		
		System.out.println("System devices:");
		int i = 0;
		for(PcapIf device : allDevs){
			String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}
		
		PcapIf device = allDevs.get(0);
		int p_length = 64*1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 5*1000;
		
		Pcap pcap = Pcap.openLive(device.getName(), p_length, flags, timeout, errBuf);
		
		if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errBuf.toString());  
            return;  
        }
		
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>(){
			//Payload payload = new Payload();
			public void nextPacket(PcapPacket packet, String user){
				/*if(packet.hasHeader(payload)){
					//String payloadS = payload.getUTF8String(0, payload.size());
					byte[] payloadCont = payload.getByteArray(0, payload.size());
					StringBuilder sb = new StringBuilder();
					for(byte b : payloadCont){
						sb.append(String.format("%02X", b));
					}
					System.out.printf("--->Payload: %s\n", sb.toString());
				}*/
				/*Print the whole packet*/
				System.out.printf("Received packet at %s caplen=%-4d %s\n", 
						new Date(packet.getCaptureHeader().timestampInMillis()), 
						packet.getCaptureHeader().caplen(),
						packet.toString());
			}
		};
		
		pcap.loop(10, jpacketHandler, "jnet");
		pcap.close();
	}

}
