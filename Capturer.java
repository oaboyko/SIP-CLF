import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.voip.Sip;

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
		
		System.out.println("Please provide the device number:");
		int devNum = Integer.parseInt(System.console().readLine());
		
		PcapIf device = allDevs.get(devNum);
		int p_length = 64*1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 5*1000;
		
		Pcap pcap = Pcap.openLive(device.getName(), p_length, flags, timeout, errBuf);
		
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "dst port 5060 and (tcp or udp)";
				
		if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errBuf.toString());  
            return;  
        }
		
		if(pcap.compile(program, expression, 0, 0xFFFFFF00) != Pcap.OK){
			System.err.println(pcap.getErr());
			return;
		}
		else{
			if(pcap.setFilter(program) != Pcap.OK){
				System.err.println(pcap.getErr());
				return;
			}
		}
		
		final Pattern pattern = Pattern.compile("Via: SIP/\\d+.\\d+/");
		
		
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>(){
			Payload payload = new Payload();
			Sip sip = new Sip();
			public void nextPacket(PcapPacket packet, String user){
				if(packet.hasHeader(payload)){
					String payloadS = payload.getUTF8String(0, payload.size());
					System.out.printf("_____________PAYLOAD STRING:\n%s\n___________________\n", payloadS);
					Matcher matcher = pattern.matcher(payloadS);
					while(matcher.find()){
						System.out.println("+++++++++Version: " + matcher.group() + "++++++++++");
					}
					/*String[] version = pattern.split(payloadS);
					for(String s : version){
						System.out.println("------Version: " + s);
					}*/
					byte[] payloadCont = payload.getByteArray(0, payload.size());
					StringBuilder sb = new StringBuilder();
					for(byte b : payloadCont){
						sb.append(String.format("%02X", b));
					}
					System.out.printf("--->Payload: %s\n", sb.toString());
				}
				if(packet.hasHeader(sip)){
					System.out.println("-+-+-+___________SIP___________-+-+-+-+");
				}
				/*Print the whole packet*/
				System.out.printf("Received packet at %s caplen=%-4d %s\n", 
						new Date(packet.getCaptureHeader().timestampInMillis()), 
						packet.getCaptureHeader().caplen(),
						packet.toString());
			}
		};
		
		pcap.loop(-1, jpacketHandler, "jnet");
		pcap.close();
	}

}
