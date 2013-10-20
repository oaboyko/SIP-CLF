import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Sip;

public class Capturer {

	public static void main(String[] args) {
		List<PcapIf> allDevs = new ArrayList<PcapIf>();
		StringBuilder errBuf = new StringBuilder();
		
		//Get all of the devices in the current system
		int r = Pcap.findAllDevs(allDevs, errBuf);
		if(r == Pcap.NOT_OK || allDevs.isEmpty()){
			System.err.printf("Can't read list of devices, error is %s", errBuf.toString());
			return;
		}
		
		//Show all devices to the user
		System.out.println("System devices:");
		int i = 0;
		for(PcapIf device : allDevs){
			String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}
		
		//Make the user manually select the preferred interface
		System.out.println("Please provide the device number:");
		int devNum = Integer.parseInt(System.console().readLine());
		
		//Set default capture interface
		PcapIf device = allDevs.get(devNum);
		//Set maximum sizeof the packet
		int p_length = 64*1024;
		//Capture in "promiscuous" mode
		int flags = Pcap.MODE_PROMISCUOUS;
		//Timeout after 5 seconds
		int timeout = 5*1000;
		
		//Start live capture
		Pcap pcap = Pcap.openLive(device.getName(), p_length, flags, timeout, errBuf);
		
		//BPF program assists in filtering in the SIP packets
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "dst port 5060 and (tcp or udp)";
				
		if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errBuf.toString());  
            return;  
        }
		
		//Set the filter
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
		
				
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>(){
			Payload payload = new Payload();
			Udp udp = new Udp();
			Tcp tcp = new Tcp();
			Sip sip = new Sip();
			Ip4 ip4 = new Ip4();
			Ip6 ip6 = new Ip6();
			String to, from, to_tag, from_tag, call_id, cseq_method, cseq_number, transport, source_addr, dest_addr, source_port, dest_port, status;
			//Date time_stamp;
			
			public void nextPacket(PcapPacket packet, String user){
				to = "";
				from = "";
				to_tag = "";
				from_tag = "";
				call_id = "";
				cseq_method = "";
				cseq_number = "";
				transport = "";
				source_addr = "";
				dest_addr = "";
				source_port = "";
				dest_port = "";
				
				System.out.println("-+-+-+___________SIP___________-+-+-+-+");
				
				//Get the time stamp of the packet
				//time_stamp = new Date(packet.getCaptureHeader().timestampInMillis());
				System.out.println("CLF TIME STAMP\t" + packet.getCaptureHeader().timestampInMillis());
				
				if(packet.hasHeader(sip)){
					String temp;
					Pattern pattern;
					Matcher matcher;
					
					//Get the From URI
					temp = sip.fieldValue(Sip.Fields.From);
					pattern = Pattern.compile("<(.*);.*>;tag=(.*)");
					matcher = pattern.matcher(temp);
					while(matcher.find()){
						from = matcher.group(1);
						from_tag = matcher.group(2);
					}
					System.out.println("CLF FROM\t" + from + "\nCLF FROM TAG\t" + from_tag);
					
					//Get the To URI
					temp = sip.fieldValue(Sip.Fields.To);
					pattern = Pattern.compile("<(.*)>");
					matcher = pattern.matcher(temp);
					while(matcher.find()){
						to = matcher.group(1);
					}
					System.out.println("CLF TO\t\t" + to);
					
					//Get the To Tag
					pattern = Pattern.compile("tag=(.*)");
					matcher = pattern.matcher(temp);
					while(matcher.find()){
						to_tag = matcher.group(1);
					}
					System.out.println("CLF TO TAG\t" + to_tag);
					
					//Get the Call ID
					call_id = sip.fieldValue(Sip.Fields.Call_ID);
					System.out.println("CLF CALL ID\t" + call_id);
					
					//Get the CSeq Method
					temp = sip.fieldValue(Sip.Fields.CSeq);
					pattern = Pattern.compile("(\\d+)\\s+(\\w+)");
					matcher = pattern.matcher(temp);
					while(matcher.find()){
						cseq_number = matcher.group(1);
						cseq_method = matcher.group(2);
					}
					System.out.println("CLF CSeq Number " + cseq_number + "\nCLF CSeq Method\t" + cseq_method);
					
					String sip_header = sip.getUTF8String(0, sip.size());
					//System.out.println(sip_header);
					//Get Status
					pattern = Pattern.compile("SIP/\\d+.\\d+ (\\d+) ");
					matcher = pattern.matcher(sip_header);
					while(matcher.find()){
						status = matcher.group(1);
					}
					System.out.println("CLF Status\t" + status);
				}
				else{
					if(packet.hasHeader(payload)){
						Pattern pattern;
						Matcher matcher;
						String s_payload = payload.getUTF8String(0, payload.size());
						
						//Get From URI and From Tag
						pattern = Pattern.compile("From:.*<(.*);.*>;tag=(\\w+)");
						matcher = pattern.matcher(s_payload);
						System.out.println(s_payload);
						while(matcher.find()){
							from = matcher.group(1);
							from_tag = matcher.group(2);
						}
						System.out.println("CLF FROM\t" + from);
						System.out.println("CLF FROM TAG\t" + from_tag);
						
						//Get To URI
						pattern = Pattern.compile("To: <(.*)>");
						matcher = pattern.matcher(s_payload);
						while(matcher.find()){
							to = matcher.group(1);
						}
						System.out.println("CLF TO\t\t" + to);
						
						//Get To Tag if there is one
						pattern = Pattern.compile("To:.*tag=(.*)");
						matcher = pattern.matcher(s_payload);
						while(matcher.find()){
							to_tag = matcher.group(1);
						}
						System.out.println("CLF TO TAG\t" + to_tag);
						
						//Get CSeq Number and CSeq Method
						pattern = Pattern.compile("CSeq: (\\d+) (.*)");
						matcher = pattern.matcher(s_payload);
						while(matcher.find()){
							cseq_number = matcher.group(1);
							cseq_method = matcher.group(2);
						}
						System.out.println("CLF CSEQ #\t" + cseq_number);
						System.out.println("CLF CSEQ METHOD\t" + cseq_method);
						
						//Get Call-ID
						pattern = Pattern.compile("Call-ID: (.*)");
						matcher = pattern.matcher(s_payload);
						while(matcher.find()){
							call_id = matcher.group(1);
						}
						System.out.println("CLF CALL-ID\t" + call_id);
					
					}
				}
				
				//Get Transport, Source Port # and Destination Port #
				if(packet.hasHeader(udp)){
					transport = "udp";
					source_port = Integer.toString(udp.source());
					dest_port = Integer.toString(udp.destination());
				}
				else{
					if(packet.hasHeader(tcp)){
						transport = "tcp";
						source_port = Integer.toString(tcp.source());
						dest_port = Integer.toString(tcp.destination());
					}
					else{
						transport = "NULL";
						source_port = "NULL";
						dest_port = "NULL";
					}
				}
				System.out.println("CLF Transport\t" + transport);
				System.out.println("CLF Source Port\t" + source_port);
				System.out.println("CLF Dest Port\t" + dest_port);
				
				if(packet.hasHeader(ip4)){
					//Get Source Address if IP v4
					source_addr = FormatUtils.ip(ip4.source());
					//Get Destination Address IP v4
					dest_addr = FormatUtils.ip(ip4.destination());
				}
				else{
					if(packet.hasHeader(ip6)){
						//Get Source Address if IP v6
						source_addr = FormatUtils.ip(ip6.source());
						
						//Get Destination Address if IP v6
						dest_addr = FormatUtils.ip(ip6.destination());
					}
					else{
						source_addr = "NULL";
						dest_addr = "NULL";
					}
				}
				System.out.println("CLF Source\t" + source_addr);
				System.out.println("CLF Destin\t" + dest_addr);
				
				System.out.println("________________________________");
								
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
