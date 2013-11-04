import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
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
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.voip.Sip.Fields;

public class updatedCapturer {

	public static void main(String[] args) {
		List<PcapIf> allDevs = new ArrayList<PcapIf>();
		StringBuilder errBuf = new StringBuilder();

		// Get all of the devices in the current system
		int r = Pcap.findAllDevs(allDevs, errBuf);
		if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errBuf.toString());
			return;
		}

		// Show all devices to the user
		System.out.println("System devices:");
		int i = 0;
		for (PcapIf device : allDevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
					description);
		}

		// Make the user manually select the preferred interface
		System.out.println("Please provide the device number:");
		int devNum = Integer.parseInt(System.console().readLine());

		// Set default capture interface
		PcapIf device = allDevs.get(devNum);
		// Set maximum sizeof the packet
		int p_length = 15 * 1024;
		// Capture in "promiscuous" mode
		int flags = Pcap.MODE_PROMISCUOUS;
		// Timeout after X seconds
		System.out.println("Please input the timeout duration in seconds: ");
		int timeout = Integer.parseInt(System.console().readLine()) * 1000;
		//Filter at specific port
		System.out.println("Please input the port number on which you want to listen: ");
		int port_num = Integer.parseInt(System.console().readLine());

		// Start live capture
		Pcap pcap = Pcap.openLive(device.getName(), p_length, flags, timeout,
				errBuf);

		// BPF program assists in filtering in the SIP packets
		PcapBpfProgram program = new PcapBpfProgram();
		String expression = "dst port " + port_num +" and (tcp or udp)";

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errBuf.toString());
			return;
		}

		// Set the filter
		if (pcap.compile(program, expression, 0, 0xFFFFFF00) != Pcap.OK) {
			System.err.println(pcap.getErr());
			return;
		} else {
			if (pcap.setFilter(program) != Pcap.OK) {
				System.err.println(pcap.getErr());
				return;
			}
		}

		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			Udp udp = new Udp();
			Tcp tcp = new Tcp();
			Sip sip = new Sip();
			Ip4 ip4 = new Ip4();
			Ip6 ip6 = new Ip6();
			Sdp sdp = new Sdp();

			String to, from, to_tag, from_tag, call_id, cseq_method,
					cseq_number, transport, source_addr, dest_addr,
					source_port, dest_port, status, request_uri, request,
					directionality, server_txn, client_txn, allow, contact,
					min_expires, proxy_authenticate, unsupported,
					www_authenticate, sip_message, sdp_length, allow_length,
					contact_length, min_expires_length,
					proxy_authenticate_length, unsupported_length,
					www_authenticate_length;

			public void nextPacket(PcapPacket packet, String user) {
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
				request_uri = "";
				request = "";
				directionality = "";
				server_txn = "";
				client_txn = "";
				allow = "";
				allow_length = "";
				contact = "";
				contact_length = "";
				min_expires = "";
				min_expires_length = "";
				proxy_authenticate = "";
				proxy_authenticate_length = "";
				unsupported = "";
				unsupported_length = "";
				www_authenticate = "";
				www_authenticate = "";
				sip_message = "";
				sdp_length = "";

				System.out.println("************BEGIN SIP********************");

				// Get the time stamp of the packet
				System.out.println("CLF TIME STAMP\t"
						+ packet.getCaptureHeader().timestampInMillis());

				if (packet.hasHeader(sip)) {
					String temp;
					Pattern pattern;
					Matcher matcher;

					// Get the From URI
					temp = sip.fieldValue(Sip.Fields.From);
					pattern = Pattern.compile("<(.*);.*>;tag=(\\w+([\\:\\-]?\\w+)+)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						from = matcher.group(1);
						from_tag = matcher.group(2);
					}
					if(from == null || from_tag == null){
							System.out.println("Malformed Packet on the From Tag");
					}
					System.out.println("CLF FROM\t" + from + "\nCLF FROM TAG\t"
							+ from_tag);

					// Get the To URI
					temp = sip.fieldValue(Sip.Fields.To);
					pattern = Pattern.compile("<(.*)>");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						to = matcher.group(1);
					}
					System.out.println("CLF TO\t\t" + to);

					// Get the To Tag
					pattern = Pattern.compile("tag=(\\w+([\\:\\-]?\\w+)+)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						to_tag = matcher.group(1);
					}
					if(to_tag == null){
							System.out.println("Malformed Packet on the From Tag");
					}
					System.out.println("CLF TO TAG\t" + to_tag);

					// Get the Call ID
					call_id = sip.fieldValue(Sip.Fields.Call_ID);
					System.out.println("CLF CALL ID\t" + call_id);

					// Get the CSeq Method
					temp = sip.fieldValue(Sip.Fields.CSeq);
					pattern = Pattern.compile("(\\d+)\\s+(\\w+)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						cseq_number = matcher.group(1);
						cseq_method = matcher.group(2);
					}
					System.out.println("CLF CSeq Number " + cseq_number
							+ "\nCLF CSeq Method\t" + cseq_method);

					String sip_header = sip.getUTF8String(0, sip.size());
					System.out.println("SIP: " + sip_header);

					// Get Status
					pattern = Pattern.compile("SIP/\\d+.\\d+ (\\d+) ");
					matcher = pattern.matcher(sip_header);
					while (matcher.find()) {
						status = matcher.group(1);
					}
					System.out.println("CLF Status:\t" + status);

					// Get Request-URI
					pattern = Pattern.compile("[A-Z]+\\s+(.*)\\s+SIP");
					matcher = pattern.matcher(sip_header);
					while (matcher.find()) {
						request_uri = matcher.group(1);
					}
					System.out.println("CLF R-URI:\t" + request_uri);

					// Get Message Type
					if (!request_uri.isEmpty()) {
						request = "R";
						System.out.println("CLF Message Type:\t " + request);
					} else {
						request = "r";
						System.out.println("CLF Message Type:\t " + request);
					}

				}

				// get SDP message body
				if (packet.hasHeader(sdp)) {
					sip_message = sdp.text();
					// total length of SDP body including content type in hex
					sdp_length = Integer.toHexString(sdp.getLength() + 16);
					// add leading zeros
					if (sdp_length.length() < 4) {
						while (sdp_length.length() < 4) {
							sdp_length = "0".concat(sdp_length);
						}
					}

				}

				else {
					sip_message = "-";
					sdp_length = "-";
				}

				// Get Transport, Source Port # and Destination Port #
				if (packet.hasHeader(udp)) {
					transport = "udp";
					source_port = Integer.toString(udp.source());
					dest_port = Integer.toString(udp.destination());
				} else {
					if (packet.hasHeader(tcp)) {
						transport = "tcp";
						source_port = Integer.toString(tcp.source());
						dest_port = Integer.toString(tcp.destination());
					} else {
						transport = "NULL";
						source_port = "NULL";
						dest_port = "NULL";
					}
				}
				System.out.println("CLF Transport\t" + transport);
				System.out.println("CLF Source Port\t" + source_port);
				System.out.println("CLF Dest Port\t" + dest_port);

				if (packet.hasHeader(ip4)) {
					// Get Source Address if IP v4
					source_addr = FormatUtils.ip(ip4.source());
					// Get Destination Address IP v4
					dest_addr = FormatUtils.ip(ip4.destination());
				} else {
					if (packet.hasHeader(ip6)) {
						// Get Source Address if IP v6
						source_addr = FormatUtils.ip(ip6.source());

						// Get Destination Address if IP v6
						dest_addr = FormatUtils.ip(ip6.destination());
					} else {
						source_addr = "NULL";
						dest_addr = "NULL";
					}
				}
				System.out.println("CLF Source\t" + source_addr);
				System.out.println("CLF Destin\t" + dest_addr);

				// Get Directionality
				// First get local (external) IP address
				String ip_local = null;
				URL ipEcho = null;
				try {
					ipEcho = new URL("http://ipecho.net/plain");
				} catch (MalformedURLException e1) {
					e1.printStackTrace();
				}
				BufferedReader reader = null;
				try {
					reader = new BufferedReader(new InputStreamReader(
							ipEcho.openStream(), "UTF-8"));
					for (String line; (line = reader.readLine()) != null;) {
						ip_local = line;
					}
				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					if (reader != null)
						try {
							reader.close();
						} catch (IOException ignore) {

						}
				}
				// Now compare local (external) IP address to the destination IP
				// of the packet
				if (dest_addr == ip_local) {
					directionality = "r";
				} else {
					if (source_addr == ip_local) {
						directionality = "s";
					}
				}

				System.out
						.println("******************BEGIN OPTIONAL FIELDS********************");
				String temp;
				Pattern pattern;
				Matcher matcher;

				// Get allow
				if (sip.fieldValue(Fields.Allow) == null) {
					allow = "-";
					allow_length = "-";
				} else {
					allow = sip.fieldValue(Fields.Allow);
					allow_length = Integer.toHexString(allow.length());
					// add leading zeros
					if (allow_length.length() < 4) {
						while (allow_length.length() < 4) {
							allow_length = "0".concat(allow_length);
						}
					}
				}

				System.out.println("CLF ALLOW:\t" + allow);
				System.out.println("CLF ALLOW LENGTH:\t" + allow_length);

				// Get contact
				temp = sip.fieldValue(Sip.Fields.Contact);
				if (temp == null) {
					contact = "-";
					contact_length = "-";
				} else {
					pattern = Pattern.compile("(sip:.*):(.*)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						contact = "<" + matcher.group(1) + ">";

					}
					contact_length = Integer.toHexString(contact.length());
					// add leading zeros
					if (contact_length.length() < 4) {
						while (contact_length.length() < 4) {
							contact_length = "0".concat(contact_length);
						}
					}
					System.out.println("CLF CONTACT:\t" + contact);
					System.out
							.println("CLF CONTACT LENGTH:\t" + contact_length);
				}

				// Get min-expires
				if (sip.fieldValue(Fields.Min_Expires) == null) {
					min_expires = "-";
					min_expires_length = "-";
				} else {
					min_expires = sip.fieldValue(Fields.Min_Expires);
					min_expires_length = Integer.toHexString(min_expires
							.length());
					// add leading zeros
					if (min_expires_length.length() < 4) {
						while (min_expires_length.length() < 4) {
							min_expires_length = "0".concat(min_expires_length);
						}
					}
				}

				System.out.println("CLF MIN-EXPIRES:\t" + min_expires);
				System.out.println("CLF MIN-EXPIRES LENGTH:\t"
						+ min_expires_length);

				// Get proxy-authenticate field
				if (sip.fieldValue(Fields.Proxy_Authenticate) == null) {
					proxy_authenticate = "-";
					proxy_authenticate_length = "-";
				} else {
					proxy_authenticate = sip
							.fieldValue(Fields.Proxy_Authenticate);
					proxy_authenticate_length = Integer
							.toHexString(proxy_authenticate.length());
					// add leading zeros
					if (proxy_authenticate_length.length() < 4) {
						while (proxy_authenticate_length.length() < 4) {
							proxy_authenticate_length = "0"
									.concat(proxy_authenticate_length);
						}
					}
				}

				System.out.println("CLF PROXY-AUTHENTICATE:\t"
						+ proxy_authenticate);
				System.out.println("CLF PROXY-AUTHENTICATE LENGTH:\t"
						+ proxy_authenticate_length);

				// Get unsupported field
				if (sip.fieldValue(Fields.Unsupported) == null) {
					unsupported = "-";
					unsupported_length = "-";
				} else {
					unsupported = sip.fieldValue(Fields.Unsupported);
					unsupported_length = Integer.toHexString(unsupported
							.length());
					// add leading zeros
					if (unsupported_length.length() < 4) {
						while (unsupported_length.length() < 4) {
							unsupported_length = "0".concat(unsupported_length);
						}
					}
				}
				System.out.println("CLF UNSUPPORTED:\t" + unsupported);
				System.out.println("CLF UNSUPPORTED LENGTH:\t"
						+ unsupported_length);

				// Get www-authenticate field
				if (sip.fieldValue(Fields.WWW_Authenticate) == null) {
					www_authenticate = "-";
					www_authenticate_length = "-";
				} else {
					www_authenticate = sip.fieldValue(Fields.WWW_Authenticate);
					www_authenticate_length = Integer
							.toHexString(www_authenticate.length());
					// add leading zeros
					if (www_authenticate_length.length() < 4) {
						while (www_authenticate_length.length() < 4) {
							www_authenticate_length = "0"
									.concat(www_authenticate_length);
						}
					}
				}

				System.out
						.println("CLF WWW-AUTHENTICATE:\t" + www_authenticate);
				System.out.println("CLF WWW-AUTHENTICATE LENGTH:\t"
						+ www_authenticate_length);

				// Print sip message
				System.out.println("CLF SIP MESSAGE:\t" + sip_message);
				System.out.println("CLF SDP LENGTH:\t" + sdp_length);

				System.out.println("__________________________________________________________");

			}
		};

		pcap.loop(-1, jpacketHandler, "jnet");
		pcap.close();
	}

}
