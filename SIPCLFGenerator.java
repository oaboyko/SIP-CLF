/* 
 * Name:    SIP CLF Log Generator
 * Authors: Oleksandr Boyko (oaboyko@ncsu.edu)
 *          Vincent Sanders (vmsander@ncsu.edu)
 *          Ethan Smith     (essmith2@ncsu.edu)
 * License:	GPLv3
 * Date:    12/01/2013 
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
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

public class SIPCLFGenerator {

	public static String to_uri, from, to_tag, from_tag, call_id, cseq_method,
			cseq_number, transport, source_addr, dest_addr, source_port,
			dest_port, status, request_uri, message_type, directionality,
			server_txn, client_txn, allow, contact, min_expires,
			proxy_authenticate, unsupported, www_authenticate, sip_message,
			sdp_length, allow_length, contact_length, min_expires_length,
			proxy_authenticate_length, unsupported_length,
			www_authenticate_length, sip_header, BEB;

	public static long time_stamp, fractional_seconds;

	public static int YES = 1;
	public static int NO = 0;
	public static int firstWrite = YES;
	public static int sipPackets = 0;

	
	public static java.util.Date date = new java.util.Date();
	public final static long dateAppend = date.getTime();
	
	private static int role;

	public static PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

		Udp udp = new Udp();
		Tcp tcp = new Tcp();
		Sip sip = new Sip();
		Ip4 ip4 = new Ip4();
		Ip6 ip6 = new Ip6();
		Sdp sdp = new Sdp();

		private int srv_txn = -1;
		private int clt_txn = -1;
		
		private Map<String,Integer> Sources = new HashMap<String,Integer>();
		private Map<String,Integer> Destinations = new HashMap<String,Integer>();
		
		public void nextPacket(PcapPacket packet, String user) {
			to_uri = "-";
			from = "-";
			to_tag = "-";
			from_tag = "-";
			call_id = "-";
			status = "-";
			cseq_method = "-";
			cseq_number = "-";
			transport = "-";
			source_addr = "-";
			dest_addr = "-";
			source_port = "-";
			dest_port = "-";
			request_uri = "-";
			message_type = "-";
			directionality = "-";
			server_txn = "-";
			client_txn = "-";
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
			time_stamp = 0;
			fractional_seconds = 0;

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

			// Get the time stamp of the packet
			time_stamp = packet.getCaptureHeader().seconds();

			// Get fractional seconds in ms
			fractional_seconds = packet.getCaptureHeader().nanos() / 1000000;

			if (packet.hasHeader(sip)) {
				String temp;
				Pattern pattern;
				Matcher matcher;

				// Get the From URI
				temp = sip.fieldValue(Sip.Fields.From);
				pattern = Pattern.compile("<(.*);?.*>;tag=(.*)");
				matcher = pattern.matcher(temp);
				while (matcher.find()) {
					from = matcher.group(1);
					from_tag = matcher.group(2);
				}
				if (from == null || from_tag == null) {
					System.out.println("Malformed Packet on the From Tag");
				}

				// Get the To URI
				temp = sip.fieldValue(Sip.Fields.To);
				pattern = Pattern.compile("<(.*)>");
				matcher = pattern.matcher(temp);
				while (matcher.find()) {
					to_uri = matcher.group(1);
				}

				// Get the To Tag
				pattern = Pattern.compile("tag=(.*)");
				matcher = pattern.matcher(temp);
				while (matcher.find()) {
					to_tag = matcher.group(1);
				}
				if (to_tag == null) {
					System.out.println("Malformed Packet on the From Tag");
				}

				// Get the Call ID
				call_id = sip.fieldValue(Sip.Fields.Call_ID);

				// Get the CSeq Method
				temp = sip.fieldValue(Sip.Fields.CSeq);
				pattern = Pattern.compile("(\\d+)\\s+(\\w+)");
				matcher = pattern.matcher(temp);
				while (matcher.find()) {
					cseq_number = matcher.group(1);
					cseq_method = matcher.group(2);
				}

				sip_header = sip.getUTF8String(0, sip.size());

				// Get Status
				pattern = Pattern.compile("SIP/\\d+.\\d+ (\\d+) ");
				matcher = pattern.matcher(sip_header);
				while (matcher.find()) {
					status = matcher.group(1);
				}

				// Get Request-URI
				pattern = Pattern.compile("[A-Z]+\\s+(.*)\\s+SIP");
				matcher = pattern.matcher(sip_header);
				while (matcher.find()) {
					request_uri = matcher.group(1);
				}

				// Get Message Type
				if (!request_uri.isEmpty()) {
					message_type = "R";
				} else {
					message_type = "r";
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

				sip_message = sip_message.replaceAll("\r\n", "%0D%0A");
				sip_message = sip_message.replaceAll("\n", "%0D%0A");

			}

			else {
				sip_message = "-";
				sdp_length = "-";
			}

			// Get Transport, Source Port # and Destination Port #
			if (packet.hasHeader(udp)) {
				transport = "U";
				source_port = Integer.toString(udp.source());
				dest_port = Integer.toString(udp.destination());
			} else {
				if (packet.hasHeader(tcp)) {
					transport = "T";
					source_port = Integer.toString(tcp.source());
					dest_port = Integer.toString(tcp.destination());
				} else {
					transport = "-";
					source_port = "-";
					dest_port = "-";
				}
			}

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
					source_addr = "-";
					dest_addr = "-";
				}
			}

			// Get Directionality
			// Now compare local (external) IP address to the destination IP
			// of the packet
			if (dest_addr == ip_local) {
				directionality = "r";
			} else {
				if (source_addr == ip_local) {
					directionality = "s";
				}
			}
			
			// Get the server and client Txn
			if(directionality == "r" && message_type == "R"){		//receive a request
				switch(role){										
					case 1: if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								clt_txn++;
								Destinations.put(dest_addr + ":" + dest_port, clt_txn);
							}
							if(!Sources.containsKey(source_addr + ":" + source_port)){
								srv_txn++;
								Sources.put(source_addr + ":" + source_port, srv_txn);
							}
							client_txn = "c-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							server_txn = "s-tr-" + Sources.get(source_addr + ":" + source_port);
							break;
					case 2: if(!Sources.containsKey(source_addr + ":" + source_port)){
								srv_txn++;
								Sources.put(source_addr + ":" + source_port, srv_txn);
							}
							client_txn = "-";
							server_txn = "s-tr-" + Sources.get(source_addr + ":" + source_port);
							break;												
				}
			}
			else if(directionality == "s" && message_type == "R"){  //sending a request
				switch(role){
					case 1: if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								clt_txn++;
								Destinations.put(dest_addr + ":" + dest_port, clt_txn);
							}
							client_txn = "c-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							server_txn = "-";
							break;
					case 2: if(!Sources.containsKey(source_addr + ":" + source_port)){
								clt_txn++;
								Sources.put(source_addr + ":" + source_port, clt_txn);
							}
							if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								srv_txn++;
								Destinations.put(dest_addr + ":" + dest_port, srv_txn);
							}
							client_txn = "c-tr-" + Sources.get(source_addr + ":" + source_port);
							server_txn = "s-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							break;
				}
			}
			else if(directionality == "r" && message_type == "r"){  //receive a response
				switch(role){
					case 1: if(!Sources.containsKey(source_addr + ":" + source_port)){
								clt_txn++;
								Sources.put(source_addr + ":" + source_port, clt_txn);
							}
							client_txn = "c-tr-" + Sources.get(source_addr + ":" + source_port);
							server_txn = "-";
							break;
					case 2: if(!Sources.containsKey(source_addr + ":" + source_port)){
								clt_txn++;
								Sources.put(source_addr + ":" + source_port, clt_txn);
							}
							if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								srv_txn++;
								Destinations.put(dest_addr + ":" + dest_port, srv_txn);
							}
							client_txn = "c-tr-" + Sources.get(source_addr + ":" + source_port);
							server_txn = "s-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							break;
				}
			}
			else if(directionality == "s" && message_type == "r"){	//send a response
				switch(role){
					case 1: if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								clt_txn++;
								Destinations.put(dest_addr + ":" + dest_port, clt_txn);
							}
							if(!Sources.containsKey(source_addr + ":" + source_port)){
								srv_txn++;
								Sources.put(source_addr + ":" + source_port, srv_txn);
							}
							client_txn = "c-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							server_txn = "s-tr-" + Sources.get(source_addr + ":" + source_port);
							break;
					case 2: if(!Destinations.containsKey(dest_addr + ":" + dest_port)){
								srv_txn++;
								Destinations.put(dest_addr + ":" + dest_port, srv_txn);
							}
							client_txn = "-";
							server_txn = "s-tr-" + Destinations.get(dest_addr + ":" + dest_port);
							break;
				}
			}
			else{
				
			}

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
			}

			// Get min-expires
			if (sip.fieldValue(Fields.Min_Expires) == null) {
				min_expires = "-";
				min_expires_length = "-";
			} else {
				min_expires = sip.fieldValue(Fields.Min_Expires);
				min_expires_length = Integer.toHexString(min_expires.length());
				// add leading zeros
				if (min_expires_length.length() < 4) {
					while (min_expires_length.length() < 4) {
						min_expires_length = "0".concat(min_expires_length);
					}
				}
			}

			// Get proxy-authenticate field
			if (sip.fieldValue(Fields.Proxy_Authenticate) == null) {
				proxy_authenticate = "-";
				proxy_authenticate_length = "-";
			} else {
				proxy_authenticate = sip.fieldValue(Fields.Proxy_Authenticate);
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

			// Get unsupported field
			if (sip.fieldValue(Fields.Unsupported) == null) {
				unsupported = "-";
				unsupported_length = "-";
			} else {
				unsupported = sip.fieldValue(Fields.Unsupported);
				unsupported_length = Integer.toHexString(unsupported.length());
				// add leading zeros
				if (unsupported_length.length() < 4) {
					while (unsupported_length.length() < 4) {
						unsupported_length = "0".concat(unsupported_length);
					}
				}
			}

			// Get www-authenticate field
			if (sip.fieldValue(Fields.WWW_Authenticate) == null) {
				www_authenticate = "-";
				www_authenticate_length = "-";
			} else {
				www_authenticate = sip.fieldValue(Fields.WWW_Authenticate);
				www_authenticate_length = Integer.toHexString(www_authenticate
						.length());
				// add leading zeros
				if (www_authenticate_length.length() < 4) {
					while (www_authenticate_length.length() < 4) {
						www_authenticate_length = "0"
								.concat(www_authenticate_length);
					}
				}
			}

			// Print sip message
			if (packet.hasHeader(sip)) {
				sipPackets++;
				logGenerator();
			}
		}
	};

	public static void main(String[] args) throws Exception {

		Scanner scan = new Scanner(System.in); // use scanner to allow
												// functionality in IDE
		List<PcapIf> allDevs = new ArrayList<PcapIf>();
		StringBuilder errBuf = new StringBuilder();

		int num_of_packets;
		int capt_type = 0;

		// Get all of the devices in the current system
		int r = Pcap.findAllDevs(allDevs, errBuf);
		if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errBuf.toString());
			scan.close();
			return;
		}

		Pcap pcap = null;
		// scan.nextLine()
		while(capt_type != 1 && capt_type != 2){
			System.out
					.println("Please select the number for type of capture:\n  [1] Offline\n  [2] Online");
			// capt_type = Integer.parseInt(System.console().readLine());
			capt_type = Integer.parseInt(scan.nextLine());
		}
		while(role != 1 && role != 2){
			System.out.println("What is the role of this system?\n [1] Client\n [2] Proxy");
			role = Integer.parseInt(scan.nextLine());
		}
		System.out
				.println("Please enter the number of packets to be processed (-1 for \"all\")");
		// num_of_packets = Integer.parseInt(System.console().readLine());
		num_of_packets = Integer.parseInt(scan.nextLine());
		if (capt_type == 1) {
			System.out
					.println("Please input the absolute path to the input capture file: ");
			// final String FILENAME = System.console().readLine();
			final String FILENAME = scan.nextLine();
			pcap = Pcap.openOffline(FILENAME, errBuf);
		} else {
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
			// int devNum = Integer.parseInt(System.().readLine());
			int devNum = Integer.parseInt(scan.nextLine());
			// Set default capture interface
			PcapIf device = allDevs.get(devNum);
			// Set maximum size of the packet
			int p_length = 15 * 1024;
			// Capture in "promiscuous" mode
			int flags = Pcap.MODE_PROMISCUOUS;
			// Timeout after X seconds
			System.out
					.println("Please input the timeout duration in seconds: ");
			// int timeout = Integer.parseInt(System.console().readLine()) *
			// 1000;
			int timeout = Integer.parseInt(scan.nextLine()) * 1000;
			// Start live capture
			pcap = Pcap.openLive(device.getName(), p_length, flags, timeout,
					errBuf);
			// Filter at specific port
			System.out
					.println("Please input the port number on which you want to listen: ");
			// int port_num = Integer.parseInt(System.console().readLine());
			int port_num = Integer.parseInt(scan.nextLine());

			scan.close();
			
			// BPF program assists in filtering in the SIP packets
			PcapBpfProgram program = new PcapBpfProgram();
			String expression = "dst port " + port_num + " and (tcp or udp)";

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
		}

		System.out.println("SIP CLF TOOL: PARSING");
		pcap.loop(num_of_packets, jpacketHandler, "jnet");
		pcap.close();
		if (num_of_packets == -1) {
			System.out
					.println("SIP CLF TOOL: FINISHED PARSING ENTIRE PACKET CAPTURE..."
							+ sipPackets + " WERE SIP PACKETS");
		} else {
			System.out.println("SIP CLF TOOL: FINISHED PARSING "
					+ num_of_packets + " PACKETS..." + sipPackets
					+ " WERE SIP PACKETS");
		}
	}

	public static void logGenerator() {
		// optional fields pointer (if there, point to x09 for first entry. if
		// no optional fields, point to terminating line feed 0x0A)

		// ----------------------------------------------------------------------------

		// mandatory Fields
		// fields must appear in the order listed by pointers, each field must
		// be present. max field size = 4096 bytes.
		// each field seperated by single tab (0x09). When written to log,
		// change tab to space (0x20).
		// if field is not present, put a dash. "-"
		// if field fails to parse .. put "?"
		// mandatory fields are all on one line in the log.
		// ***VALUES CURRENTLY SET EQUAL TO EXAMPLE IN RFC 6873 for construction
		// testing
		long timestamp = time_stamp; // 10 bytes, decimal encoded. #seconds
										// since unix epoch
		long fractionalseconds = fractional_seconds; // 3bytes, decimal encoded
														// fractional seconds.
														// timestamp(0x2E
														// ["."])fractionalseconds
		/*
		 * Flags (5 bytes) 1) R =request r = response 2) O= Original D =
		 * Duplicate S = server is stateless 3) S = Sent message R = Recieved
		 * Message 4) U=UDP T = TCP S = SCTP 5) E= Encrypted Message (TLS, DTLS,
		 * etc) U = unencrypted
		 */
		String flags = message_type + "O" + directionality + transport + "U";
		String cseqString = cseq_number + " " + cseq_method; // include cseq
																// number and
																// method name
		String responsestatus; // set to single UTF-8 "-" (0x2D) for requests.
		if (flags.substring(0, 1).equals("R")) {
			responsestatus = "-";
		} else
			responsestatus = status; // put response status here.

		String RURI = request_uri;
		String DstIP = dest_addr; // ipaddres:portnumber --- ipv4:
									// dotted decimal ipv6: mixed case
									// (RFC5952 sect 5)
		String SrcIP = source_addr;
		String ToURI = to_uri;
		String ToTag = to_tag; // if not present, set to "-"
		if (ToTag == null) {
			ToTag = "-";
		}

		String FromURI = from;
		String FromTag = from_tag; // if not present, "-"
		if (FromTag == null) {
			FromTag = "-";
		}
		String Callid = call_id;
		String serverTxn = server_txn;
		String clientTxn = client_txn;

		String mandatory;
		mandatory = timestamp + "." + fractionalseconds + "        " + flags
				+ "        " + cseqString + "        " + responsestatus
				+ "        " + RURI + "        " + DstIP + "        " + SrcIP
				+ "        " + ToURI + "        " + ToTag + "        "
				+ FromURI + "        " + FromTag + "        " + Callid
				+ "        " + serverTxn + "        " + clientTxn;

		String version = "A"; // 1byte
		String recordlength; // 6bytes (length of entire record, from version to
								// terminating line feed 0x0A
		// "," 0x2C between recordlength and pointers.

		// --------------------------------------------------------------------------------------
		// pointers are absolute. starting with beginning of file to first byte
		// of desired entry. each will be >=82
		// pointers. must be given byte length, insert preleading 0s as
		// necessary.
		// all pointers 3 bytes

		// mandatory fields pointers-- no delimiters, 52 character hexadecimal
		// encoded string.
		int pointerstart = 82 + 1;
		String cseqpoint = padZeros(Integer.toHexString(pointerstart));
		String respStatuspoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1));
		String rURIpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1));
		String dstIPpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1));
		String srcIPpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1));
		String toURIpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1));
		String toTagpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1));
		String fromURIpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1));
		String fromTagpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1));
		String callIDpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1));
		String serverTXNpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1 + Callid.length() + 1));
		String clientTXNpoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1 + Callid.length() + 1
				+ serverTxn.length() + 1));
		// optfieldpointer points to linefeed, not first optional field (if
		// there is no optional field)

		String optFieldspoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1 + Callid.length() + 1
				+ serverTxn.length() + 1 + clientTxn.length()));

		String indexPointers = (cseqpoint + respStatuspoint + rURIpoint
				+ dstIPpoint + srcIPpoint + toURIpoint + toTagpoint
				+ fromURIpoint + fromTagpoint + callIDpoint + serverTXNpoint
				+ clientTXNpoint + optFieldspoint).toUpperCase() + "\n";

		// allow
		String allowField = "-";
		if (!(allow.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < allow.length(); i++) {
				char character = allow.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			allowField = "        00@00000000," + allow_length + "," + BEB
					+ ",allow: " + allow.replace("        ", " ");

		}

		// contact
		String contactField = "-";
		if (!(contact.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < contact.length(); i++) {
				char character = contact.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			contactField = "        00@00000000," + contact_length + "," + BEB
					+ ",contact: " + contact.replace("        ", " ");
		}

		// min_expires
		String min_expires_Field = "-";
		if (!(min_expires.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < min_expires.length(); i++) {
				char character = min_expires.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			min_expires_Field = "        00@00000000," + min_expires_length
					+ "," + BEB + ",min-expires: "
					+ min_expires.replace("        ", " ");
		}

		// proxy_authenticate
		String proxy_authenticate_Field = "-";
		if (!(proxy_authenticate.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < proxy_authenticate.length(); i++) {
				char character = proxy_authenticate.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			proxy_authenticate_Field = "        00@00000000,"
					+ proxy_authenticate_length + "," + BEB
					+ ",proxy-authenticate: "
					+ proxy_authenticate.replace("        ", " ");
		}

		// get sdp message body
		String message_field = "\t-";
		if (!(sip_message.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < sip_message.length(); i++) {
				char character = sip_message.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			message_field = "\t01@00000000," + sdp_length + "," + BEB
					+ ",application/sdp: " + sip_message.replace("\t", " ");
		}

		// unsupported
		String unsupportedField = "-";
		if (!(unsupported.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < unsupported.length(); i++) {
				char character = unsupported.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			unsupportedField = "        00@00000000," + unsupported_length
					+ "," + BEB + ",unsupported: "
					+ unsupported.replace("        ", " ");
		}
		// www_authenticate
		String www_authenticate_Field = "-";
		if (!(www_authenticate.equalsIgnoreCase("-"))) {
			BEB = "00";
			for (int i = 0; i < www_authenticate.length(); i++) {
				char character = www_authenticate.charAt(i);
				int ascii = (int) character;
				if ((ascii < 32) || (ascii > 126)) {
					BEB = "01";
					break;
				}
			}
			www_authenticate_Field = "        00@00000000,"
					+ www_authenticate_length + "," + BEB
					+ ",www-authenticate: "
					+ www_authenticate.replace("        ", " ");
		}

		String optional = allowField + contactField + min_expires_Field
				+ proxy_authenticate_Field + unsupportedField
				+ www_authenticate_Field + message_field + "\n";

		// recordlength (assuming no optional fields)
		String prereclength = Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1 + Callid.length() + 1
				+ serverTxn.length() + 1 + clientTxn.length()

				+ optional.length() + 1 /* new linechar */

		);
		recordlength = ("000000".substring(0, 6 - prereclength.length()) + prereclength)
				.toUpperCase();

		// print CLF (pre tab/space switch).
		String CLF = version + recordlength + "," + indexPointers + mandatory + optional;

		if (CLF.length() != (Integer.parseInt(prereclength, 16) - optional
				.length())) {
			// System.out.println("Error: record length discrepancy detected -- mandatory fields");
		}

		writeToFile(CLF);
		firstWrite = NO;

	} // endclass

	// method to append text to a file
	public static void writeToFile(String in) {
		if (firstWrite == YES) {
			try {
				PrintWriter out = new PrintWriter(new BufferedWriter(
						new FileWriter("SIP" + dateAppend + ".log")));
				out.print(in);
				out.close();
			} catch (IOException e) {
				// error writing to file
				System.out.println(e);
			}
		}

		else {
			try {
				PrintWriter out = new PrintWriter(new BufferedWriter(
						new FileWriter("SIP" + dateAppend + ".log", true)));
				out.print(in);
				out.close();
			} catch (IOException e) {
				// error writing to file
				System.out.println(e);
			}
		}

	}

	// create hex string of input String.
	public static String toHex(String arg) throws UnsupportedEncodingException {
		return String.format("%x", new BigInteger(1, arg.getBytes("UTF8")));
	}

	// pad hex string to 4 bytes.
	public static String padZeros(String toPad) {

		return "0000".substring(0, 4 - toPad.length()) + toPad;
	}
}
