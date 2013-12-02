import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.network.Ip4.Flag;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Sdp;
import org.jnetpcap.protocol.voip.Sip;
import org.jnetpcap.protocol.voip.Sip.Fields;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;

public class offlineCapturer {

	public static String to_uri, from, to_tag, from_tag, call_id, cseq_method,
			cseq_number, transport, source_addr, dest_addr, source_port,
			dest_port, status, request_uri, message_type, directionality,
			server_txn, client_txn, allow, contact, min_expires,
			proxy_authenticate, unsupported, www_authenticate, sip_message,
			sdp_length, allow_length, contact_length, min_expires_length,
			proxy_authenticate_length, unsupported_length,
			www_authenticate_length;

	public static BufferedWriter out;
	
	public static long time_stamp, fractional_seconds;

	public static void main(String[] args) throws Exception {

		// else if(captureType.equalsIgnoreCase("N")){

		out = new BufferedWriter(new FileWriter("LogFile.txt"));
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis

		final String FILENAME = "C:/Users/oaboyko/Downloads/aaa.pcap";
		final StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf); // Error is stored in errbuf if any
			return;
		}

		// System.out.println("How many packets do you want to parse?");
		int numOfPackets = 223; // Integer.parseInt(System.console().readLine());

		pcap.loop(numOfPackets, new JPacketHandler<StringBuilder>() {

			Udp udp = new Udp();
			Tcp tcp = new Tcp();
			Sip sip = new Sip();
			Ip4 ip4 = new Ip4();
			Ip6 ip6 = new Ip6();
			Sdp sdp = new Sdp();
			
			private Map<String,String> Sources = new HashMap<String,String>();
			private Map<String,String> Destinations = new HashMap<String,String>();
			private int srv_txn = 0;
			private int clt_txn = 0;

			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				to_uri = "-";
				from = "-";
				to_tag = "-";
				from_tag = "-";
				status = "-";
				call_id = "-";
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

				System.out.println("************BEGIN SIP********************");
				
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
				System.out.println("CLF TIME STAMP\t" + time_stamp + "."
						+ fractional_seconds);

				if (packet.hasHeader(sip)) {
					String temp;
					Pattern pattern;
					Matcher matcher;

					// Get the From URI
					temp = sip.fieldValue(Sip.Fields.From);
					pattern = Pattern
							.compile("<(.*);?.*>;tag=(.*)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						from = matcher.group(1);
						from_tag = matcher.group(2);
					}
					if (from == null || from_tag == null) {
						System.out.println("Malformed Packet on the From Tag");
					}
					System.out.println("CLF FROM\t" + from + "\nCLF FROM TAG\t"
							+ from_tag);

					// Get the To URI
					temp = sip.fieldValue(Sip.Fields.To);
					pattern = Pattern.compile("<(.*)>");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						to_uri = matcher.group(1);
					}
					System.out.println("CLF TO\t\t" + to_uri);

					// Get the To Tag
					pattern = Pattern.compile("tag=(.*)");
					matcher = pattern.matcher(temp);
					while (matcher.find()) {
						to_tag = matcher.group(1);
					}
					if (to_tag == null) {
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
					//System.out.println("SIP: " + sip_header);

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
						message_type = "R";
						System.out.println("CLF Message Type:\t "
								+ message_type);
					} else {
						message_type = "r";
						System.out.println("CLF Message Type:\t "
								+ message_type);
					}

				}
				else{
					return;
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
					System.out.println(sip_message);

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
						transport = "-";
						source_port = "-";
						dest_port = "-";
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
						source_addr = "-";
						dest_addr = "-";
					}
				}
				System.out.println("CLF Source\t" + source_addr);
				System.out.println("CLF Destin\t" + dest_addr);
				
				/*if(Sources.get(source_addr + ":" + source_port) != null && source_addr != ip_local){
					server_txn = Sources.get(source_addr + ":" + source_port);
				}
				else{
					Sources.put(source_addr + ":" + source_port, "s-tr-" + Integer.toString(srv_txn++));
				}*/
				
				//Get the server and client Txn
				server_txn = "s-tr-" + ip_local;
				
				if(Destinations.get(dest_addr + ":" + dest_port) != null && dest_addr != ip_local){
					client_txn = Destinations.get(dest_addr + ":" + dest_port);
				}
				else{
					Destinations.put(dest_addr + ":" + dest_port, "c-tr-" + Integer.toString(clt_txn++));
					client_txn = Destinations.get(dest_addr + ":" + dest_port);
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

				System.out
						.println("__________________________________________________________");
				logGenerator();
			}
		}, errbuf);

		out.close();
		
		pcap.close();
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

		//.replace("", " ")
		
		String mandatory;
		mandatory = timestamp + "." + fractionalseconds + "	" + flags + "	"
				+ cseqString + "	" + responsestatus + "	" + RURI + "	" + DstIP
				+ "	" + SrcIP + "	" + ToURI + "	" + ToTag + "	" + FromURI + "	"
				+ FromTag + "	" + Callid + "	" + serverTxn + "	" + clientTxn
				;
		// System.out.print(mandatory);

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
		// optfieldpointer points to linefeed, not first optional field (if there is no optional field)
		
		String optFieldspoint = padZeros(Integer.toHexString(pointerstart
				+ cseqString.length() + 1 + responsestatus.length() + 1
				+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
				+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
				+ 1 + FromTag.length() + 1 + Callid.length() + 1
				+ serverTxn.length() + 1 + clientTxn.length()));

		String indexPointers = (cseqpoint + respStatuspoint + rURIpoint
				+ dstIPpoint + srcIPpoint + toURIpoint + toTagpoint
				+ fromURIpoint + fromTagpoint + callIDpoint + serverTXNpoint
				+ clientTXNpoint + optFieldspoint + "\n").toUpperCase();
		// System.out.println(indexPointers);




		// Index pointer test printing:
		// System.out.println(cseqpoint);
		// System.out.println(respStatuspoint);
		// System.out.println(rURIpoint);
		// System.out.println(dstIPpoint);
		// System.out.println(srcIPpoint);
		// System.out.println( toURIpoint);
		// System.out.println(toTagpoint);
		// System.out.println( fromURIpoint);
		// System.out.println(fromTagpoint);
		// System.out.println(callIDpoint);
		// System.out.println(serverTXNpoint);
		// System.out.println(clientTXNpoint);
		// System.out.println(optFieldspoint);

		// -----------------------------------------------------------------------------------
		// Optional Fields
				// 00@00000000,length,00,value
				// generated starting at line 300
				
				
				//allow
				String allowField = "\t-";
				if (!(allow.equalsIgnoreCase("-"))) {
					
					allowField = "\t00@00000000," + allow_length + ",00,allow: " + allow.replace("\t"," ");
					
				}
					
				//contact
				String contactField = "\t-";
				if (!(contact .equalsIgnoreCase("-"))) {
					contactField = "\t00@00000000," + contact_length + ",00,contact: " + contact.replace("\t"," ");
				}
				
				// min_expires
				String min_expires_Field = "\t-";
				if (!(min_expires.equalsIgnoreCase("-"))) {
					min_expires_Field = "\t00@00000000," + min_expires_length+ ",00,min-expires: " + min_expires.replace("\t"," ");
				}
				
				String message_field = "\t-";
				if (!(sip_message.equalsIgnoreCase("-"))) {
					message_field = "\t01@00000000," + sdp_length+ ",00,application/sdp: " + sip_message.replace("\t"," ");
				}
				
				//proxy_authenticate
				String proxy_authenticate_Field = "\t-";	
				if (!(proxy_authenticate.equalsIgnoreCase("-"))) {
					proxy_authenticate_Field= "\t00@00000000," + proxy_authenticate_length + ",00,proxy-authenticate: " + proxy_authenticate.replace("\t"," ");
				}
				
				//unsupported
				String unsupportedField = "\t-";		
				if (!(unsupported.equalsIgnoreCase("-"))) {
					unsupportedField = "\t00@00000000," + unsupported_length + ",00,unsupported: " +unsupported.replace("\t"," ");
				}
				//www_authenticate
				String www_authenticate_Field = "\t-";
				if (!(www_authenticate.equalsIgnoreCase("-"))) {
					www_authenticate_Field = "\t00@00000000," + www_authenticate_length + ",00,www-authenticate: " + www_authenticate.replace("\t"," ");
				}
				
				String optional = allowField+ contactField+min_expires_Field + proxy_authenticate_Field+unsupportedField+www_authenticate_Field + message_field;
				
				
				


				// recordlength (assuming no optional fields)
				String prereclength = Integer.toHexString(  pointerstart
						+ cseqString.length() + 1 + responsestatus.length() + 1
						+ RURI.length() + 1 + DstIP.length() + 1 + SrcIP.length() + 1
						+ ToURI.length() + 1 + ToTag.length() + 1 + FromURI.length()
						+ 1 + FromTag.length() + 1 + Callid.length() + 1
						+ serverTxn.length() + 1 + clientTxn.length()   
						
						
						+   optional.length() +1 /* new linechar*/
						
						);
				recordlength = ("000000".substring(0, 6 - prereclength.length()) + prereclength)
						.toUpperCase();
				
				

				
				// print CLF (pre tab/space switch).
				String CLF = (version + recordlength + "," + indexPointers + mandatory +optional +"\n");
				//System.out.println(CLF);

				
//				if (CLF.length() != ( Integer.parseInt(prereclength, 16) - optional.length())) {
//					System.out.println("error, record length discrpency detected -- mandatory fields");
//				}
				
		        try {		           
		                out.write(CLF);
		        } catch (IOException e) {
		        	System.out.println("error writing to file");
		        }
				
			} // endclass
			// create hex string of input String.
			public static String toHex(String arg) throws UnsupportedEncodingException {
				return String.format("%x", new BigInteger(1, arg.getBytes("UTF8")));
			}

			// pad hex string to 4 bytes.
			public static String padZeros(String toPad) {

				return "0000".substring(0, 4 - toPad.length()) + toPad;
			}

		}