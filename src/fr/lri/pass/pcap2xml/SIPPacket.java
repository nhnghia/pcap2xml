/**
 * Dec 6, 2012 3:49:06 PM
 * @author nhnghia
 */
package fr.lri.pass.pcap2xml;

import java.text.ParseException;

import edu.gatech.sjpcap.UDPPacket;
import gov.nist.javax.sip.header.Via;
import gov.nist.javax.sip.message.SIPMessage;
import gov.nist.javax.sip.message.SIPRequest;
import gov.nist.javax.sip.message.SIPResponse;
import gov.nist.javax.sip.parser.*;

public class SIPPacket extends UDPPacket {

	/**
	 * @param packet
	 */
	SIPMessage msg;

	public SIPPacket(UDPPacket packet) throws ParseException {
		super(packet);
		// TODO Auto-generated constructor stub
		this.src_port = packet.src_port;
		this.dst_port = packet.dst_port;
		this.data = packet.data;

		try{
			
			StringMsgParser smp = new StringMsgParser();
			msg = smp.parseSIPMessage(this.data, false, false, null);
		}catch(ParseException ex){
			ex.printStackTrace();
		}
	}

	public String toXMLString() {
		String src = String.format("%s:%d", this.src_ip.getHostAddress(),
				this.src_port);
		String dst = String.format("%s:%d", this.dst_ip.getHostAddress(),
				this.dst_port);
		long tstamp = this.timestamp;

		String body;

		if (msg instanceof SIPRequest) {
			SIPRequest req = (SIPRequest) msg;

			body = String.format("<method>%s</method>", req.getMethod());
			if (req.getRequestURI() != null){
				body += String.format("\n  <requestURI>%s</requestURI>", req.getRequestURI().toString());
			}
		} else {
			SIPResponse res = (SIPResponse) msg;

			body = String.format("<statusCode>%d</statusCode>",
					res.getStatusCode());
		}
		
		body += String.format("\n  <from>" +
				"\n    <tag>%s</tag>" +
				"\n    <address>" +
				"\n      <displayName>%s</displayName>" +
				"\n      <URI>%s</URI>" +
				"\n    </address>" +
				"\n  </from>", 
				msg.getFromTag(),
				msg.getFrom().getAddress().getDisplayName(),
				msg.getFrom().getAddress().getURI().toString());
		
		body += String.format("\n  <to> " +
				"\n    <tag>%s</tag>" +
				"\n    <address>" +
				"\n      <displayName>%s</displayName>" +
				"\n      <URI>%s</URI>" +
				"\n    </address>" +
				"\n  </to>", 
				msg.getToTag(), 
				msg.getTo().getAddress().getDisplayName(),
				msg.getTo().getAddress().getURI().toString());
		
		body += String.format("\n  <time>%d</time>", tstamp);

		body += String
				.format("\n  <cSeq>\n    <method>%s</method>\n    <seq>%d</seq>\n  </cSeq>",
						msg.getCSeq().getMethod(), msg.getCSeq().getSeqNumber());

		if (msg.getCallId() != null)
			body += String.format("\n  <callId>%s</callId>", msg.getCallId().getCallId().trim());
		if (msg.getMaxForwards() != null)
			body += String.format("\n  <maxForwards>%d</maxForwards>", msg
					.getMaxForwards().getMaxForwards());
		if (msg.getViaHeaders() != null){
			body += "\n  <vias>";
			int n = msg.getViaHeaders().size();
			for (int i=0; i<n; i++){
				Via via = msg.getViaHeaders().get(i);
				body += String.format("\n    <via>" +
						"\n      <branch>%s</branch>" +
						"\n      <transport>%s</transport>" +
						"\n      <ip>%s</ip>" +
						"\n      <port>%d</port>" +
						"\n    </via>",  
						via.getBranch(),
						via.getTransport(),
						via.getHost(),
						via.getPort());
			}
			body += "\n  </vias>";
		}
		
		return String.format("<message tstamp=\"%d\" source=\"%s\" destination=\"%s\">\n  %s\n</message>\n",
				tstamp,
				src, 
				dst,
				body);

	}
}