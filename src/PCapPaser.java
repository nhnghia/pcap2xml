/**
 * Dec 5, 2012 3:11:18 PM
 * @author nhnghia
 */

import java.io.IOException;
import java.text.ParseException;

import edu.gatech.sjpcap.IPPacket;
import edu.gatech.sjpcap.Packet;
import edu.gatech.sjpcap.PcapParser;
import edu.gatech.sjpcap.TCPPacket;
import edu.gatech.sjpcap.UDPPacket;
import fr.lri.pass.pcap2xml.SIPPacket;
import fr.lri.schora.util.Broadcast;
import fr.lri.schora.util.Debug;

public class PCapPaser {

	public static void main(String[] args) throws ParseException {
		if (fr.lri.schora.util.Debug.isDebug()){
			args = new String[1];
			args[0] = "/Users/nhnghia/these/SIPP/pcap/lan.client.pcap";
			//args[1] = "8083";
		}
		
		if (args.length != 1 && args.length != 2){
			System.out.println("Usage: java -jar pcapPaser.jar file [port]");
			System.out.println("   + file: pcap file");
			System.out.println("   + port: port where output is broadcasted, if it is omitted result is output to console");
			return;
		}
		String file = args[0];
		
		PcapParser pcapParser = new PcapParser();
		if (pcapParser.openFile(file) < 0) {
			fr.lri.schora.util.Print.error("Failed to open " + file + ".");
			return;
		}

		Broadcast broadcast = null;
		if (args.length == 2){
			broadcast = new Broadcast();
			try {
				broadcast.setPort(Integer.parseInt(args[1]));
			} catch (NumberFormatException e) {
				fr.lri.schora.util.Print.error("port is incorrect");
				Debug.print(e);
				return;
			} catch (IOException e) {
				fr.lri.schora.util.Print.error(e.getMessage());
				Debug.print(e);
				return;
			}
		}
		
		Packet packet = pcapParser.getPacket();
		
		
		
		while (packet != Packet.EOF) {
			if (!(packet instanceof IPPacket)) {
				packet = pcapParser.getPacket();
				continue;
			}

			IPPacket ipPacket = (IPPacket) packet;
			if (ipPacket instanceof UDPPacket) {
				SIPPacket sipPacket = new SIPPacket((UDPPacket)packet);
				
				String msg = sipPacket.toXMLString();
				if (broadcast != null)
					broadcast.broadcast(msg);
				else
					System.out.println(msg);
				//break;
			}
			if (ipPacket instanceof TCPPacket) {
				TCPPacket tcpPacket = (TCPPacket) ipPacket;
		
			}

			packet = pcapParser.getPacket();
		}
		
		broadcast.close();
		pcapParser.closeFile();
	}
}
