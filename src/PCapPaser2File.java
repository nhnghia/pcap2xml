/**
 * Dec 5, 2012 3:11:18 PM
 * @author nhnghia
 */

import java.text.ParseException;

import edu.gatech.sjpcap.IPPacket;
import edu.gatech.sjpcap.Packet;
import edu.gatech.sjpcap.PcapParser;
import edu.gatech.sjpcap.TCPPacket;
import edu.gatech.sjpcap.UDPPacket;
import fr.lri.pass.pcap2xml.SIPPacket;

public class PCapPaser2File {

	static void help(){
		System.out.println("Usage: java -jar pcapPaser.jar pcapFile [from] to");
		System.out.println("   + pcapFile: path to *.pcap file");
		System.out.println("   + from    : ");
		System.out.println("   + to      : ");
	}
	
	public static void main(String[] args) throws ParseException {
		if (fr.lri.schora.util.Debug.isDebug()){
			args = new String[3];
			args[0] = "/Users/nhnghia/these/workshop/SIPP/pcap/Sipp_Traces_320000.pcap";
			args[1] = "1";
			args[2] = "500";
		}
		
		if (args.length != 2 && args.length != 3){
			help();
			return;
		}
		String file = args[0];
		
		PcapParser pcapParser = new PcapParser();
		if (pcapParser.openFile(file) < 0) {
			fr.lri.schora.util.Print.error("Failed to open " + file + ".");
			return;
		}
		int from = 1;
		int to = 0;
		if (args.length == 3){
			from = Integer.parseInt(args[1]);
			to = Integer.parseInt(args[2]);
		}
		else{
			to = Integer.parseInt(args[1]);
		}
		if (to < from){
			fr.lri.schora.util.Print.error("from > to");
			help();
			return;
		}
		
		Packet packet = pcapParser.getPacket();
		
		
		int i=1;
		while (packet != Packet.EOF && i <= from) {
			packet = pcapParser.getPacket();
			i++;
		}
		
		if (packet == Packet.EOF){
			fr.lri.schora.util.Print.error("number of packet in pcapFile is not sufficient");
			help();
			return;
		}
		
		while (packet != Packet.EOF && i<= to) {

			IPPacket ipPacket = (IPPacket) packet;
			if (ipPacket instanceof UDPPacket) {
				SIPPacket sipPacket = new SIPPacket((UDPPacket)packet);
				
				String msg = sipPacket.toXMLString();
				System.out.println(msg);
			}
			i++;
			packet = pcapParser.getPacket();
		}
		pcapParser.closeFile();
	}
}
