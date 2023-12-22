#include "m.h"
#include "t.h"
#include <iostream>
#include <pcap.h>
#include <pcapplusplus/Packet.h>
int main(int argc, char *argv[]) {

  char errbuff[PCAP_ERRBUF_SIZE];
  char *dev1_name = argv[1], *dev2_name = argv[2];

  pcap_t *dev1, *dev2;
  dev1 = pcap_open_live(dev1_name, BUFSIZ, 1, -1, errbuff);
  if (dev1 == NULL) {
    std::cout << errbuff << std::endl;
  }
  dev2 = pcap_open_live(dev2_name, BUFSIZ, 1, -1, errbuff);
  if (dev2 == NULL) {
    std::cout << errbuff << std::endl;
  }

  t t1;
  t1.add(pcpp::MacAddress("10:66:43:11:22:33"), pcpp::IPv4Address("10.0.0.5"));
  t1.add(pcpp::MacAddress("18:53:49:61:32:53"), pcpp::IPv4Address("10.0.0.12"));

  while (true) {
    const u_char *packet1, *packet2;
    struct pcap_pkthdr *packet_header1, *packet_header2;

    if (pcap_next_ex(dev1, &packet_header1, &packet1)) {
      pcpp::RawPacket rawPacket(packet1, packet_header1->len,
                                packet_header1->ts, false);
      pcpp::RawPacket *replyRawPacket = t1.get_packet(rawPacket);

      if (replyRawPacket != NULL) {
        pcap_sendpacket(dev1, replyRawPacket->getRawData(), replyRawPacket->getRawDataLen());
      } else {
        pcap_sendpacket(dev2, packet1, int(packet_header1->len));
      }
    }

    if (pcap_next_ex(dev2, &packet_header2, &packet2)) {
      pcpp::RawPacket rawPacket(packet2, packet_header2->len,
                                packet_header2->ts, false);
      pcpp::RawPacket *replyRawPacket = t1.get_packet(rawPacket);

      if (replyRawPacket != NULL) {
        pcap_sendpacket(dev2, replyRawPacket->getRawData(), replyRawPacket->getRawDataLen());
      } else {
        pcap_sendpacket(dev1, packet2, int(packet_header2->len));
      }
    }
  }

  pcap_close(dev1);
  pcap_close(dev2);
  return 0;
}
