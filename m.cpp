//
// Created by mobin on 18/12/23.
//

#include "m.h"

m::m(pcpp::MacAddress macAddress1, pcpp::IPv4Address iPv4Address1) {
  macAddress = macAddress1;
  iPv4Address = iPv4Address1;
}

pcpp::Packet *m::get_packet(pcpp::RawPacket rawPacket) {
  pcpp::Packet parsedPacket(&rawPacket);
  if (!for_me(parsedPacket)) {
    return NULL;
  } else if (parsedPacket.isPacketOfType(pcpp::ARP)) {
    return arp_reply(parsedPacket);
  } else if (parsedPacket.isPacketOfType(pcpp::ICMP)) {
    return ping_reply(parsedPacket);
  } else {
    return NULL;
  }
}

pcpp::Packet *m::arp_reply(pcpp::Packet packet) {
  pcpp::Packet *replyPacket = new pcpp::Packet;
  pcpp::EthLayer *ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
  pcpp::ArpLayer *arpLayer = packet.getLayerOfType<pcpp::ArpLayer>();
  if (!arpLayer->isRequest()) {

    return NULL;
  }
  pcpp::EthLayer newEthLayer = makeEthLReply(ethLayer);
  pcpp::ArpLayer newArpLayer = makeArpLReply(arpLayer);

  replyPacket->addLayer(&newEthLayer);
  replyPacket->addLayer(&newArpLayer);
  replyPacket->computeCalculateFields();

  return replyPacket;
}

pcpp::Packet *m::ping_reply(pcpp::Packet packet) {
  pcpp::Packet *replyPacket = new pcpp::Packet;
  pcpp::EthLayer *ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
  pcpp::IPv4Layer *iPv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
  pcpp::IcmpLayer *icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
  if (!icmpLayer->isMessageOfType(pcpp::ICMP_ECHO_REQUEST)) {
    return NULL;
  }
  pcpp::EthLayer replyEthLayer = makeEthLReply(ethLayer);
  pcpp::IPv4Layer replyIpv4Layer = makeIPv4LReply(iPv4Layer);
  pcpp::IcmpLayer replyIcmpLayer = makeIcmpLReply(icmpLayer);

  replyPacket->addLayer(&replyEthLayer);
  replyPacket->addLayer(&replyIpv4Layer);
  replyPacket->addLayer(&replyIcmpLayer);
  replyPacket->computeCalculateFields();

  return replyPacket;
}

pcpp::EthLayer m::makeEthLReply(pcpp::EthLayer *requestEthLayer) {
  pcpp::EthLayer replyEthLayer(macAddress, requestEthLayer->getSourceMac());
  return replyEthLayer;
}

pcpp::IPv4Layer m::makeIPv4LReply(pcpp::IPv4Layer *requestIpv4Layer) {
  pcpp::IPv4Layer replyIpv4Layer(iPv4Address,
                                 requestIpv4Layer->getSrcIPv4Address());
  replyIpv4Layer.getIPv4Header()->timeToLive = 64;
  replyIpv4Layer.computeCalculateFields();
  return replyIpv4Layer;
}

pcpp::ArpLayer m::makeArpLReply(pcpp::ArpLayer *requestArpLayer) {
  pcpp::ArpLayer replyArpLayer(pcpp::ARP_REPLY, macAddress,
                               requestArpLayer->getSenderMacAddress(),
                               iPv4Address, requestArpLayer->getSenderIpAddr());
  return replyArpLayer;
}

pcpp::IcmpLayer m::makeIcmpLReply(pcpp::IcmpLayer *requestIcmpLayer) {
  pcpp::IcmpLayer replyIcmpLayer;
  pcpp::icmp_echo_request *icmpEchoRequest =
      requestIcmpLayer->getEchoRequestData();
  pcpp::icmp_echo_hdr *icmpEchoHdr = icmpEchoRequest->header;
  uint16_t idReply = icmpEchoHdr->id;
  uint16_t sequenceReply = icmpEchoHdr->sequence;
  int a, b;
  a = idReply / 256;
  b = idReply - (a * 256);
  a = b * 256 + a;
  int a1, b1;
  a1 = sequenceReply / 256;
  b1 = sequenceReply - (a1 * 256);
  a1 = b1 * 256 + a1;
  replyIcmpLayer.setEchoReplyData(a, a1, icmpEchoHdr->timestamp,
                                  icmpEchoRequest->data,
                                  icmpEchoRequest->dataLength);

  replyIcmpLayer.computeCalculateFields();
  return replyIcmpLayer;
}

bool m::for_me(pcpp::Packet packet) {
  if (packet.isPacketOfType(pcpp::ARP)) {
    pcpp::IPv4Address desIpv4 =
        packet.getLayerOfType<pcpp::ArpLayer>()->getTargetIpAddr();
    return for_me(desIpv4);
  } else if (packet.isPacketOfType(pcpp::ICMP)) {
    pcpp::MacAddress desMac =
        packet.getLayerOfType<pcpp::EthLayer>()->getDestMac();
    pcpp::IPv4Address desIpv4 =
        packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
    return for_me(desMac) || for_me(desIpv4);
  } else {
    return false;
  }
}

bool m::for_me(pcpp::MacAddress macAddress1) {
  if (macAddress1 == macAddress) {
    return true;
  } else {
    return false;
  }
}

bool m::for_me(pcpp::IPv4Address iPv4Address1) {
  if (iPv4Address1 == iPv4Address) {
    return true;
  } else {
    return false;
  }
}
