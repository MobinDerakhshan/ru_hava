//
// Created by mobin on 18/12/23.
//

#ifndef LIMI2_M_H
#define LIMI2_M_H
#include "ArpLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IcmpLayer.h"
#include "Packet.h"
class m {
public:
  m(pcpp::MacAddress, pcpp::IPv4Address);
  pcpp::Packet *get_packet(pcpp::RawPacket);

private:
  pcpp::MacAddress macAddress;
  pcpp::IPv4Address iPv4Address;

  pcpp::Packet *ping_reply(pcpp::Packet);
  pcpp::Packet *arp_reply(pcpp::Packet);

  pcpp::IcmpLayer makeIcmpLReply(pcpp::IcmpLayer*);
  pcpp::EthLayer makeEthLReply(pcpp::EthLayer*);
  pcpp::IPv4Layer makeIPv4LReply(pcpp::IPv4Layer*);
  pcpp::ArpLayer makeArpLReply(pcpp::ArpLayer*);

  bool for_me(pcpp::Packet);
  bool for_me(pcpp::MacAddress);
  bool for_me(pcpp::IPv4Address);
};

#endif // LIMI2_M_H
