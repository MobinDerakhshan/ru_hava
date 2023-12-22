//
// Created by mobin on 19/12/23.
//
#include "t.h"

void t::add(pcpp::MacAddress macAddress1, pcpp::IPv4Address iPv4Address1) {
    ms.emplace_back(macAddress1,iPv4Address1);
}

pcpp::RawPacket *t::get_packet(pcpp::RawPacket rawPacket) {
  for (auto m : ms) {
    pcpp::Packet *replyPacket = m.get_packet(rawPacket);
    if (replyPacket != NULL) {
        return replyPacket->getRawPacket();
    }
  }
  return NULL;
}
