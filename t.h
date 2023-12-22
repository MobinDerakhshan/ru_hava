//
// Created by mobin on 19/12/23.
//

#ifndef LIMI2_T_H
#define LIMI2_T_H
#include "m.h"
#include <Packet.h>
class t {
public:
  void add(pcpp::MacAddress, pcpp::IPv4Address);
  pcpp::RawPacket *get_packet(pcpp::RawPacket);

private:
  std::vector<m> ms;
};

#endif // LIMI2_T_H
