#pragma once
#include <map>
#include <set>
#include <variant>
#include <string>
#include <ios>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <libnet.h>

struct EthEndPoint{
    uint8_t eth_addr[ETHER_ADDR_LEN];
    
    EthEndPoint(){}
    EthEndPoint(uint8_t* eth_addr_startpoint);
    bool operator<(const EthEndPoint& other) const;
    bool operator!=(const EthEndPoint& other) const;
};

struct Ipv4EndPoint{
    in_addr_t ip;
    
    Ipv4EndPoint(){}
    Ipv4EndPoint(in_addr_t& ip_rval);
    bool operator<(const Ipv4EndPoint& other) const;
    bool operator!=(const Ipv4EndPoint& other) const;
};

struct TcpUdpEndPoint{
    in_addr_t ip;
    in_port_t port;
    
    TcpUdpEndPoint(){}
    TcpUdpEndPoint(in_addr_t& ip_rval, in_port_t& port_rval);
    bool operator<(const TcpUdpEndPoint& other) const;
    bool operator!=(const TcpUdpEndPoint& other) const;
};

using EndPoint = std::variant<EthEndPoint, Ipv4EndPoint, TcpUdpEndPoint>;

struct EndPointInfo{
    std::string operator()(EthEndPoint& endpoint);
    std::string operator()(Ipv4EndPoint& endpoint);
    std::string operator()(TcpUdpEndPoint& endpoint);
};

// Flow Key definition
struct FlowKey{
    EndPoint src, dst;

    FlowKey(){}
    FlowKey(libnet_ethernet_hdr* eth_hdr);
    FlowKey(libnet_ipv4_hdr* ipv4_hdr);
    FlowKey(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr);
    FlowKey(libnet_ipv4_hdr* ip_hdr, libnet_udp_hdr* udp_hdr);
    FlowKey(EndPoint& src, EndPoint& dst);
    bool operator<(const FlowKey& other) const;
    FlowKey reverseKey();
};

// Flow Value definition
struct FlowVal{
    uint64_t packets, bytes;

    FlowVal(){}
    FlowVal(uint32_t& bytes_rval);
    void update(uint32_t& bytes_rval);
};

using EndPointMap = std::map<EndPoint, std::set<FlowKey>>;
using FlowMap = std::map<FlowKey, FlowVal>;