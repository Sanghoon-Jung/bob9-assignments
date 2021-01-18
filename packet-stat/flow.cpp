#include "flow.h"

EthEndPoint::EthEndPoint(uint8_t* eth_addr_startpoint){
    std::copy(eth_addr_startpoint, eth_addr_startpoint + ETHER_ADDR_LEN, this->eth_addr);
}

bool EthEndPoint::operator<(const EthEndPoint& other) const{
    for(std::size_t i = 0; i < ETHER_ADDR_LEN; i++){
        if(this->eth_addr[i] != other.eth_addr[i])
            return this->eth_addr[i] < other.eth_addr[i];
    }
    return false;
}

bool EthEndPoint::operator!=(const EthEndPoint& other) const{
    for(std::size_t i = 0; i < ETHER_ADDR_LEN; i++){
        if(this->eth_addr[i] != other.eth_addr[i])
            return true;
    }
    return false;
}

Ipv4EndPoint::Ipv4EndPoint(in_addr_t& ip_rval) : ip(ip_rval){}

bool Ipv4EndPoint::operator<(const Ipv4EndPoint& other) const{
    return this->ip < other.ip;
}

bool Ipv4EndPoint::operator!=(const Ipv4EndPoint& other) const{
    return this->ip != other.ip;
}

TcpUdpEndPoint::TcpUdpEndPoint(in_addr_t& ip_rval, in_port_t& port_rval)
    : ip(ip_rval), port(port_rval){}

bool TcpUdpEndPoint::operator<(const TcpUdpEndPoint& other) const{
    if(this->ip != other.ip) return this->ip < other.ip;
    return this->port < other.port;
}

bool TcpUdpEndPoint::operator!=(const TcpUdpEndPoint& other) const{
    if(this->ip != other.ip) return true;
    return this->port != other.port;
}

std::string EndPointInfo::operator()(EthEndPoint& endpoint){
    std::ostringstream hex_sstream;
    hex_sstream << "Address = ";
    for(std::size_t i = 0; i < ETHER_ADDR_LEN; i++){
        hex_sstream << std::hex << std::setw(2) << std::setfill('0') 
        << static_cast<int>(endpoint.eth_addr[i]) << ":";
    }
    std::string result = hex_sstream.str();
    result.pop_back();
    return result;
}

std::string EndPointInfo::operator()(Ipv4EndPoint& endpoint){
    char inet_p[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &endpoint.ip, inet_p, INET_ADDRSTRLEN);
    return "Address = " + std::string(inet_p);
}

std::string EndPointInfo::operator()(TcpUdpEndPoint& endpoint){
    std::ostringstream osstream;
    char inet_p[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &endpoint.ip, inet_p, INET_ADDRSTRLEN);
    osstream << "Address = " << inet_p << ", Port = " << ntohs(endpoint.port);
    return osstream.str();
}

FlowKey::FlowKey(libnet_ethernet_hdr* eth_hdr)
    : src(EthEndPoint(eth_hdr->ether_shost)), dst(EthEndPoint(eth_hdr->ether_dhost)){}
FlowKey::FlowKey(libnet_ipv4_hdr* ip_hdr)
    : src(Ipv4EndPoint(ip_hdr->ip_src.s_addr)), dst(Ipv4EndPoint(ip_hdr->ip_dst.s_addr)){}
FlowKey::FlowKey(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr)
    : src(TcpUdpEndPoint(ip_hdr->ip_src.s_addr, tcp_hdr->th_sport)), 
        dst(TcpUdpEndPoint(ip_hdr->ip_dst.s_addr, tcp_hdr->th_dport)){}
FlowKey::FlowKey(libnet_ipv4_hdr* ip_hdr, libnet_udp_hdr* udp_hdr)
    : src(TcpUdpEndPoint(ip_hdr->ip_src.s_addr, udp_hdr->uh_sport)), 
        dst(TcpUdpEndPoint(ip_hdr->ip_dst.s_addr, udp_hdr->uh_dport)){}
FlowKey::FlowKey(EndPoint& src_, EndPoint& dst_) : src(src_), dst(dst_){}

bool FlowKey::operator<(const FlowKey& other) const{
    if(this->src != other.src) return this->src < other.src;
    return this->dst < other.dst;
}

FlowKey FlowKey::reverseKey(){
    return FlowKey(this->dst, this->src);
}

FlowVal::FlowVal(uint32_t& bytes_rval) : packets(1), bytes(bytes_rval){}

void FlowVal::update(uint32_t& bytes){
    this->packets += 1;
    this->bytes += bytes;
}