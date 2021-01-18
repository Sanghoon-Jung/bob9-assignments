#include "pktstat.h"

FlowMap eth_flows, ipv4_flows, tcp_flows, udp_flows;
EndPointMap eth_endpoints, ipv4_endpoints, tcp_endpoints, udp_endpoints;

void Enroller::enrollFlow(FlowMap& flow_map, FlowKey& flow_key, uint32_t& pkt_len){
    if(flow_map.contains(flow_key)) flow_map[flow_key].update(pkt_len);
    else flow_map.insert(std::make_pair(flow_key, FlowVal(pkt_len)));
}

void Enroller::enrollEndPoint(EndPointMap& endpoint_map, EndPoint& endpoint, FlowKey& flow_key){
    if(endpoint_map.contains(endpoint) && !endpoint_map[endpoint].contains(flow_key))
        endpoint_map[endpoint].insert(flow_key);
    else endpoint_map.insert(std::make_pair(endpoint, std::set<FlowKey> {flow_key}));
}

Enroller::Enroller(const uint8_t* pkt_base, uint32_t& pkt_len){
    this->pkt_ptr = const_cast<uint8_t*>(pkt_base);

    libnet_ethernet_hdr* eth_hdr = reinterpret_cast<libnet_ethernet_hdr*>(this->pkt_ptr);
    FlowKey eth_key(eth_hdr);
    this->enrollFlow(eth_flows, eth_key, pkt_len);
    this->enrollEndPoint(eth_endpoints, eth_key.src, eth_key);
    this->enrollEndPoint(eth_endpoints, eth_key.dst, eth_key);
    this->pkt_ptr += LIBNET_ETH_H;

    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
        libnet_ipv4_hdr* ip_hdr = reinterpret_cast<libnet_ipv4_hdr*>(this->pkt_ptr);
        FlowKey ip_key(ip_hdr);
        this->enrollFlow(ipv4_flows, ip_key, pkt_len);
        this->enrollEndPoint(ipv4_endpoints, ip_key.src, ip_key);
        this->enrollEndPoint(ipv4_endpoints, ip_key.dst, ip_key);
        this->pkt_ptr += ip_hdr->ip_hl << 2;

        if(ip_hdr->ip_p == IPPROTO_TCP){
            libnet_tcp_hdr* tcp_hdr = reinterpret_cast<libnet_tcp_hdr*>(this->pkt_ptr);
            FlowKey tcp_key(ip_hdr, tcp_hdr);
            this->enrollFlow(tcp_flows, tcp_key, pkt_len);
            this->enrollEndPoint(tcp_endpoints, tcp_key.src, tcp_key);
            this->enrollEndPoint(tcp_endpoints, tcp_key.dst, tcp_key);
        }
        else if(ip_hdr->ip_p == IPPROTO_UDP){
            libnet_udp_hdr* udp_hdr = reinterpret_cast<libnet_udp_hdr*>(this->pkt_ptr);
            FlowKey udp_key(ip_hdr, udp_hdr);
            this->enrollFlow(udp_flows, udp_key, pkt_len);
            this->enrollEndPoint(udp_endpoints, udp_key.src, udp_key);
            this->enrollEndPoint(udp_endpoints, udp_key.dst, udp_key);
        }
    }
}

void StatViewer::showStatistics(){
    std::cout << "\n********** Statistical Information (Endpoints) **********\n\n";
    std::cout << "1. Ethernet Endpoints\n\n";
    this->showEndpoints(eth_endpoints, eth_flows);
    std::cout << "2. Ipv4 Endpoints\n\n";
    this->showEndpoints(ipv4_endpoints, ipv4_flows);
    std::cout << "3. TCP Endpoints\n\n";
    this->showEndpoints(tcp_endpoints, tcp_flows);
    std::cout << "4. UDP Endpoints\n\n";
    this->showEndpoints(udp_endpoints, udp_flows);
    
    std::cout << "\n********** Statistical Information (Conversations) **********\n\n";
    std::cout << "1. Ethernet Conversations\n\n";
    this->showConversations(eth_flows);
    std::cout << "2. Ipv4 Conversations\n\n";
    this->showConversations(ipv4_flows);
    std::cout << "3. TCP Conversations\n\n";
    this->showConversations(tcp_flows);
    std::cout << "4. UDP Conversations\n\n";
    this->showConversations(udp_flows);
}

void StatViewer::showEndpoints(EndPointMap& endpoint_map, FlowMap& flow_map){
    int endpoint_counter = 0;
    for(auto it = endpoint_map.begin(); it != endpoint_map.end(); it++){
        uint64_t tx_packets = 0, tx_bytes = 0;
        uint64_t rx_packets = 0, rx_bytes = 0;
        EndPoint endpoint = it->first;
        std::set<FlowKey> flow_key_set(it->second);
        
        for(auto flow_key : flow_key_set){
            if(flow_key.dst != endpoint){
                tx_packets += flow_map[flow_key].packets;
                tx_bytes += flow_map[flow_key].bytes;
            }
            else{
                rx_packets += flow_map[flow_key].packets;
                rx_bytes += flow_map[flow_key].bytes;
            }
        }

        std::cout << "[ EndPoint #" << ++endpoint_counter << " ]" << std::endl;
        std::cout << std::visit(EndPointInfo(), endpoint) << std::endl;
        std::cout << "total - packets: " << tx_packets + rx_packets
            << ", bytes: " << tx_bytes + rx_bytes << std::endl;
        std::cout << "Tx - packets: " << tx_packets << ", bytes: " << tx_bytes << std::endl;
        std::cout << "Rx - packets: " << rx_packets << ", bytes: " << rx_bytes << std::endl << std::endl;
    }
}

void StatViewer::showConversations(FlowMap flow_map){
    
    int conversation_counter = 0;
    for(auto it = flow_map.begin(); it != flow_map.end(); it++){
        auto original_key = it->first;
        auto original_val = it->second;
        
        auto reverse_key = original_key.reverseKey();
        auto reverse_val = flow_map[reverse_key];

        std::cout << "[ Converastion #" << ++conversation_counter << " ]" << std::endl;
        std::cout << "A: " << std::visit(EndPointInfo(), original_key.src) << std::endl;
        std::cout << "B: " << std::visit(EndPointInfo(), original_key.dst) << std::endl;
        std::cout << "total - packets: " << original_val.packets + reverse_val.packets
            << ", bytes: " << original_val.bytes + reverse_val.bytes << std::endl;
        std::cout << "A->B - packets: " << original_val.packets 
            << ", bytes: " << original_val.bytes << std::endl;
        std::cout << "B->A - packets: " << reverse_val.packets 
            << ", bytes: " << reverse_val.bytes << std::endl << std::endl;

        flow_map.erase(reverse_key);
    }
}