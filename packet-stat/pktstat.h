#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "flow.h"

class Enroller{
    private:
    uint8_t* pkt_ptr;
    void enrollFlow(FlowMap& flow_map, FlowKey& flow_key, uint32_t& pkt_len);
    void enrollEndPoint(EndPointMap& endpoint_map, EndPoint& endpoint, FlowKey& flow_key);

    public:
    Enroller(){}
    Enroller(const uint8_t* pkt_baseptr, uint32_t& pkt_len);
};

class StatViewer{
    private:
    void showEndpoints(EndPointMap& endpoint_map, FlowMap& flow_map);
    void showConversations(FlowMap flow_map);

    public:
    void showStatistics();
};