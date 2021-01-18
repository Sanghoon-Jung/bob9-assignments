#include <pcap.h>
#include <glog/logging.h>
#include <iostream>
#include "pktstat.h"

void usage(){
    LOG(ERROR) << "syntax : packet-stat <pcap file>";
    LOG(ERROR) << "sample : packet-stat test.pcap";
}

int main(int argc, char *argv[]){
    FLAGS_logtostderr = true;           // glog flag to print error only to stderr
    google::InitGoogleLogging(argv[0]);
    
    if(argc != 2){
        usage();
        return -1;
    }

    char *pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handler = pcap_open_offline(pcap_file, errbuf);
    PLOG_IF(FATAL, handler == nullptr) << "pcap_open_offline() returned nullptr";
    
    std::cout << "pcap filename: " << pcap_file << std::endl;

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handler, &header, &packet);
        if(res == 0){
            LOG(INFO) << "no result from pcap_next_ex()";
            continue;
        }
        else if(res == -1){
            LOG(ERROR) << "pcap_next_ex() got an error with " << pcap_geterr(handler);
            break;
        }
        else if(res == -2){
            LOG(INFO) << "End of packets in " << pcap_file;
            break;
        }
        
        Enroller flow_enroller(packet, header->caplen);
    }

    StatViewer stat_viewer;
    stat_viewer.showStatistics();
    
    return 0;
}