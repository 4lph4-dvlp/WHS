#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>

/* 이더넷 헤더 구조 */
struct ethheader {
    unsigned char ether_dhost[6]; // 목적지 MAC 주소 6바이트
    unsigned char ether_shost[6]; // 출발지 MAC 주소 6바이트
    unsigned short ether_type; // 프로토콜 타입 2바이트 (0x0800: IP, 0x0806: ARP, 0x8035: RARP)
};

/* IP 헤더 구조 */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4; // IP 헤더 길이, 버전
    unsigned char iph_tos; // 서비스 타입
    unsigned short iph_len; // IP 헤더 길이
    unsigned short iph_ident; // 식별자
    unsigned short iph_flag:3, iph_offset:13; // 플래그, 단편화 옵션
    unsigned char iph_ttl; // Time to Live
    unsigned char iph_protocol; // 프로토콜
    unsigned short iph_chksum; // 체크섬
    struct in_addr iph_sourceip; // 출발지 IP 주소
    struct in_addr iph_destip; // 목적지 IP 주소
};

/* TCP 헤더 구조 */
struct tcpheader {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int seq_number;
    unsigned int ack_number;
    unsigned char data_offset:4, reserved:4;
    unsigned char flags;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ethheader *eth = (struct ethheader *)packet; //ethernet 헤더 포인터

    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); //ethernet 헤더 다음 위치에 IP 헤더 포인터

        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 패킷 확인
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4)); // IP 헤더 다음 위치에 TCP 헤더 포인터

            // 시간 가져오기
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char timestamp[20];
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

            printf("\033[32m[%s] TCP Packet Detected.\033[0m\n", timestamp);

            // 이더넷 헤더 출력
            printf("[Ethernet Header]\n");
            printf("Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("-----------------------------------\n");

            // IP 헤더 출력
            printf("[IP Header]\n");
            printf("Source IP : %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP : %s\n", inet_ntoa(ip->iph_destip));
            printf("-----------------------------------\n");

            // TCP 헤더 출력
            printf("[TCP Header]\n");
            printf("Source Port : %u\n", ntohs(tcp->source_port));
            printf("Destination Port : %u\n", ntohs(tcp->dest_port));
            printf("-----------------------------------\n");

            // 메시지 출력
            printf("[Message] : ");
            int ip_header_len = (ip->iph_ihl) * 4;
            int tcp_header_len = (tcp->data_offset) * 4;
            int message_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
            unsigned char *message = (unsigned char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);

            for (int i = 0; i < message_len; i++) {
                if (message[i] >= 32 && message[i] <= 126) {
                    printf("%c", message[i]);
                } else {
                    printf(".");
                }
            }
            printf("\n==================================================\n");
        }
    }
}

int main() {
    pcap_if_t *alldevs, *d;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, dev_index;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "인터페이스 목록을 불러올 수 없습니다: %s\n", errbuf);
        return 1;
    }

    printf("사용 가능한 네트워크 인터페이스:\n");
    for (d = alldevs; d; d = d->next) {
        printf("[%d] %s\n", i++, d->name);
    }

    printf("사용할 인터페이스 번호를 선택하세요: ");
    scanf("%d", &dev_index);

    d = alldevs;
    for (i = 0; i < dev_index && d; i++, d = d->next);
    if (d == NULL) {
        fprintf(stderr, "잘못된 선택입니다.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "인터페이스를 열 수 없습니다: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("선택된 인터페이스: %s\n", d->name);
    pcap_freealldevs(alldevs);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터를 설정할 수 없습니다.\n");
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
