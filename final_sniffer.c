#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#define BUFFER_SIZE 65536

void parse_print_packet(unsigned char *buffer, int size);

void signalHandler(int sig);

int sock_raw = 0;
unsigned  char *buffer = NULL;

// Прерывание 2Не удалось получить пакеты
// double free or corruption (!prev)
// Аварийный останов


//[ Ethernet Header (14 bytes) ] [ IP Header ] [ Transport Header ] [ Data ]
int main(int argc, char *argv[]) {

	signal(SIGINT, signalHandler);
    //int sock_raw;
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    char *interface_name;

    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        printf("Не удалось выделить память\n");
        return 1;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        printf("Ошибка сокета\n");
        free(buffer); 
        return 1;
    }

     // Проверка аргументов командной строки
    if (argc != 2) {
        printf("Неверное кол-во аргументов\n");
        free(buffer);
        return 1;
    }
    interface_name = argv[1];

    printf("Запуск анализатора пакетов...\n");

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        printf("Неверное имя интерфейса\n");
        close(sock_raw);
        free(buffer);
        return 1;
    }

    while (1) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);
        if (data_size < 0) {
            printf("Не удалось получить пакеты\n");
            break;
        }
        parse_print_packet(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);
    return 0;
}

void signalHandler(int sig)  { 
    printf("\nПрерывание %d", sig);
    close(sock_raw);
    free(buffer);
}

void parse_print_packet(unsigned char *buffer, int size) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    printf("\n%d\n", ip->protocol);
    if(ip->protocol != IPPROTO_UDP)
    {
    	return;
    }

    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
    
    printf("\nSTART\n");
    // Читаем MAC-адреса из Ethernet-заголовка
    printf("   |-MAC отправителя: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
           
    printf("   |-MAC получателя: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // Читаем IP-адреса из IP-заголовка
    struct in_addr src_ip, dst_ip;
    src_ip.s_addr = ip->saddr;
    dst_ip.s_addr = ip->daddr;
    
    printf("   |-IP отправителя: %s\n", inet_ntoa(src_ip));
    printf("   |-IP получателя: %s\n", inet_ntoa(dst_ip));

    printf("   |-UDP-порт отправителя: %u\n", ntohs(udp->source));
    printf("   |-UDP-порт получателя: %u\n", ntohs(udp->dest));
    printf("   |-Длина нагрузки UDP: %u\n", ntohs(udp->len));
    printf("\nEND\n");

}
