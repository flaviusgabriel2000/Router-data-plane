#include "queue.h"
#include "skel.h"


#define MAX_RTABLE_ENTRIES 100000
#define ICMP_PROTOCOL 1
#define ORIGINAL_PAYLOAD_LEN 64

struct route_table_entry *rtable;
struct arp_entry *arp_table;

int rtable_size;
int arp_table_size;
int r2r_ip_idx;

struct route_table_entry *get_best_entry(uint32_t dest_ip) {
	struct route_table_entry *best_entry = NULL;

	for (int i = 0; i < rtable_size; i++) {
		if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
			if (best_entry == NULL) {
				best_entry = &rtable[i];
			} else if (ntohl(rtable[i].mask) > ntohl(best_entry->mask)) {
				best_entry = &rtable[i];
			}
		}
	}
	return best_entry;
}

struct arp_entry *get_arp_entry(uint32_t ip) {
    for(int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
    return NULL;
}

void send_icmp(packet original_m, int type, int code) {
	// Original IP Header
	struct iphdr *ip_hdr = (struct iphdr *)(original_m.payload + sizeof(struct ether_header));
	
	// The ICMP packet to be sent
	packet icmp_packet;
	memcpy(&icmp_packet, &original_m, sizeof(original_m));
	icmp_packet.len += sizeof(struct icmphdr);

	// The new packet IP Header
	struct iphdr *icmp_ip_hdr = (struct iphdr *)(icmp_packet.payload + sizeof(struct ether_header));
	icmp_ip_hdr->daddr = ip_hdr->saddr;
	icmp_ip_hdr->saddr = arp_table[r2r_ip_idx].ip;
	icmp_ip_hdr->tot_len += htons(sizeof(struct icmphdr));
	uint16_t old = icmp_ip_hdr->protocol;
	icmp_ip_hdr->protocol = (uint8_t)1;
	icmp_ip_hdr->check = ~(~icmp_ip_hdr->check + ~old + icmp_ip_hdr->protocol) - 1;

	// Fill the ICMP Header with the corresponding type and code
	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	memset(&icmp_hdr->un, 0, 4);

	// Copy the original IP Header and payload into the ICMP Message
	memcpy(icmp_hdr + 1, original_m.payload + sizeof(struct ether_header), ORIGINAL_PAYLOAD_LEN);	
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

	send_packet(&icmp_packet);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(MAX_RTABLE_ENTRIES * sizeof(struct route_table_entry));
	arp_table = malloc(10 * sizeof(struct arp_entry));

	rtable_size = read_rtable(argv[1], rtable);
	arp_table_size = parse_arp_table("arp_table.txt", arp_table);
	r2r_ip_idx = 4 + atoi(&argv[1][6]);

	while (1) {
		rc = get_packet(&m);
		if (rc < 0) {
			free(rtable);
			free(arp_table);
			DIE(rc < 0, "get_packet");
		}

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			if (ip_checksum((uint8_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
				continue;
			}

			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
				send_icmp(m, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
				continue;
			}

			if (ip_hdr->protocol == ICMP_PROTOCOL) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				int found_host = 0;
				if (!found_host) {
					for (int i = 0; i < arp_table_size; i++) {
						if (ip_hdr->daddr == arp_table[i].ip) {
							found_host = 1;
							break;
						}
					}
				}
				if (icmp_hdr->type == ICMP_ECHO && icmp_hdr->code == 0 && !found_host) {
					uint16_t old = ip_hdr->daddr;
					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->check = ~(~ip_hdr->check + ~old + ip_hdr->daddr) - 1;
					
					icmp_hdr->type = ICMP_ECHOREPLY;
					icmp_hdr->code = 0;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, 
										m.len - sizeof(struct ether_header) - sizeof(struct iphdr));
				}
			}

			struct route_table_entry *best_rtable_entry = get_best_entry(ip_hdr->daddr);
			if (best_rtable_entry == NULL) {
				send_icmp(m, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
				continue;
			}

			struct arp_entry *best_neighbour = get_arp_entry(best_rtable_entry->next_hop);
			if (best_neighbour == NULL) {
				continue;
			}

			uint16_t old_ttl = ip_hdr->ttl;
			ip_hdr->ttl--;
			ip_hdr->check = ~(~ip_hdr->check + ~old_ttl + ip_hdr->ttl) - 1;

			memcpy(eth_hdr->ether_dhost, best_neighbour->mac, 6);
			get_interface_mac(best_rtable_entry->interface, eth_hdr->ether_shost);
			m.interface = best_rtable_entry->interface;
			send_packet(&m);
		}	
	}
}
