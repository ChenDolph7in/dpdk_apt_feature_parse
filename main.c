/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include "hashmap.h"

#include <unistd.h>

#include <Python.h>

pthread_mutex_t mute;
PyObject *pModule, *pFunc, *pDict;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IsBitSet(val, bit) ((val) & (1 << (bit)))

/* hashmap config */
#define KEY_MAX_LENGTH (256)
#define KEY_COUNT (1024 * 1024)
#define TEXT_LENGTH (1024 * 32)
/* queue structure */
struct List
{
	unsigned long timestamp;
	int proto;
	char *ip_src;
	char *ip_dst;
	int ip_len;
	int port_src;
	int port_dst;
	int ip_hdr_len;
	uint8_t tcp_flags;
	int tcp_hdr_len;
	int tls_version;
	int more_seg_flag;
	int tcp_ack;
	int tls_content_type;
	char *certs;
	char *sni;
	struct List *next;
};

struct Queue
{
	int size;
	struct List *head;
	struct List *rear;
};
typedef struct Queue *qlink;

/* hashmap value : five tuple's features structure */
typedef struct data_struct_s
{
	char key_string[KEY_MAX_LENGTH];
	uint64_t last_update_time;
	int finish_flag;
	/* features */
	qlink list;
} data_struct_t;

qlink create_queue(void)
{
	qlink queue = malloc(sizeof(struct Queue));
	if (!queue)
		return queue;
	queue->size = 0;
	queue->head = queue->rear = NULL;
	return queue;
}

int empty(qlink queue)
{
	return queue->size == 0;
}

void enqueue(qlink queue, struct List *new)
{
	if (!new)
		return;
	new->next = NULL;
	if (queue->head)
		queue->rear->next = new;
	else
		queue->head = new;
	queue->rear = new;
	queue->size++;
}

int dequeue(qlink queue)
{
	if (empty(queue))
		return -1;
	// int retval = queue->head->item;
	struct List *torm = queue->head;
	if (queue->head == queue->rear)
		queue->rear = NULL;
	queue->head = queue->head->next;
	free(torm);
	queue->size--;
	// return retval;
	return 0;
}

int gen_features(char *key_string, qlink link)
{
	if (empty(link))
		return -1;
	struct List *p = link->head;
	int cnt = link->size;
	if (cnt <= 0)
		return -1;
	PyObject *PyList = PyList_New(0);
	PyObject *ArgList = PyTuple_New(1);
	while (cnt > 0)
	{
		PyObject *PyList1 = PyList_New(19);
		
		PyList_SetItem(PyList1, 0, PyBytes_FromString(key_string));
		PyList_SetItem(PyList1, 1, PyLong_FromLong(p->timestamp));
		PyList_SetItem(PyList1, 2, PyLong_FromLong(p->proto));
		PyList_SetItem(PyList1, 3, PyBytes_FromString(p->ip_src));
		PyList_SetItem(PyList1, 4, PyBytes_FromString(p->ip_dst));
		PyList_SetItem(PyList1, 5, PyLong_FromLong(p->port_src));
		PyList_SetItem(PyList1, 6, PyLong_FromLong(p->port_dst));

		PyList_SetItem(PyList1, 9, PyLong_FromLong(p->ip_len));
		PyList_SetItem(PyList1, 10, PyLong_FromLong(p->ip_hdr_len));
		
		PyList_SetItem(PyList1, 11, PyLong_FromLong(p->tcp_flags));
		PyList_SetItem(PyList1, 12, PyLong_FromLong(p->tcp_hdr_len));
		PyList_SetItem(PyList1, 13, PyLong_FromLong(p->tls_version));
		PyList_SetItem(PyList1, 14, PyLong_FromLong(p->more_seg_flag));
		PyList_SetItem(PyList1, 15, PyLong_FromLong(p->tcp_ack));
		PyList_SetItem(PyList1, 16, PyLong_FromLong(p->tls_content_type));
		PyList_SetItem(PyList1, 17, PyBytes_FromString(p->certs));
		PyList_SetItem(PyList1, 18, PyBytes_FromString(p->sni));
		PyList_Append(PyList, PyList1);
		/* free ip_src */
		free(p->ip_src);
		free(p->ip_dst);
		free(p->certs);
		free(p->sni);
		p = p->next;
		cnt--;
	}
	PyTuple_SetItem(ArgList, 0, PyList);
	PyObject_CallObject(pFunc, ArgList);
	// PyObject *pReturn = PyObject_CallObject(pFunc, ArgList); // 调用函数，返回一个list
	// int result;
	// PyArg_Parse(pReturn, "i", &result);
	// printf("python return: %d\n",result);
	// printf("return ok!!!\n");
	Py_DECREF(ArgList);
	Py_DECREF(PyList);
	while (!empty(link))
	{
		dequeue(link);
	}
	return 0;
}

/* hashmap for five tuple */
struct hashmap_s mymap;
// static int myiterate(void *const context, void *const value)
// {

// 	uint64_t time = *(uint64_t *)context;
// 	printf("time: %ld\n", time);
// 	data_struct_t *myvalue = (data_struct_t *)value;
// 	uint64_t timestamp = myvalue->last_update_time;
// 	printf("timestamp: %ld\n", timestamp);
// 	if (time - timestamp > 5000)
// 	{
// 		printf("1\n");
// 		char key_string[KEY_MAX_LENGTH];
// 		printf("key_string: %s\n", myvalue->key_string);
// 		strncpy(key_string, myvalue->key_string, KEY_MAX_LENGTH);
// 		qlink link = myvalue->list;
// 		printf("key_string2: %s\n", key_string);
// 		/* gen features */
// 		gen_features(link);
// 		printf("gen_features over\n");
// 		free(link);
// 		// int error = hashmap_remove(&mymap, key_string,strlen(key_string));
// 		printf("key_string3: %s\n", key_string);
// 		printf("key_string_len: %ld\n", strlen(key_string));
// 		// int error = hashmap_remove(&mymap, key_string, strlen(key_string));
// 		pthread_mutex_lock(&mute);
// 		int error = hashmap_remove(&mymap, myvalue->key_string, strlen(myvalue->key_string));
// 		pthread_mutex_unlock(&mute);
// 		if (0 != error)
// 		{
// 			printf("hashmap remove error :%d\n", error);
// 		}
// 		// Return 0 to tell the iteration to stop here.
// 		return 0;
// 	}
// 	printf("2\n");
// 	// Otherwise tell the iteration to keep going.
// 	return 1;
// }

int log_and_free(void *const context, struct hashmap_element_s *const e)
{
	uint64_t time = *(uint64_t *)context;
	data_struct_t *myvalue = (data_struct_t *)e->data;
	uint64_t timestamp = myvalue->last_update_time;
	char key_string[KEY_MAX_LENGTH];
	strncpy(key_string, e->key, e->key_len);
	if (time - timestamp > 5000)
	{
		qlink link = myvalue->list;
		/* gen features */
		// printf("gen_features start\n");
		gen_features(key_string, link);
		// printf("gen_features over\n");
		free(link);
		return -1;
	}

	return 0;
}

/* delete and handle timeout flow */
int hashmap_ring()
{
	bool app_stopped = true;
	while (app_stopped)
	{
		sleep(5);
		printf("hashmap_ring\n");
		uint64_t now = rte_rdtsc();
		// printf("after sleep now time: %ld\n", now);
		// while(0!= hashmap_iterate(&mymap, iterate, &now)){}
		// if (0 == hashmap_iterate(&mymap, myiterate, &now))
		// {
		// 	printf("error\n");
		// }
		pthread_mutex_lock(&mute);
		if (0 != hashmap_iterate_pairs(&mymap, log_and_free, &now))
		{
			printf("failed to deallocate hashmap entries\n");
		}
		pthread_mutex_unlock(&mute);
	}
	pthread_exit(NULL);
}

static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
hwts_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
							 hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static inline tsc_t *
tsc_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}

static const char usage[] =
	"%s EAL_ARGS -- [-t]\n";


int hw_timestamping;

#define TICKS_PER_CYCLE_SHIFT 16
static uint64_t ticks_per_cycle_mult;

static inline void
lpm_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

/* Callback added to the RX port and applied to packets. 8< */
static uint16_t
parse_five_tuple(uint16_t port __rte_unused, uint16_t qidx __rte_unused,
				 struct rte_mbuf **pkts, uint16_t nb_pkts,
				 uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	uint64_t now = rte_rdtsc();

	for (i = 0; i < nb_pkts; i++)
		*tsc_field(pkts[i]) = now;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int)(nb_pkts - 1); ++i)
	{
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 1],
									   struct ether_hdr *));
		lpm_parse_ptype(pkts[i]);
	}
	lpm_parse_ptype(pkts[i]);

	for (i = 0; i < (unsigned int)nb_pkts; ++i)
	{
		// struct rte_ipv6_hdr *ipv6_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_ether_hdr *eth_hdr;
		struct rte_tcp_hdr *tcp_hdr;
		// struct rte_udp_hdr *udp_hdr;

		struct rte_mbuf *pkt = pkts[i];
		if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type))
		{

			eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
			ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

			/* emit udp */
			// if (ipv4_hdr->next_proto_id == 17)
			// {
			// 	proto = 17;
			// 	udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
			// 	printf(" port_src = %d, port_dst = %d, proto = udp\n", htons(udp_hdr->src_port), htons(udp_hdr->dst_port));
			// 	port_src = htons(udp_hdr->src_port);
			// 	port_dst = htons(udp_hdr->dst_port);

			// }
			// else

			if (ipv4_hdr->next_proto_id == 6)
			{
				tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);

				struct in_addr addr1, addr2;
				memcpy(&addr1, &ipv4_hdr->src_addr, 4);
				memcpy(&addr2, &ipv4_hdr->dst_addr, 4);
				unsigned long timestamp = now;
				int proto = 6;

				char *ip_src = (char *)malloc(sizeof(char) * 16);
				strncpy(ip_src, inet_ntoa(addr1), 16);
				char *ip_dst = (char *)malloc(sizeof(char) * 16);
				strncpy(ip_dst, inet_ntoa(addr2), 16);
				int ip_len = htons(ipv4_hdr->total_length);
				int ip_hdr_len = ipv4_hdr->ihl;
				int port_src = htons(tcp_hdr->src_port);
				int port_dst = htons(tcp_hdr->dst_port);
				uint8_t tcp_flags = tcp_hdr->tcp_flags;
				char flags_str[8];
				sprintf(flags_str, "0x%03X", tcp_flags);
				uint8_t fin = IsBitSet(tcp_flags, 0) ? 1 : 0;
				uint8_t syn = IsBitSet(tcp_flags, 1) ? 1 : 0;
				uint8_t rst = IsBitSet(tcp_flags, 2) ? 1 : 0;
				uint8_t psh = IsBitSet(tcp_flags, 3) ? 1 : 0;
				uint8_t ack = IsBitSet(tcp_flags, 4) ? 1 : 0;
				uint8_t urg = IsBitSet(tcp_flags, 5) ? 1 : 0;
				uint8_t ece = IsBitSet(tcp_flags, 6) ? 1 : 0;
				uint8_t cwr = IsBitSet(tcp_flags, 7) ? 1 : 0;
				uint8_t tcp_hdr_len = (tcp_hdr->data_off) >> 4;
				// printf("tcp_hdr_len: %X\n", tcp_hdr_len);

				int tls_version = 0x03;
				int more_seg_flag = 0x01;
				int tcp_ack = tcp_hdr->recv_ack;
				int tls_content_type = 0x04;
				char *certs = (char *)malloc(TEXT_LENGTH);
				snprintf(certs, TEXT_LENGTH, "cert_test");
				char *sni = (char *)malloc(TEXT_LENGTH);
				snprintf(sni, TEXT_LENGTH, "sni_test");
				/* gen key string */
				char key_string[KEY_MAX_LENGTH];
				if (port_src > port_dst)
					snprintf(key_string, KEY_MAX_LENGTH, "%s:%d %s:%d", ip_src, port_src, ip_dst, port_dst);
				else
					snprintf(key_string, KEY_MAX_LENGTH, "%s:%d %s:%d", ip_dst, port_dst, ip_src, port_src);
				/* judge exist ? */
				// int error = hashmap_get(mymap, key_string, (void **)(&value));
				// printf("key_len = %ld\n",strlen(key_string));

				void *const element = hashmap_get(&mymap, key_string, strlen(key_string));

				if (element != NULL)
				{
					/* get exist hash node */
					data_struct_t *value = (data_struct_t *)element;

					// printf("key_string: %s ====== ====== ",key_string);
					// printf("value->key_string: %s\n",value->key_string);
					/* insert into queue */
					value->last_update_time = timestamp;

					qlink link = value->list;
					struct List *new = (struct List *)malloc(sizeof(struct List));
					new->timestamp = timestamp;
					new->proto = proto;
					new->ip_src = ip_src;
					new->ip_dst = ip_dst;
					new->ip_len = ip_len;
					new->ip_hdr_len = ip_hdr_len;
					new->port_src = port_src;
					new->port_dst = port_dst;
					new->tcp_flags = tcp_flags;
					new->tcp_hdr_len = tcp_hdr_len;
					new->tls_version = tls_version;
					new->more_seg_flag = more_seg_flag;
					new->tcp_ack = tcp_ack;
					new->tls_content_type = tls_content_type;
					new->certs = certs;
					new->sni = sni;
					enqueue(link, new);
					/* judge finish */
					if (value->finish_flag == 0 && ((fin == 1 && syn == 1) || rst == 1))
					{
						value->finish_flag = 1;
					}
					else if (value->finish_flag == 1)
					{
						/* gen features */
						printf("%d %d %d %d %d %d %d %d\n", cwr, ece, urg, ack, psh, rst, syn, fin);

						gen_features(key_string, link);
						free(link);
						// int error = hashmap_remove(&mymap, key_string,strlen(key_string));

						pthread_mutex_lock(&mute);
						if (0 != hashmap_remove(&mymap, key_string, strlen(key_string)))
						{
							printf("hashmap remove error\n");
						}
						pthread_mutex_unlock(&mute);
					}
				}
				else
				{
					data_struct_t *value = malloc(sizeof(data_struct_t));

					/* insert into hashmap */
					qlink new_link = create_queue();
					struct List *new = (struct List *)malloc(sizeof(struct List));
					new->timestamp = timestamp;
					new->proto = proto;
					new->ip_src = ip_src;
					new->ip_dst = ip_dst;
					new->ip_len = ip_len;
					new->ip_hdr_len = ip_hdr_len;
					new->port_src = port_src;
					new->port_dst = port_dst;
					new->tcp_flags = tcp_flags;
					new->tcp_hdr_len = tcp_hdr_len;
					new->tls_version = tls_version;
					new->more_seg_flag = more_seg_flag;
					new->tcp_ack = tcp_ack;
					new->tls_content_type = tls_content_type;
					new->certs = certs;
					new->sni = sni;
					enqueue(new_link, new);
					snprintf(value->key_string, KEY_MAX_LENGTH, "%s:%d %s:%d", ip_src, port_src, ip_dst, port_dst);
					value->list = new_link;
					value->last_update_time = timestamp;
					value->finish_flag = 0;

					if (0 != hashmap_put(&mymap, key_string, strlen(key_string), value))
					{
						printf("hashmap put error\n");
					}
				}
			}
		}
		// else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type))
		// {
		// 	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		// 	ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
		// }
	}
	return nb_pkts;
}
/* >8 End of callback addition and application. */

/* >8 End of callback addition. */

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */

/* Port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0)
	{
		printf("Error during getting device (port %u) info: %s\n",
			   port, strerror(-retval));

		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	if (hw_timestamping)
	{
		if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP))
		{
			printf("\nERROR: Port %u does not support hardware timestamping\n", port);
			return -1;
		}
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
		rte_mbuf_dyn_rx_timestamp_register(&hwts_dynfield_offset, NULL);
		if (hwts_dynfield_offset < 0)
		{
			printf("ERROR: Failed to register timestamp field\n");
			return -rte_errno;
		}
	}

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	rxconf = dev_info.default_rxconf;

	for (q = 0; q < rx_rings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	if (hw_timestamping && ticks_per_cycle_mult == 0)
	{
		uint64_t cycles_base = rte_rdtsc();
		uint64_t ticks_base;
		retval = rte_eth_read_clock(port, &ticks_base);
		if (retval != 0)
			return retval;
		rte_delay_ms(100);
		uint64_t cycles = rte_rdtsc();
		uint64_t ticks;
		rte_eth_read_clock(port, &ticks);
		uint64_t c_freq = cycles - cycles_base;
		uint64_t t_freq = ticks - ticks_base;
		double freq_mult = (double)c_freq / t_freq;
		printf("TSC Freq ~= %" PRIu64
			   "\nHW Freq ~= %" PRIu64
			   "\nRatio : %f\n",
			   c_freq * 10, t_freq * 10, freq_mult);
		/* TSC will be faster than internal ticks so freq_mult is > 0
		 * We convert the multiplication to an integer shift & mult
		 */
		ticks_per_cycle_mult = (1 << TICKS_PER_CYCLE_SHIFT) / freq_mult;
	}

	struct rte_ether_addr addr;

	retval = rte_eth_macaddr_get(port, &addr);
	if (retval < 0)
	{
		printf("Failed to get MAC address on port %u: %s\n",
			   port, rte_strerror(-retval));
		return retval;
	}
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		   (unsigned)port,
		   RTE_ETHER_ADDR_BYTES(&addr));

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	/* RX and TX callbacks are added to the ports. 8< */
	rte_eth_add_rx_callback(port, 0, parse_five_tuple, NULL);
	// rte_eth_add_tx_callback(port, 0, calc_latency, NULL);
	/* >8 End of RX and TX callbacks. */

	return 0;
}
/* >8 End of port initialization. */

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port)
	if (rte_eth_dev_socket_id(port) >= 0 &&
		rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
			   "polling thread.\n\tPerformance will "
			   "not be optimal.\n",
			   port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		   rte_lcore_id());
	for (;;)
	{
		RTE_ETH_FOREACH_DEV(port)
		{
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
													bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
													bufs, nb_rx);
			if (unlikely(nb_tx < nb_rx))
			{
				uint16_t buf;

				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/* Main function, does initialisation and calls the per-lcore functions */
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	struct option lgopts[] = {
		{NULL, 0, 0, 0}};
	int opt, option_index;

	static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
		.name = "example_bbdev_dynfield_tsc",
		.size = sizeof(tsc_t),
		.align = __alignof__(tsc_t),
	};

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	while ((opt = getopt_long(argc, argv, "t", lgopts, &option_index)) != EOF)
		switch (opt)
		{
		case 't':
			hw_timestamping = 1;
			break;
		default:
			printf(usage, argv[0]);
			return -1;
		}
	optind = 1; /* reset getopt lib */

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
										NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
										RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	tsc_dynfield_offset =
		rte_mbuf_dynfield_register(&tsc_dynfield_desc);
	if (tsc_dynfield_offset < 0)
		rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
				 portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			   "App uses only 1 lcore\n");

	/* create hashtable for five tuple*/
	const unsigned initial_size = KEY_COUNT;
	if (0 != hashmap_create(initial_size, &mymap))
	{
		printf("create hashmap error\n");
	}
	/* create python call handle */
	// 初始化python
	Py_Initialize();
	if (!Py_IsInitialized())
	{
		printf("python初始化失败！");
		return 0;
	}
	PyRun_SimpleString("import sys");
	int result = PyRun_SimpleString("print('----------import sys-------')");
	if (result != -1)
	{
		printf("test python OK!\n");
	}
	PyRun_SimpleString("sys.path.append('./')");
	pModule = PyImport_ImportModule("gen_features");
	if (!pModule)
	{
		printf("python import module failed\n");
		return -1;
	}
	pDict = PyModule_GetDict(pModule);
	if (!pDict)
	{
		printf("python can't get dict\n");
		getchar();
		return -1;
	}
	pFunc = PyDict_GetItemString(pDict, "gen_five_tuple");
	if (!pFunc)
	{
		printf("python can't get function\n");
		getchar();
		return -1;
	}
	/* create timeout monitor thread */
	pthread_t th;
	pthread_create(&th, NULL, (void *)hashmap_ring, NULL);

	/* call lcore_main on main core only */
	lcore_main();

    Py_DECREF(pModule);
	Py_DECREF(pDict);
	Py_DECREF(pFunc);
	Py_Finalize();
	getchar();
	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}