#include "mqnic.h"


void mqnic_rx_irq(struct mqnic_cq* cq) {
    napi_schedule_irqoff(&cq->napi);
}
bool mqnic_is_rx_ring_empty(const struct mqnic_ring* ring) {
    return ring->prod_ptr == ring->cons_ptr;
}

bool mqnic_is_rx_ring_full(const struct mqnic_ring* ring) {
    return ring->prod_ptr - ring->cons_ptr >= ring->size;
}

void mqnic_rx_read_cons_ptr(struct mqnic_ring* ring) {
    ring->cons_ptr += ((ioread32(ring->hw_addr + MQNIC_QUEUE_PTR_REG) >> 16) - ring->cons_ptr) & MQNIC_QUEUE_PTR_MASK;
}

void mqnic_rx_write_prod_ptr(struct mqnic_ring* ring) {
    iowrite32(MQNIC_QUEUE_CMD_SET_PROD_PTR | (ring->prod_ptr & MQNIC_QUEUE_PTR_MASK),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
}

int mqnic_enable_rx_ring(struct mqnic_ring* ring) {
    if (!ring->hw_addr)
        return -EINVAL;

    // enable queue
    iowrite32(MQNIC_QUEUE_CMD_SET_ENABLE | 1,
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);

    ring->enabled = 1;

    return 0;
}

void mqnic_disable_rx_ring(struct mqnic_ring* ring) {
    // disable queue
    if (ring->hw_addr) {
        iowrite32(MQNIC_QUEUE_CMD_SET_ENABLE | 0,
            ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    }

    ring->enabled = 0;
}

struct mqnic_ring* mqnic_create_rx_ring(struct mqnic_if* interface) {
    struct mqnic_ring* ring;

    ring = kzalloc(sizeof(*ring), GFP_KERNEL);
    if (!ring)
        return ERR_PTR(-ENOMEM);

    ring->dev = interface->dev;
    ring->interface = interface;

    ring->index = -1;
    ring->enabled = 0;

    ring->hw_addr = NULL;

    ring->prod_ptr = 0;
    ring->cons_ptr = 0;

    return ring;
}

void mqnic_destroy_rx_ring(struct mqnic_ring* ring) {
    mqnic_close_rx_ring(ring);

    kfree(ring);
}
/*
 +14    ^^^^^^^^^^^^^^^^^^^^^^^^^MAC Header ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

        +---------------------------------------------------------------+
  00    |Version|  IHL |     TOS     |        IP Total Length           |
        +---------------------------------------------------------------+
  04    |        Identification      |Flags|     Fragment Offset        |
        +---------------------------------------------------------------+
  08    |      TTL     |  Protocol   |      Header Checksum             |
        +---------------------------------------------------------------+
  12    |                       Source IP Address                       |
        +---------------------------------------------------------------+
  16    |                    Destination IP Address                     |
        +---------------------------------------------------------------+
        |________________________NO IP OPTION___________________________|
        +---------------------------------------------------------------+
  20    |         Source Port        |        Destination Port          |
        +---------------------------------------------------------------+
  24    |                        Sequence Number                        |
        +---------------------------------------------------------------+
  28    |                     Acknowledgment Number                     |
        +---------------------------------------------------------------+
  32    | Offset| Rsvd |    Flags    |          Window Size             |
        +---------------------------------------------------------------+
  36    |          Checksum          |        Urgent Pointer            |
        +---------------------------------------------------------------+
  40    |                      Options (MSS)                            |
        +---------------------------------------------------------------+
*/

/*returns the number of truncated bytes.*/
int hack_trim_header(struct page* hdr_page, const u16 hw_hdr_len) {
    char* byte;
    u8 tcp_option;
    u8 proto;
    const u16 ip_hdr_len = 20;
    const int offset = 14;

    byte = (char*)(page_address(hdr_page) + offset);
    tcp_option = (byte[32] >> 4) * 4; // Word length is 4 bytes
    proto = (u8)byte[9];// Exclude non-tcp packets
    if (proto != 0x06) {// 06 means TCP
        return 1;
    }

    int trim = tcp_option + offset + ip_hdr_len - hw_hdr_len;

    return trim; // if >0, then discard; if ==0 then it is pure kernel handling; if <0, then trim
}