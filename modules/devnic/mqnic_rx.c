// SPDX-License-Identifier: BSD-2-Clause-Views
/*
 * Copyright (c) 2019-2023 The Regents of the University of California
 */

#include "mqnic.h"
#include "debug.h"
 //Override
int hds_mqnic_open_rx_ring(struct mqnic_ring* ring, struct mqnic_priv* priv,
    struct mqnic_cq* cq, int size, int desc_block_size, int rxq_idx) {
    int ret = 0;

    if (ring->enabled || ring->hw_addr || ring->buf || !priv || !cq)
        return -EINVAL;

    ring->index = rxq_idx;
    if (ring->index < 0)
        return -ENOMEM;
    ring->log_desc_block_size = desc_block_size < 2 ? 0 : ilog2(desc_block_size - 1) + 1;
    ring->desc_block_size = 1 << ring->log_desc_block_size;

    ring->size = roundup_pow_of_two(size);
    ring->full_size = ring->size >> 1;
    ring->size_mask = ring->size - 1;
    ring->stride = roundup_pow_of_two(MQNIC_DESC_SIZE * ring->desc_block_size);

    ring->rx_info = kvzalloc(sizeof(*ring->rx_info) * ring->size, GFP_KERNEL);
    if (!ring->rx_info) {
        ret = -ENOMEM;
        goto fail;
    }

    ring->buf_size = ring->size * ring->stride;
    ring->buf = dma_alloc_coherent(ring->dev, ring->buf_size, &ring->buf_dma_addr, GFP_KERNEL);
    if (!ring->buf) {
        ret = -ENOMEM;
        goto fail;
    }

    /*Allocate header buffers. The header size is fixed 66B*/
    ring->hdr_len = HW_HDR_SIZE;
    // ring->hdr_buf = dma_alloc_coherent(ring->dev, ring->hdr_len * ring->size, &ring->hdr_bufs_addr, GFP_KERNEL);

    struct page_pool_params pp_params = { 0 };
    /*
    Create a page_pool and register it with rxq
    netdev and queue are devmemtcp features
    */
    pp_params.order = ring->page_order;
    pp_params.pool_size = ring->size;
    pp_params.nid = NUMA_NO_NODE;
    pp_params.dev = priv->dev;
    pp_params.netdev = priv->ndev;
    pp_params.flags = PP_FLAG_DMA_MAP;
    pp_params.dma_dir = DMA_FROM_DEVICE;
    pp_params.queue = NULL;
    pp_params.queue = __netif_get_rx_queue(priv->ndev, ring->index);
    ring->pp = page_pool_create(&pp_params);
    {
        struct page_pool* pp = ring->pp;
        if (pp->mp_priv) {
            pr_debug("%s: We actually successfully bound dmabuf in ring<%d> of IF<%d>\n", __func__, ring->index, priv->interface->index);
        }
        else {
            pr_debug("%s: Kernel page in ring<%d>\n", __func__, ring->index);
        }
    }
    ring->priv = priv;
    ring->cq = cq;
    cq->src_ring = ring;
    cq->handler = mqnic_rx_irq;

    ring->hw_addr = mqnic_res_get_addr(ring->interface->rxq_res, ring->index);

    ring->prod_ptr = 0;
    ring->cons_ptr = 0;

    // deactivate queue
    iowrite32(MQNIC_QUEUE_CMD_SET_ENABLE | 0,
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set base address
    iowrite32((ring->buf_dma_addr & 0xfffff000),
        ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_VF_REG + 0);
    iowrite32(ring->buf_dma_addr >> 32,
        ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_VF_REG + 4);
    // set size
    iowrite32(MQNIC_QUEUE_CMD_SET_SIZE | ilog2(ring->size) | (ring->log_desc_block_size << 8),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set CQN
    iowrite32(MQNIC_QUEUE_CMD_SET_CQN | ring->cq->cqn,
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set pointers
    iowrite32(MQNIC_QUEUE_CMD_SET_PROD_PTR | (ring->prod_ptr & MQNIC_QUEUE_PTR_MASK),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    iowrite32(MQNIC_QUEUE_CMD_SET_CONS_PTR | (ring->cons_ptr & MQNIC_QUEUE_PTR_MASK),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);

    ret = mqnic_refill_rx_buffers(ring);
    if (ret) {
        netdev_err(priv->ndev, "failed to allocate RX buffer for RX queue index %d (of %u total) entry index %u (of %u total)",
            ring->index, priv->rxq_count, ring->prod_ptr, ring->size);
        if (ret == -ENOMEM)
            netdev_err(priv->ndev, "machine might not have enough DMA-capable RAM; try to decrease number of RX channels (currently %u) and/or RX ring parameters (entries; currently %u) and/or module parameter \"num_rxq_entries\" (currently %u)",
                priv->rxq_count, ring->size, mqnic_num_rxq_entries);

        goto fail;
    }

    return 0;

fail:
    mqnic_close_rx_ring(ring);
    return ret;
}

int mqnic_open_rx_ring(struct mqnic_ring* ring, struct mqnic_priv* priv,
    struct mqnic_cq* cq, int size, int desc_block_size) {

    int ret = 0;

    if (ring->enabled || ring->hw_addr || ring->buf || !priv || !cq)
        return -EINVAL;

    ring->index = mqnic_res_alloc(ring->interface->rxq_res);
    if (ring->index < 0)
        return -ENOMEM;
    ring->log_desc_block_size = desc_block_size < 2 ? 0 : ilog2(desc_block_size - 1) + 1;
    ring->desc_block_size = 1 << ring->log_desc_block_size;

    ring->size = roundup_pow_of_two(size);
    ring->full_size = ring->size >> 1;
    ring->size_mask = ring->size - 1;
    ring->stride = roundup_pow_of_two(MQNIC_DESC_SIZE * ring->desc_block_size);

    ring->rx_info = kvzalloc(sizeof(*ring->rx_info) * ring->size, GFP_KERNEL);
    if (!ring->rx_info) {
        ret = -ENOMEM;
        goto fail;
    }

    ring->buf_size = ring->size * ring->stride;
    ring->buf = dma_alloc_coherent(ring->dev, ring->buf_size, &ring->buf_dma_addr, GFP_KERNEL);
    if (!ring->buf) {
        ret = -ENOMEM;
        goto fail;
    }

    /*Allocate header buffers. The header size is fixed 66B*/
    ring->hdr_len = HW_HDR_SIZE;
    // ring->hdr_buf = dma_alloc_coherent(ring->dev, ring->hdr_len * ring->size, &ring->hdr_bufs_addr, GFP_KERNEL);

    struct page_pool_params pp_params = { 0 };
    /*
    Create a page_pool and register it with rxq
    netdev and queue are devmemtcp features
    */
    pp_params.order = ring->page_order;
    pp_params.pool_size = ring->size;
    pp_params.nid = NUMA_NO_NODE;
    pp_params.dev = priv->dev;
    pp_params.netdev = priv->ndev;
    pp_params.flags = PP_FLAG_DMA_MAP;
    pp_params.dma_dir = DMA_FROM_DEVICE;
    pp_params.queue = NULL;
    // pp_params.queue = __netif_get_rx_queue(priv->ndev, ring->index);
    ring->pp = page_pool_create(&pp_params);

    ring->priv = priv;
    ring->cq = cq;
    cq->src_ring = ring;
    cq->handler = mqnic_rx_irq;

    ring->hw_addr = mqnic_res_get_addr(ring->interface->rxq_res, ring->index);

    ring->prod_ptr = 0;
    ring->cons_ptr = 0;

    // deactivate queue
    iowrite32(MQNIC_QUEUE_CMD_SET_ENABLE | 0,
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set base address
    iowrite32((ring->buf_dma_addr & 0xfffff000),
        ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_VF_REG + 0);
    iowrite32(ring->buf_dma_addr >> 32,
        ring->hw_addr + MQNIC_QUEUE_BASE_ADDR_VF_REG + 4);
    // set size
    iowrite32(MQNIC_QUEUE_CMD_SET_SIZE | ilog2(ring->size) | (ring->log_desc_block_size << 8),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set CQN
    iowrite32(MQNIC_QUEUE_CMD_SET_CQN | ring->cq->cqn,
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    // set pointers
    iowrite32(MQNIC_QUEUE_CMD_SET_PROD_PTR | (ring->prod_ptr & MQNIC_QUEUE_PTR_MASK),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);
    iowrite32(MQNIC_QUEUE_CMD_SET_CONS_PTR | (ring->cons_ptr & MQNIC_QUEUE_PTR_MASK),
        ring->hw_addr + MQNIC_QUEUE_CTRL_STATUS_REG);

    ret = mqnic_refill_rx_buffers(ring);
    if (ret) {
        netdev_err(priv->ndev, "failed to allocate RX buffer for RX queue index %d (of %u total) entry index %u (of %u total)",
            ring->index, priv->rxq_count, ring->prod_ptr, ring->size);
        if (ret == -ENOMEM)
            netdev_err(priv->ndev, "machine might not have enough DMA-capable RAM; try to decrease number of RX channels (currently %u) and/or RX ring parameters (entries; currently %u) and/or module parameter \"num_rxq_entries\" (currently %u)",
                priv->rxq_count, ring->size, mqnic_num_rxq_entries);

        goto fail;
    }

    return 0;

fail:
    mqnic_close_rx_ring(ring);
    return ret;
}

void mqnic_close_rx_ring(struct mqnic_ring* ring) {
    mqnic_disable_rx_ring(ring);

    if (ring->cq) {
        ring->cq->src_ring = NULL;
        ring->cq->handler = NULL;
    }

    ring->priv = NULL;
    ring->cq = NULL;

    ring->hw_addr = NULL;

    if (ring->buf) {
        mqnic_free_rx_buf(ring);
        dma_free_coherent(ring->dev, ring->buf_size, ring->buf, ring->buf_dma_addr);
        ring->buf = NULL;
        ring->buf_dma_addr = 0;
    }

    if (ring->rx_info) {
        //Free the page-pool pages
        struct mqnic_rx_info* rx_info_arr = ring->rx_info;//This is an array 
        struct page* hdr_page;
        netmem_ref pld_netmem;
        for (int i = 0; i < ring->size; i++) {
            hdr_page = rx_info_arr[i].hdr_page;
            pld_netmem = rx_info_arr[i].pld_netmem;
            if (hdr_page) {
                __free_pages(hdr_page, ring->page_order);
            }
            if (pld_netmem) {
                page_pool_put_full_netmem(ring->pp, pld_netmem, false);
            }
        }

        kvfree(ring->rx_info);
        ring->rx_info = NULL;
    }

    mqnic_res_free(ring->interface->rxq_res, ring->index);
    ring->index = -1;

    if (ring->pp) {
        page_pool_destroy(ring->pp);
    }
    ring->pp = NULL;

}
int mqnic_alloc_hdr(struct mqnic_ring* ring, struct page** hdr_page) {
    *hdr_page = dev_alloc_pages(ring->page_order);
    if (unlikely(!(*hdr_page))) {
        dev_err(ring->dev, "%s: failed to allocate header memory on interface %d",
            __func__, ring->interface->index);
        return -ENOMEM;
    }
    return 0;
}
/*This function will automatically give the netmem a dma_addr*/
int mqnic_alloc_pld(struct mqnic_ring* ring, netmem_ref* netmemp) {
    *netmemp = page_pool_alloc_netmem(ring->pp, GFP_ATOMIC);
    if (unlikely(!*netmemp)) {
        dev_err(ring->dev, "%s: failed to allocate payload memory on interface %d",
            __func__, ring->interface->index);
        return -ENOMEM;
    }
    return 0;
}

void mqnic_free_rx_desc(struct mqnic_ring* ring, int index) {
    struct mqnic_rx_info* rx_info = &ring->rx_info[index];

    if (!rx_info->hdr_page)
        return;

    dma_unmap_page(ring->dev, dma_unmap_addr(rx_info, hdr_dma_addr),
        dma_unmap_len(rx_info, hdr_len), DMA_FROM_DEVICE);
    // dma_unmap_page(ring->dev, dma_unmap_addr(rx_info, pld_dma_addr),
    // 	dma_unmap_len(rx_info, pld_len), DMA_FROM_DEVICE);
    rx_info->hdr_dma_addr = 0;
    rx_info->pld_dma_addr = 0;
    __free_pages(rx_info->hdr_page, rx_info->page_order);
    page_pool_put_full_netmem(ring->pp, rx_info->pld_netmem, false);
    rx_info->pld_netmem = NULL;
    rx_info->hdr_page = NULL;
}

int mqnic_free_rx_buf(struct mqnic_ring* ring) {
    u32 index;
    int cnt = 0;

    while (!mqnic_is_rx_ring_empty(ring)) {
        index = ring->cons_ptr & ring->size_mask;
        mqnic_free_rx_desc(ring, index);
        ring->cons_ptr++;
        cnt++;
    }

    return cnt;
}

int mqnic_prepare_rx_desc(struct mqnic_ring* ring, int index) {
    struct mqnic_rx_info* rx_info = &ring->rx_info[index];
    struct mqnic_desc* rx_desc = (struct mqnic_desc*)(ring->buf + index * ring->stride);
    netmem_ref pld_netmem = rx_info->pld_netmem;
    struct page* hdr_page = rx_info->hdr_page;
    u32 page_order = ring->page_order;
    u32 pld_len = PAGE_SIZE << page_order;
    u32 hdr_len = ring->hdr_len;
    dma_addr_t hdr_dma_addr = 0;
    dma_addr_t pld_dma_addr = 0;

    // Not freed by last run
    if (unlikely(pld_netmem)) {
        dev_err(ring->dev, "%s: pld_page not yet processed on interface %d",
            __func__, ring->interface->index);
        return -1;
    }
    if (unlikely(hdr_page)) {
        dev_err(ring->dev, "%s: hdr_page not yet processed on interface %d",
            __func__, ring->interface->index);
        return -1;
    }

    // Allocate and map payload buf netmem
    if (likely(mqnic_alloc_pld(ring, &pld_netmem) == 0)) {
        pld_dma_addr = page_pool_get_dma_addr_netmem(pld_netmem);
    }
    else {
        pr_debug("alloc pld failed dma_addr=%llx\n", pld_dma_addr);
        return -1;
    }

    // Allocate and map payload buf netmem
    if (likely(mqnic_alloc_hdr(ring, &hdr_page) == 0)) {
        hdr_dma_addr = dma_map_page(ring->dev, hdr_page, 0, hdr_len, DMA_FROM_DEVICE);
    }
    else {
        return -1;
    }

    if (unlikely(dma_mapping_error(ring->dev, hdr_dma_addr))) {
        dev_err(ring->dev, "%s: DMA mapping failed on interface %d",
            __func__, ring->interface->index);
        __free_pages(hdr_page, page_order);
        page_pool_put_full_netmem(ring->pp, pld_netmem, false);
        return -1;
    }

    // write descriptor
    rx_desc[0].len = cpu_to_le32(hdr_len);
    rx_desc[0].addr = cpu_to_le64(hdr_dma_addr);
    rx_desc[1].len = cpu_to_le32(pld_len);
    rx_desc[1].addr = cpu_to_le64(pld_dma_addr);


    // update rx_info
    rx_info->page_order = page_order;
    rx_info->page_offset = 0;
    rx_info->hdr_page = hdr_page;
    rx_info->hdr_dma_addr = hdr_dma_addr;
    rx_info->hdr_len = hdr_len;
    rx_info->pld_netmem = pld_netmem;
    rx_info->pld_dma_addr = pld_dma_addr;
    rx_info->pld_len = pld_len;

    return 0;
}

int mqnic_refill_rx_buffers(struct mqnic_ring* ring) {
    u32 missing = ring->size - (ring->prod_ptr - ring->cons_ptr);
    int ret = 0;

    if (missing < 8)
        return 0;

    for (; missing-- > 0;) {
        ret = mqnic_prepare_rx_desc(ring, ring->prod_ptr & ring->size_mask);
        if (ret) {
            pr_err("%s: replenish %d rx buffer failed \n", __func__, missing);
            break;
        }
        ring->prod_ptr++;
    }

    // enqueue on NIC
    dma_wmb();
    mqnic_rx_write_prod_ptr(ring);

    // Swg debug: 
    struct mqnic_cq* cq = ring->cq;
    if (cq->enabled) {
        mqnic_arm_cq(cq);
    }

    return ret;
}

int mqnic_process_rx_cq(struct mqnic_cq* cq, int napi_budget) {
    struct mqnic_if* interface = cq->interface;
    struct device* dev = interface->dev;
    struct mqnic_ring* rx_ring = cq->src_ring;
    struct mqnic_priv* priv = rx_ring->priv;
    struct mqnic_rx_info* rx_info;
    struct mqnic_cpl* cpl;
    struct sk_buff* skb;
    struct page* hdr_page;
    netmem_ref pld_netmem;
    u32 cq_index;
    u32 cq_cons_ptr;
    u32 ring_index;
    u32 ring_cons_ptr;
    int done = 0;
    int budget = napi_budget;
    u16 hdr_len, pld_len;
    // ktime_t start_time, stop_time, elapsed_time;// measure critical section...

    if (unlikely(!priv || !priv->port_up))
        return done;

    // process completion queue
    cq_cons_ptr = cq->cons_ptr;
    cq_index = cq_cons_ptr & cq->size_mask;

    while (done < budget) {
        cpl = (struct mqnic_cpl*)(cq->buf + cq_index * cq->stride);
        if (!!(cpl->phase & cpu_to_le32(0x80000000)) == !!(cq_cons_ptr & cq->size))
            break;

        dma_rmb();

        ring_index = le16_to_cpu(cpl->index) & rx_ring->size_mask;

        rx_info = &rx_ring->rx_info[ring_index];

        hdr_page = rx_info->hdr_page;
        hdr_len = min_t(u32, le16_to_cpu(cpl->len), rx_info->hdr_len);
        pld_netmem = rx_info->pld_netmem;
        pld_len = rx_info->pld_len;

        if (hdr_len < ETH_HLEN) {
            netdev_warn(priv->ndev, "%s: ring %d dropping short frame (header length %d)",
                __func__, rx_ring->index, hdr_len);
            rx_ring->dropped_packets++;
            goto rx_drop;
        }

        if (unlikely(!hdr_page)) {
            netdev_err(priv->ndev, "%s: ring %d null page at index %d; pldnetmem= %x",
                __func__, rx_ring->index, ring_index, pld_netmem);
            print_hex_dump(KERN_ERR, "", DUMP_PREFIX_NONE, 16, 1,
                cpl, MQNIC_CPL_SIZE, true);
            break;
        }

        /* Unmap is purposed to prevent data in buf being overwritten.
                      However, in a recyclable system, it is not possible to double-access buf. So maybe cancel this op.
                      */
        dma_unmap_page(dev, dma_unmap_addr(rx_info, hdr_dma_addr),
            dma_unmap_len(rx_info, hdr_len), DMA_FROM_DEVICE);
        dma_sync_single_range_for_cpu(dev, rx_info->hdr_dma_addr, rx_info->page_offset,
            hdr_len, DMA_FROM_DEVICE);
        dma_sync_single_for_cpu(dev, rx_info->pld_dma_addr, pld_len, DMA_FROM_DEVICE);
        rx_info->hdr_dma_addr = 0;
        rx_info->pld_dma_addr = 0;
        // Clear refcnt. (Q: Actually is it better to rely on page->refcnt?)
        rx_info->hdr_page = NULL;
        rx_info->pld_netmem = NULL;

        int trim = 0;
        // Hack! modify the header length field here.
        if (cpl->len > rx_ring->hdr_len) {
            trim = -12; //12 bytes of option field 66-12=54
        }

        // SKB handling: we should have a small copied header and attach a netmem as a frag
        skb = mqnic_skb_copy_header(priv->ndev, &cq->napi, hdr_page, hdr_len+trim);
        if (unlikely(!skb)) {
            netdev_err(priv->ndev, "%s: ring %d failed to allocate skb",
                __func__, rx_ring->index);
            break;
        }
        skb_mark_for_recycle(skb);
        skb_record_rx_queue(skb, rx_ring->index);
        // RX hardware timestamp
        if (interface->if_features & MQNIC_IF_FEATURE_PTP_TS)
            skb_hwtstamps(skb)->hwtstamp = mqnic_read_cpl_ts(interface->mdev, rx_ring, cpl);
        // RX hardware checksum
        if (priv->ndev->features & NETIF_F_RXCSUM) {
            skb->csum = csum_unfold((__sum16)cpu_to_be16(le16_to_cpu(cpl->rx_csum)));
            /*COMPLETE means the NIC calculate csum AS A WHOLE. So the network stack has
            to do a second parse, while it is much lighter. But UNNECESSARY means
            the network stack wont worry about csum at all.*/
            // skb->ip_summed = CHECKSUM_COMPLETE;  
            skb->ip_summed = CHECKSUM_UNNECESSARY;
        }

        if (cpl->len > hdr_len) {
            int error = mqnic_skb_append_frag(&cq->napi, pld_netmem, pld_len, skb, priv);
            if (unlikely(error != 0)) {
                page_pool_put_full_netmem(rx_ring->pp, pld_netmem, false);
                pld_netmem = NULL;
                netdev_err(priv->ndev, "%s: ring %d failed to append frag",
                    __func__, rx_ring->index);
                goto rx_drop;
            }
        }
        // hand off SKB
        napi_gro_receive(&cq->napi, skb);

        rx_ring->packets++;
        rx_ring->bytes += le16_to_cpu(cpl->len);

    rx_drop:
        done++;

        cq_cons_ptr++;
        cq_index = cq_cons_ptr & cq->size_mask;
    }

    // update CQ consumer pointer
    cq->cons_ptr = cq_cons_ptr;
    mqnic_cq_write_cons_ptr(cq);

    // process ring
    ring_cons_ptr = READ_ONCE(rx_ring->cons_ptr);
    ring_index = ring_cons_ptr & rx_ring->size_mask;

    while (ring_cons_ptr != rx_ring->prod_ptr) {
        rx_info = &rx_ring->rx_info[ring_index];

        if (rx_info->hdr_page)
            break;

        ring_cons_ptr++;
        ring_index = ring_cons_ptr & rx_ring->size_mask;
    }

    // update consumer pointer
    WRITE_ONCE(rx_ring->cons_ptr, ring_cons_ptr);

    // replenish buffers
    mqnic_refill_rx_buffers(rx_ring);

    return done;
}

int mqnic_poll_rx_cq(struct napi_struct* napi, int budget) {
    // pr_debug("%s: IRQ triggered\n", __func__);
    struct mqnic_cq* cq = container_of(napi, struct mqnic_cq, napi);
    int done;

    done = mqnic_process_rx_cq(cq, budget);
    if (done == budget)
        return done;

    if (napi_complete(napi))
        mqnic_arm_cq(cq);

    return done;
}
struct sk_buff* mqnic_skb_copy_header(struct net_device* dev, struct napi_struct* napi,
    struct page* page, u16 len) {
    struct sk_buff* skb;
    skb = napi_alloc_skb(napi, len);
    if (unlikely(!skb))
        return NULL;
    __skb_put(skb, len);
    if (unlikely(!page)) {
        return NULL;
    }
    skb_copy_to_linear_data_offset(skb, 0, page_address(page), len);
    skb->protocol = eth_type_trans(skb, dev);

    return skb;
}

int mqnic_skb_append_frag(struct napi_struct* napi, netmem_ref pld_netmem, u16 pld_len,
    struct sk_buff* skb, struct mqnic_priv* priv) {
    int num_frags = skb_shinfo(skb)->nr_frags;

    /*TODO: should have a fallback copy mode*/
    skb_add_rx_frag_netmem(skb, num_frags, pld_netmem, 0, pld_len, /*truesize:*/4096);
    /*For userpages,
    1. we should decrement the refcnt because as soon as we hand off the header
    to kernel, no one is holding the userpage(udmabuf)
    2. We should free the buf_state
    */
    return 0;
}

