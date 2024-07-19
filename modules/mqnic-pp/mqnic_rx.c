// SPDX-License-Identifier: BSD-2-Clause-Views
/*
 * Copyright (c) 2019-2023 The Regents of the University of California
 */

#include "mqnic.h"
#include "debug.h"

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
	ring->hdr_len = 96;
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
	// pp_params.netdev = priv->dev;
	pp_params.flags = PP_FLAG_DMA_MAP;
	pp_params.dma_dir = DMA_FROM_DEVICE;
	// pp_params.queue = __netif_get_rx_queue(priv->dev, rx->q_num);
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
		kvfree(ring->rx_info);
		ring->rx_info = NULL;
	}

	mqnic_res_free(ring->interface->rxq_res, ring->index);
	ring->index = -1;

	if (ring->pp) {
		page_pool_destroy(ring->pp);
	}

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

void mqnic_free_rx_desc(struct mqnic_ring* ring, int index) {
	struct mqnic_rx_info* rx_info = &ring->rx_info[index];

	if (!rx_info->hdr_page)
		return;

	dma_unmap_page(ring->dev, dma_unmap_addr(rx_info, hdr_dma_addr),
		dma_unmap_len(rx_info, hdr_len), DMA_FROM_DEVICE);
	dma_unmap_page(ring->dev, dma_unmap_addr(rx_info, pld_dma_addr),
		dma_unmap_len(rx_info, pld_len), DMA_FROM_DEVICE);
	rx_info->hdr_dma_addr = 0;
	rx_info->pld_dma_addr = 0;
	__free_pages(rx_info->hdr_page, rx_info->page_order);
	page_pool_put_full_page(ring->pp, rx_info->pld_page, false);
	rx_info->pld_page = NULL;
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
	struct page* pld_page = rx_info->pld_page;
	struct page* hdr_page = rx_info->hdr_page;
	u32 page_order = ring->page_order;
	u32 pld_len = PAGE_SIZE << page_order;
	u32 hdr_len = ring->hdr_len;
	dma_addr_t hdr_dma_addr;
	dma_addr_t pld_dma_addr;

	// Not freed by last run
	if (unlikely(pld_page)) {
		dev_err(ring->dev, "%s: pld_page not yet processed on interface %d",
			__func__, ring->interface->index);
		return -1;
	}
	if (unlikely(hdr_page)) {
		dev_err(ring->dev, "%s: hdr_page not yet processed on interface %d",
			__func__, ring->interface->index);
		return -1;
	}

	//call page pool here
	pld_page = page_pool_alloc_pages(ring->pp, GFP_KERNEL);
	if (unlikely(!pld_page)) {
		dev_err(ring->dev, "%s: failed to allocate payload memory on interface %d",
			__func__, ring->interface->index);
		return -ENOMEM;
	}
	hdr_page = dev_alloc_pages(page_order);
	if (unlikely(!hdr_page)) {
		dev_err(ring->dev, "%s: failed to allocate header memory on interface %d",
			__func__, ring->interface->index);
		return -ENOMEM;
	}

	// map payload page
	pld_dma_addr = dma_map_page(ring->dev, pld_page, 0, pld_len, DMA_FROM_DEVICE);
	//map header page
	hdr_dma_addr = dma_map_page(ring->dev, hdr_page, 0, hdr_len, DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(ring->dev, pld_dma_addr)) || unlikely(dma_mapping_error(ring->dev, hdr_dma_addr))) {
		dev_err(ring->dev, "%s: DMA mapping failed on interface %d",
			__func__, ring->interface->index);
		__free_pages(hdr_page, page_order);
		page_pool_put_full_page(ring->pp, pld_page, false);
		return -1;
	}

	// write descriptor
	// rx_desc->len = cpu_to_le32(len);
	// rx_desc->addr = cpu_to_le64(dma_addr);
	rx_desc[0].len = cpu_to_le32(hdr_len);
	rx_desc[0].addr = cpu_to_le64(hdr_dma_addr);
	rx_desc[1].len = cpu_to_le32(pld_len);
	rx_desc[1].addr = cpu_to_le64(pld_dma_addr);

	// update rx_info
	// rx_info->page = page;
	// rx_info->page_order = page_order;
	// rx_info->page_offset = 0;
	// rx_info->dma_addr = hdr_dma_addr;// Test: only get header
	// rx_info->len = ring->hdr_len;

	rx_info->page_order = page_order;
	rx_info->page_offset = 0;
	rx_info->hdr_page = hdr_page;
	rx_info->hdr_dma_addr = hdr_dma_addr;
	rx_info->hdr_len = hdr_len;
	rx_info->pld_page = pld_page;
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
		if (ret)
			break;
		ring->prod_ptr++;
	}

	// enqueue on NIC
	dma_wmb();
	mqnic_rx_write_prod_ptr(ring);

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
	struct page* pld_page;
	u32 cq_index;
	u32 cq_cons_ptr;
	u32 ring_index;
	u32 ring_cons_ptr;
	int done = 0;
	int budget = napi_budget;
	u16 hdr_len, pld_len;
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
		pld_page = rx_info->pld_page;
		pld_len = rx_info->pld_len;

		if (hdr_len < ETH_HLEN) {
			netdev_warn(priv->ndev, "%s: ring %d dropping short frame (header length %d)",
				__func__, rx_ring->index, hdr_len);
			rx_ring->dropped_packets++;
			goto rx_drop;
		}

		if (unlikely(!hdr_page)) {
			netdev_err(priv->ndev, "%s: ring %d null page at index %d",
				__func__, rx_ring->index, ring_index);
			print_hex_dump(KERN_ERR, "", DUMP_PREFIX_NONE, 16, 1,
				cpl, MQNIC_CPL_SIZE, true);
			break;
		}

		skb = napi_get_frags(&cq->napi);
		if (unlikely(!skb)) {
			netdev_err(priv->ndev, "%s: ring %d failed to allocate skb",
				__func__, rx_ring->index);
			break;
		}
		skb_mark_for_recycle(skb);

		// RX hardware timestamp
		if (interface->if_features & MQNIC_IF_FEATURE_PTP_TS)
			skb_hwtstamps(skb)->hwtstamp = mqnic_read_cpl_ts(interface->mdev, rx_ring, cpl);

		skb_record_rx_queue(skb, rx_ring->index);

		// RX hardware checksum
		if (priv->ndev->features & NETIF_F_RXCSUM) {
			skb->csum = csum_unfold((__sum16)cpu_to_be16(le16_to_cpu(cpl->rx_csum)));
			skb->ip_summed = CHECKSUM_COMPLETE;
		}

		// unmap
		// swg comment: this is to prevent the page being dma-overwritten
		dma_unmap_page(dev, dma_unmap_addr(rx_info, hdr_dma_addr),
			dma_unmap_len(rx_info, hdr_len), DMA_FROM_DEVICE);
		rx_info->hdr_dma_addr = 0;
		dma_unmap_page(dev, dma_unmap_addr(rx_info, pld_dma_addr),
			dma_unmap_len(rx_info, pld_len), DMA_FROM_DEVICE);
		rx_info->pld_dma_addr = 0;

		dma_sync_single_range_for_cpu(dev, rx_info->hdr_dma_addr, rx_info->page_offset,
			hdr_len, DMA_FROM_DEVICE);
		dma_sync_single_range_for_cpu(dev, rx_info->pld_dma_addr, rx_info->page_offset,
			pld_len, DMA_FROM_DEVICE);

		__skb_fill_page_desc(skb, 0, hdr_page, rx_info->page_offset, hdr_len);

		// Clear refcnt. (Q: Actually is it better to rely on page->refcnt?)
		rx_info->hdr_page = NULL;
		rx_info->pld_page = NULL;

		/* 15:30, Jul 18
			The problem is in the second page.
			If nothing is sent to the 2nd page yet we still add it to the frag, kernel will break.
			Ultimately, this will need to be addressed in hw's cpl logic. But now lets hack it.

			Problem might be pld_len...
		*/
		if (cpl->len <= hdr_len) {// Note that for now i can not send exactly 8Byte
			/* ARP or small TCP, small packet (payload<=8B) */
			// pr_info("TCP small! cpl_id=%d", cpl->index);
			skb_shinfo(skb)->nr_frags = 1;
			skb->len = hdr_len;
			skb->data_len = hdr_len;
			skb->truesize += rx_info->hdr_len;
		}
		else {
			/* TCP, large packet */
			// pr_info("TCP! cpl_id=%d", cpl->index);
			__skb_fill_page_desc(skb, 1, pld_page, rx_info->page_offset, pld_len);
			skb_shinfo(skb)->nr_frags = 2;
			skb->len += hdr_len + pld_len;
			skb->data_len += hdr_len + pld_len;
			skb->truesize += hdr_len + pld_len;
		}

		// pr_cont("...==Cpl index= %d, cpl-len= %d, in ring<%d>\n", cq_index, cpl->len, rx_ring->index);
		// print_pg(hdr_page, hdr_len);
		// if (cpl->len > 74) {
		// 	pr_cont("-----^hdr, vpld----------\n");
		// 	print_pg(pld_page, 32);
		// }
		// pr_cont("\n===============END===============");

		// hand off SKB
		napi_gro_frags(&cq->napi);

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

void mqnic_rx_irq(struct mqnic_cq* cq) {
	napi_schedule_irqoff(&cq->napi);
}

int mqnic_poll_rx_cq(struct napi_struct* napi, int budget) {
	struct mqnic_cq* cq = container_of(napi, struct mqnic_cq, napi);
	int done;

	done = mqnic_process_rx_cq(cq, budget);
	if (done == budget)
		return done;

	napi_complete(napi);

	mqnic_arm_cq(cq);

	return done;
}
