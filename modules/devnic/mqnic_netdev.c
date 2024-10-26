// SPDX-License-Identifier: BSD-2-Clause-Views
/*
 * Copyright (c) 2019-2023 The Regents of the University of California
 */

#include "mqnic.h"
#include <net/netdev_queues.h>

#include <linux/version.h>

 /* Allocate all rings and assign CQs to them */
int mqnic_start_port(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_if* iface = priv->interface;
    struct mqnic_ring* q;
    struct mqnic_cq* cq;
    struct radix_tree_iter iter;
    void** slot;
    int k;
    int ret;
    u32 desc_block_size;

    netdev_info(ndev, "%s on interface %d netdev %d, rxq size= %d", __func__,
        priv->interface->index, priv->index, priv->rx_ring_size);

    netif_set_real_num_tx_queues(ndev, priv->txq_count);
    netif_set_real_num_rx_queues(ndev, priv->rxq_count);

    desc_block_size = min_t(u32, priv->interface->max_desc_block_size, 4);

    // set up RX queues
    for (k = 0; k < priv->rxq_count; k++) {
        // create CQ
        cq = mqnic_create_cq(iface);
        if (IS_ERR_OR_NULL(cq)) {
            ret = PTR_ERR(cq);
            goto fail;
        }

        ret = mqnic_open_cq(cq, iface->eq[k % iface->eq_count], priv->rx_ring_size);
        if (ret) {
            mqnic_destroy_cq(cq);
            goto fail;
        }

        netif_napi_add(ndev, &cq->napi, mqnic_poll_rx_cq);

        napi_enable(&cq->napi);

        mqnic_arm_cq(cq);

        // create RX queue
        q = mqnic_create_rx_ring(iface);
        if (IS_ERR_OR_NULL(q)) {
            ret = PTR_ERR(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }

        q->mtu = ndev->mtu;
        if (ndev->mtu + ETH_HLEN <= PAGE_SIZE)
            q->page_order = 0;
        else
            q->page_order = ilog2((ndev->mtu + ETH_HLEN + PAGE_SIZE - 1) / PAGE_SIZE - 1) + 1;

        //Desc_block_size=2, means we have 2 descs per stride, one kernel, one user.
        ret = mqnic_open_rx_ring(q, priv, cq, priv->rx_ring_size, 2);
        if (ret) {
            mqnic_destroy_rx_ring(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }

        down_write(&priv->rxq_table_sem);
        ret = radix_tree_insert(&priv->rxq_table, k, q);
        up_write(&priv->rxq_table_sem);
        if (ret) {
            mqnic_destroy_rx_ring(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }
    }

    // set up TX queues
    for (k = 0; k < priv->txq_count; k++) {
        // create CQ
        cq = mqnic_create_cq(iface);
        if (IS_ERR_OR_NULL(cq)) {
            ret = PTR_ERR(cq);
            goto fail;
        }

        ret = mqnic_open_cq(cq, iface->eq[k % iface->eq_count], priv->tx_ring_size);
        if (ret) {
            mqnic_destroy_cq(cq);
            goto fail;
        }

        netif_napi_add_tx(ndev, &cq->napi, mqnic_poll_tx_cq);

        napi_enable(&cq->napi);

        mqnic_arm_cq(cq);

        // create TX queue
        q = mqnic_create_tx_ring(iface);
        if (IS_ERR_OR_NULL(q)) {
            ret = PTR_ERR(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }

        q->tx_queue = netdev_get_tx_queue(ndev, k);

        ret = mqnic_open_tx_ring(q, priv, cq, priv->tx_ring_size, desc_block_size);
        if (ret) {
            mqnic_destroy_tx_ring(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }

        down_write(&priv->txq_table_sem);
        ret = radix_tree_insert(&priv->txq_table, k, q);
        up_write(&priv->txq_table_sem);
        if (ret) {
            mqnic_destroy_tx_ring(q);
            mqnic_destroy_cq(cq);
            goto fail;
        }
    }

    // set MTU
    mqnic_interface_set_tx_mtu(iface, ndev->mtu + ETH_HLEN);
    mqnic_interface_set_rx_mtu(iface, ndev->mtu + ETH_HLEN);

    // configure RX indirection and RSS
    mqnic_update_indir_table(ndev);

    priv->port_up = true;

    // enable TX and RX queues
    down_read(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        mqnic_enable_tx_ring(q);
    }
    up_read(&priv->txq_table_sem);

    down_read(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        mqnic_enable_rx_ring(q);
    }
    up_read(&priv->rxq_table_sem);

    mqnic_port_set_tx_ctrl(priv->port, MQNIC_PORT_TX_CTRL_EN);

    // enable scheduler
    mqnic_activate_sched_block(priv->sched_block);

    netif_tx_start_all_queues(ndev);
    netif_device_attach(ndev);

    if (mqnic_link_status_poll) {
        priv->link_status = 0;
        mod_timer(&priv->link_status_timer,
            jiffies + msecs_to_jiffies(mqnic_link_status_poll));
    }
    else {
        netif_carrier_on(ndev);
    }

    mqnic_port_set_rx_ctrl(priv->port, MQNIC_PORT_RX_CTRL_EN);

    return 0;

fail:
    mqnic_stop_port(ndev);
    return ret;
}

void mqnic_stop_port(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_cq* cq;
    struct radix_tree_iter iter;
    void** slot;

    netdev_info(ndev, "%s on interface %d netdev %d", __func__,
        priv->interface->index, priv->index);

    if (mqnic_link_status_poll)
        del_timer_sync(&priv->link_status_timer);

    mqnic_port_set_rx_ctrl(priv->port, 0);

    netif_tx_lock_bh(ndev);
    //	if (detach)
    //		netif_device_detach(ndev);
    netif_tx_stop_all_queues(ndev);
    netif_tx_unlock_bh(ndev);

    netif_carrier_off(ndev);
    netif_tx_disable(ndev);

    spin_lock_bh(&priv->stats_lock);
    mqnic_update_stats(ndev);
    spin_unlock_bh(&priv->stats_lock);

    // disable scheduler
    mqnic_deactivate_sched_block(priv->sched_block);

    // disable TX and RX queues
    down_read(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        mqnic_disable_tx_ring(q);
    }
    up_read(&priv->txq_table_sem);

    down_read(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        mqnic_disable_rx_ring(q);
    }
    up_read(&priv->rxq_table_sem);

    msleep(20);

    mqnic_port_set_tx_ctrl(priv->port, 0);

    priv->port_up = false;

    // shut down NAPI and clean queues
    down_write(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        cq = q->cq;
        napi_disable(&cq->napi);
        netif_napi_del(&cq->napi);
        mqnic_close_tx_ring(q);
        mqnic_destroy_tx_ring(q);
        radix_tree_delete(&priv->txq_table, iter.index);
        mqnic_close_cq(cq);
        mqnic_destroy_cq(cq);
    }
    up_write(&priv->txq_table_sem);

    down_write(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        cq = q->cq;
        napi_disable(&cq->napi);
        netif_napi_del(&cq->napi);
        mqnic_close_rx_ring(q);
        mqnic_destroy_rx_ring(q);
        radix_tree_delete(&priv->rxq_table, iter.index);
        mqnic_close_cq(cq);
        mqnic_destroy_cq(cq);
    }
    up_write(&priv->rxq_table_sem);
}

static int mqnic_open(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_dev* mdev = priv->mdev;
    int ret = 0;

    mutex_lock(&mdev->state_lock);

    ret = mqnic_start_port(ndev);

    if (ret)
        netdev_err(ndev, "Failed to start port on interface %d netdev %d: %d",
            priv->interface->index, priv->index, ret);

    mutex_unlock(&mdev->state_lock);
    return ret;
}

static int mqnic_close(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_dev* mdev = priv->mdev;
    int ret = 0;

    mutex_lock(&mdev->state_lock);

    mqnic_stop_port(ndev);

    mutex_unlock(&mdev->state_lock);
    return ret;
}

int mqnic_update_indir_table(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_if* iface = priv->interface;
    struct mqnic_ring* q;
    int k;

    mqnic_interface_set_rx_queue_map_rss_mask(iface, 0, 0xffffffff);
    mqnic_interface_set_rx_queue_map_app_mask(iface, 0, 0);

    for (k = 0; k < priv->rx_queue_map_indir_table_size; k++) {
        rcu_read_lock();
        q = radix_tree_lookup(&priv->rxq_table, priv->rx_queue_map_indir_table[k]);
        rcu_read_unlock();

        if (q)
            mqnic_interface_set_rx_queue_map_indir_table(iface, 0, k, q->index);
    }

    return 0;
}

void mqnic_update_stats(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct radix_tree_iter iter;
    void** slot;
    unsigned long packets, bytes;
    unsigned long dropped;

    if (unlikely(!priv->port_up))
        return;

    packets = 0;
    bytes = 0;
    dropped = 0;
    down_read(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        const struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        packets += READ_ONCE(q->packets);
        bytes += READ_ONCE(q->bytes);
        dropped += READ_ONCE(q->dropped_packets);
    }
    up_read(&priv->rxq_table_sem);
    ndev->stats.rx_packets = packets;
    ndev->stats.rx_bytes = bytes;
    ndev->stats.rx_dropped = dropped;

    packets = 0;
    bytes = 0;
    dropped = 0;
    down_read(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        const struct mqnic_ring* q = (struct mqnic_ring*)*slot;

        packets += READ_ONCE(q->packets);
        bytes += READ_ONCE(q->bytes);
        dropped += READ_ONCE(q->dropped_packets);
    }
    up_read(&priv->txq_table_sem);
    ndev->stats.tx_packets = packets;
    ndev->stats.tx_bytes = bytes;
    ndev->stats.tx_dropped = dropped;
}

static void mqnic_get_stats64(struct net_device* ndev,
    struct rtnl_link_stats64* stats) {
    struct mqnic_priv* priv = netdev_priv(ndev);

    spin_lock_bh(&priv->stats_lock);
    mqnic_update_stats(ndev);
    netdev_stats_to_stats64(stats, &ndev->stats);
    spin_unlock_bh(&priv->stats_lock);
}

static int mqnic_hwtstamp_set(struct net_device* ndev, struct ifreq* ifr) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct hwtstamp_config hwts_config;

    if (copy_from_user(&hwts_config, ifr->ifr_data, sizeof(hwts_config)))
        return -EFAULT;

    if (hwts_config.flags)
        return -EINVAL;

    switch (hwts_config.tx_type) {
    case HWTSTAMP_TX_OFF:
    case HWTSTAMP_TX_ON:
        break;
    default:
        return -ERANGE;
    }

    switch (hwts_config.rx_filter) {
    case HWTSTAMP_FILTER_NONE:
        break;
    case HWTSTAMP_FILTER_ALL:
    case HWTSTAMP_FILTER_SOME:
    case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
    case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
    case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
    case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
    case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
    case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
    case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
    case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
    case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
    case HWTSTAMP_FILTER_PTP_V2_EVENT:
    case HWTSTAMP_FILTER_PTP_V2_SYNC:
    case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
    case HWTSTAMP_FILTER_NTP_ALL:
        hwts_config.rx_filter = HWTSTAMP_FILTER_ALL;
        break;
    default:
        return -ERANGE;
    }

    memcpy(&priv->hwts_config, &hwts_config, sizeof(hwts_config));

    if (copy_to_user(ifr->ifr_data, &hwts_config, sizeof(hwts_config)))
        return -EFAULT;

    return 0;
}

static int mqnic_hwtstamp_get(struct net_device* ndev, struct ifreq* ifr) {
    struct mqnic_priv* priv = netdev_priv(ndev);

    if (copy_to_user(ifr->ifr_data, &priv->hwts_config, sizeof(priv->hwts_config)))
        return -EFAULT;

    return 0;
}

static int mqnic_change_mtu(struct net_device* ndev, int new_mtu) {
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_dev* mdev = priv->mdev;

    if (new_mtu < ndev->min_mtu || new_mtu > ndev->max_mtu) {
        netdev_err(ndev, "Bad MTU: %d", new_mtu);
        return -EPERM;
    }

    netdev_info(ndev, "New MTU: %d", new_mtu);

    ndev->mtu = new_mtu;

    if (netif_running(ndev)) {
        mutex_lock(&mdev->state_lock);

        mqnic_stop_port(ndev);
        mqnic_start_port(ndev);

        mutex_unlock(&mdev->state_lock);
    }

    return 0;
}

static int mqnic_ioctl(struct net_device* ndev, struct ifreq* ifr, int cmd) {
    switch (cmd) {
    case SIOCSHWTSTAMP:
        return mqnic_hwtstamp_set(ndev, ifr);
    case SIOCGHWTSTAMP:
        return mqnic_hwtstamp_get(ndev, ifr);
    default:
        return -EOPNOTSUPP;
    }
}

static const struct net_device_ops mqnic_netdev_ops = {
    .ndo_open = mqnic_open,
    .ndo_stop = mqnic_close,
    .ndo_start_xmit = mqnic_start_xmit,
    .ndo_get_stats64 = mqnic_get_stats64,
    .ndo_validate_addr = eth_validate_addr,
    .ndo_change_mtu = mqnic_change_mtu,
    .ndo_eth_ioctl = mqnic_ioctl
};


/* HDS: add queue_mgmt_ops for net_devmem_bind_dmabuf_to_queue()->netdev_rx_queue_restart. */

/* ===== Below turnup/down are utils for rx_queue_mgmt_ops ===== */
void mqnic_turndown(struct mqnic_priv* priv) {
    void** slot;
    struct radix_tree_iter iter;
    struct mqnic_cq* cq;

    down_read(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;
        cq = q->cq;
        if (&cq->napi) {
            napi_disable(&cq->napi);
        }
    }
    up_read(&priv->txq_table_sem);

    down_read(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;
        cq = q->cq;
        if (&cq->napi) {
            napi_disable(&cq->napi);
        }
    }
    up_read(&priv->rxq_table_sem);
    netif_tx_disable(priv->ndev);
}
void mqnic_turnup(struct mqnic_priv* priv) {
    void** slot;
    struct radix_tree_iter iter;
    struct mqnic_cq* cq;
    //Turn up other queues
    down_read(&priv->txq_table_sem);
    radix_tree_for_each_slot(slot, &priv->txq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;
        cq = q->cq;
        if (&cq->napi) {
            napi_enable(&cq->napi);
        }
    }
    up_read(&priv->txq_table_sem);

    down_read(&priv->rxq_table_sem);
    radix_tree_for_each_slot(slot, &priv->rxq_table, &iter, 0) {
        struct mqnic_ring* q = (struct mqnic_ring*)*slot;
        cq = q->cq;
        if (&cq->napi) {
            napi_enable(&cq->napi);
        }
    }
    up_read(&priv->rxq_table_sem);

    netif_tx_start_all_queues(priv->ndev);
}

/* Create a rx_ring; do NOT configure its CQ and other params; do NOT add napi */
static int mqnic_rx_queue_mem_alloc(struct net_device* ndev, void* per_q_mem, int idx) {
    return 0;
    // int err = 0;
    // struct mqnic_priv* priv = netdev_priv(ndev);
    // struct mqnic_if* iface = priv->interface;
    // /* Configure new rx_queue */
    // struct mqnic_ring* rx_ring = (struct mqnic_ring*)per_q_mem;
    // {	// This part belongs to mqnic_create_rx_ring
    // 	rx_ring->interface = iface;
    // 	rx_ring->dev = iface->dev;
    // 	rx_ring->index = -1;
    // 	rx_ring->enabled = 0;
    // 	rx_ring->hw_addr = NULL;
    // 	rx_ring->prod_ptr = 0;
    // 	rx_ring->cons_ptr = 0;

    // 	rx_ring->mtu = ndev->mtu;
    // 	if (ndev->mtu + ETH_HLEN <= PAGE_SIZE)
    // 		rx_ring->page_order = 0;
    // 	else
    // 		rx_ring->page_order = ilog2((ndev->mtu + ETH_HLEN + PAGE_SIZE - 1) / PAGE_SIZE - 1) + 1;
    // }
    // return err;
}
static void mqnic_rx_queue_mem_free(struct net_device* ndev, void* per_q_mem) {
    // Dont do anything. queue_stop has done the job.
    // return;
    // int err = 0;
    // struct mqnic_ring* target_ring = (struct mqnic_ring*)per_q_mem;
    // struct mqnic_cq* target_cq = target_ring->cq;
    // if (target_cq) {
    // 	kfree(target_cq);
    // }
    // if (target_ring) {
    // 	kfree(target_ring);
    // }

    // // 1. Get CQ and destroy.
    // cq = rx_ring->cq;
    // if (cq)
    // {
    // 	mqnic_close_cq(cq);
    // 	mqnic_destroy_cq(cq);
    // }

    // // 2. Free rx_queue
    // mqnic_disable_rx_ring(rx_ring);
    // mqnic_destroy_rx_ring(rx_ring);

}
/* Add the rx_queue to priv's radix tree; netif_add_napi */
static int mqnic_rx_queue_start(struct net_device* ndev, void* per_q_mem, int idx) {

    int err = 0;
    struct mqnic_ring* rx_ring;
    struct mqnic_cq* cq;
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_if* iface = priv->interface;

    /* 1.1 allocate CQ and rx_ring*/
    cq = mqnic_create_cq(iface);
    err = hds_mqnic_open_cq(cq, iface->eq[idx % iface->eq_count], priv->rx_ring_size, idx);
    netif_napi_add(ndev, &cq->napi, mqnic_poll_rx_cq);
    napi_enable(&cq->napi);
    mqnic_arm_cq(cq);
    /* 1.2 rx_ring Allocate buffers and post descs */
    // Obtain the to-be-started rx_queue
    rx_ring = mqnic_create_rx_ring(iface);
    err = hds_mqnic_open_rx_ring(rx_ring, priv, cq, priv->rx_ring_size, 2, idx);

    /* Debug: Add the rx queue... */
    struct netdev_rx_queue* rxq = __netif_get_rx_queue(ndev, idx);
    pr_err("%s: the passed-down rxq<%d> has mp_priv=%lx", __func__, idx, rxq->mp_params.mp_priv);
    // 2. Add to priv
    down_write(&priv->rxq_table_sem);
    err = radix_tree_insert(&priv->rxq_table, idx, rx_ring);
    up_write(&priv->rxq_table_sem);
    if (err) {
        return err;
    }

    // // // 3. Turn down all other current rx/rx queues
    // // mqnic_turndown(priv);

    // 4. Start the target rx queue
    mqnic_enable_rx_ring(rx_ring);

    // // // 4. Turn up
    // // mqnic_turnup(priv);

    return err;
}
/*
Disable napi for all queues;
Delete target_ring napi
Re-initialize (clear to zero) target_ring, free pages if available
Delete target from radix tree
Return the target's address so that we can later free resources.
*/
static int mqnic_rx_queue_stop(struct net_device* ndev, void* per_q_mem, int idx) {
    struct mqnic_ring* target_ring;
    struct mqnic_cq* target_cq;
    struct mqnic_priv* priv = netdev_priv(ndev);
    struct mqnic_if* iface = priv->interface;

    // // 1. Turn down all queues (diable napi).
    // // mqnic_turndown(priv);

    // 2. Stop the target queue by setting hw bit
    // Note that we dont free the ring itself here.
    target_ring = radix_tree_lookup(&priv->rxq_table, idx);
    target_cq = target_ring->cq;
    mqnic_disable_rx_ring(target_ring);
    if (&target_cq->napi) {
        napi_disable(&target_cq->napi);
        netif_napi_del(&target_cq->napi);
    }
    mqnic_close_rx_ring(target_ring);
    mqnic_close_cq(target_cq);
    mqnic_destroy_rx_ring(target_ring);
    mqnic_destroy_cq(target_cq);

    // 3. Remove from tree
    down_write(&priv->rxq_table_sem);
    radix_tree_delete(&priv->rxq_table, idx);
    up_write(&priv->rxq_table_sem);

    // // // 4. Turn up
    // // mqnic_turnup(priv);

    // // // This rx_ring address will be returned.
    // // rx_ring = (struct mqnic_ring*)per_q_mem;
    // // *rx_ring = *target_ring;
    // // rx_ring->cq = target_cq;// In order to free cq's mem

    return 0;
}

static const struct netdev_queue_mgmt_ops mqnic_queue_mgmt_ops = {
    .ndo_queue_mem_size = sizeof(struct mqnic_ring),
    .ndo_queue_mem_alloc = mqnic_rx_queue_mem_alloc,
    .ndo_queue_mem_free = mqnic_rx_queue_mem_free,
    .ndo_queue_start = mqnic_rx_queue_start,
    .ndo_queue_stop = mqnic_rx_queue_stop
};

static void mqnic_link_status_timeout(struct timer_list* timer) {
    struct mqnic_priv* priv = from_timer(priv, timer, link_status_timer);
    unsigned int up = 1;

    if (!(mqnic_port_get_tx_ctrl(priv->port) & MQNIC_PORT_TX_CTRL_STATUS))
        up = 0;
    if (!(mqnic_port_get_rx_ctrl(priv->port) & MQNIC_PORT_RX_CTRL_STATUS))
        up = 0;

    if (up) {
        if (!priv->link_status) {
            netif_carrier_on(priv->ndev);
            priv->link_status = !priv->link_status;
        }
    }
    else {
        if (priv->link_status) {
            netif_carrier_off(priv->ndev);
            priv->link_status = !priv->link_status;
        }
    }

    mod_timer(&priv->link_status_timer, jiffies + msecs_to_jiffies(mqnic_link_status_poll));
}

struct net_device* mqnic_create_netdev(struct mqnic_if* interface, int index,
    struct mqnic_port* port, struct mqnic_sched_block* sched_block) {
    struct mqnic_dev* mdev = interface->mdev;
    struct device* dev = interface->dev;
    struct net_device* ndev;
    struct mqnic_priv* priv;
    int ret = 0;
    int k;

    ndev = alloc_etherdev_mqs(sizeof(*priv), mqnic_res_get_count(interface->txq_res),
        mqnic_res_get_count(interface->rxq_res));
    if (!ndev) {
        dev_err(dev, "Failed to allocate memory");
        return ERR_PTR(-ENOMEM);
    }

    SET_NETDEV_DEV(ndev, dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    SET_NETDEV_DEVLINK_PORT(ndev, &port->dl_port);
#endif
    ndev->dev_port = port->phys_index;

    // init private data
    priv = netdev_priv(ndev);
    memset(priv, 0, sizeof(struct mqnic_priv));

    spin_lock_init(&priv->stats_lock);

    priv->ndev = ndev;
    priv->mdev = interface->mdev;
    priv->dl_port = &port->dl_port;
    priv->interface = interface;
    priv->dev = dev;
    priv->index = index;
    priv->port = port;
    priv->port_up = false;
    priv->sched_block = sched_block;

    // associate interface resources
    priv->if_features = interface->if_features;

    priv->txq_count = min_t(u32, mqnic_res_get_count(interface->txq_res), 256);
    // Hack! Keep only one rx_queue
    priv->rxq_count = min_t(u32, mqnic_res_get_count(interface->rxq_res), num_online_cpus());
    // priv->rxq_count = 1;


    priv->tx_ring_size = roundup_pow_of_two(clamp_t(u32, mqnic_num_txq_entries,
        MQNIC_MIN_TX_RING_SZ, MQNIC_MAX_TX_RING_SZ));
    priv->rx_ring_size = roundup_pow_of_two(clamp_t(u32, mqnic_num_rxq_entries,
        MQNIC_MIN_RX_RING_SZ, MQNIC_MAX_RX_RING_SZ));

    init_rwsem(&priv->txq_table_sem);
    INIT_RADIX_TREE(&priv->txq_table, GFP_KERNEL);

    init_rwsem(&priv->rxq_table_sem);
    INIT_RADIX_TREE(&priv->rxq_table, GFP_KERNEL);

    netif_set_real_num_tx_queues(ndev, priv->txq_count);
    netif_set_real_num_rx_queues(ndev, priv->rxq_count);

    // set MAC
    ndev->addr_len = ETH_ALEN;

    if (ndev->dev_port >= mdev->mac_count) {
        dev_warn(dev, "Exhausted permanent MAC addresses; using random MAC");
        eth_hw_addr_random(ndev);
    }
    else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        eth_hw_addr_set(ndev, mdev->mac_list[ndev->dev_port]);
#else
        memcpy(ndev->dev_addr, mdev->mac_list[ndev->dev_port], ETH_ALEN);
#endif

        if (!is_valid_ether_addr(ndev->dev_addr)) {
            dev_warn(dev, "Invalid MAC address in list; using random MAC");
            eth_hw_addr_random(ndev);
        }
    }

    priv->hwts_config.flags = 0;
    priv->hwts_config.tx_type = HWTSTAMP_TX_OFF;
    priv->hwts_config.rx_filter = HWTSTAMP_FILTER_NONE;

    priv->rx_queue_map_indir_table_size = interface->rx_queue_map_indir_table_size;
    priv->rx_queue_map_indir_table = kzalloc(sizeof(u32) * priv->rx_queue_map_indir_table_size, GFP_KERNEL);
    if (!priv->rx_queue_map_indir_table) {
        ret = -ENOMEM;
        goto fail;
    }

    for (k = 0; k < priv->rx_queue_map_indir_table_size; k++)
        priv->rx_queue_map_indir_table[k] = k % priv->rxq_count;

    // entry points
    ndev->netdev_ops = &mqnic_netdev_ops;
    ndev->ethtool_ops = &mqnic_ethtool_ops;
    ndev->queue_mgmt_ops = &mqnic_queue_mgmt_ops;

    // set up features
    ndev->hw_features = NETIF_F_SG;

    if (priv->if_features & MQNIC_IF_FEATURE_RX_CSUM)
        ndev->hw_features |= NETIF_F_RXCSUM;

    if (priv->if_features & MQNIC_IF_FEATURE_TX_CSUM)
        ndev->hw_features |= NETIF_F_HW_CSUM;

    ndev->features = ndev->hw_features | NETIF_F_HIGHDMA;
    ndev->hw_features |= 0;

    ndev->min_mtu = ETH_MIN_MTU;
    ndev->max_mtu = 1500;

    if (interface->max_tx_mtu && interface->max_rx_mtu)
        ndev->max_mtu = min(interface->max_tx_mtu, interface->max_rx_mtu) - ETH_HLEN;

    netif_carrier_off(ndev);
    if (mqnic_link_status_poll)
        timer_setup(&priv->link_status_timer, mqnic_link_status_timeout, 0);

    ret = register_netdev(ndev);
    if (ret) {
        dev_err(dev, "netdev registration failed on interface %d netdev %d: %d",
            priv->interface->index, priv->index, ret);
        goto fail;
    }

    priv->registered = 1;

    return ndev;

fail:
    mqnic_destroy_netdev(ndev);
    return ERR_PTR(ret);
}

void mqnic_destroy_netdev(struct net_device* ndev) {
    struct mqnic_priv* priv = netdev_priv(ndev);

    if (priv->registered)
        unregister_netdev(ndev);

    kfree(priv->rx_queue_map_indir_table);

    free_netdev(ndev);
}

