/*
 * livepatch_bsc1177727
 *
 * Fix for CVE-2020-24490, bsc#1177727
 *
 *  Upstream commit:
 *  a2ec905d1e16 ("Bluetooth: fix kernel oops in store_pending_adv_report")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  not affected
 *
 *  SLE15-SP2 commit:
 *  b960bacafd57c3fb803195d104c826065989cb5c
 *
 *
 *  Copyright (c) 2020 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG_BT=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1177727.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <asm/unaligned.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static __printf(1, 2)
void (*klpe_bt_err)(const char *fmt, ...);
static __printf(1, 2)
void (*klpe_bt_err_ratelimited)(const char *fmt, ...);

#define KLPR_BT_ERR(fmt, ...)	(*klpe_bt_err)(fmt "\n", ##__VA_ARGS__)

#define KLPR_BT_ERR_RATELIMITED(fmt, ...) (*klpe_bt_err_ratelimited)(fmt "\n", ##__VA_ARGS__)

#define klpr_bt_dev_err(hdev, fmt, ...)				\
	KLPR_BT_ERR("%s: " fmt, (hdev)->name, ##__VA_ARGS__)

#define klpr_bt_dev_err_ratelimited(hdev, fmt, ...)			\
	KLPR_BT_ERR_RATELIMITED("%s: " fmt, (hdev)->name, ##__VA_ARGS__)

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static struct list_head (*klpe_hci_cb_list);

static struct mutex (*klpe_hci_cb_list_lock);

static struct hci_conn *(*klpe_hci_connect_le)(struct hci_dev *hdev, bdaddr_t *dst,
				u8 dst_type, u8 sec_level, u16 conn_timeout,
				u8 role, bdaddr_t *direct_rpa);

static struct bdaddr_list *(*klpe_hci_bdaddr_list_lookup)(struct list_head *list,
					   bdaddr_t *bdaddr, u8 type);

static struct hci_conn_params *(*klpe_hci_conn_params_lookup)(struct hci_dev *hdev,
					       bdaddr_t *addr, u8 addr_type);

static struct hci_conn_params *(*klpe_hci_pend_le_action_lookup)(struct list_head *list,
						  bdaddr_t *addr,
						  u8 addr_type);

static struct smp_ltk *(*klpe_hci_find_ltk)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			     u8 addr_type, u8 role);

static struct smp_irk *(*klpe_hci_find_irk_by_rpa)(struct hci_dev *hdev, bdaddr_t *rpa);

static struct adv_info *(*klpe_hci_find_adv_instance)(struct hci_dev *hdev, u8 instance);

static inline void klpr_hci_connect_cfm(struct hci_conn *conn, __u8 status)
{
	struct hci_cb *cb;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->connect_cfm)
			cb->connect_cfm(conn, status);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));

	if (conn->connect_cfm_cb)
		conn->connect_cfm_cb(conn, status);
}

static inline struct smp_irk *klpr_hci_get_irk(struct hci_dev *hdev,
					  bdaddr_t *bdaddr, u8 addr_type)
{
	if (!hci_bdaddr_is_rpa(bdaddr, addr_type))
		return NULL;

	return (*klpe_hci_find_irk_by_rpa)(hdev, bdaddr);
}

static int (*klpe_hci_send_cmd)(struct hci_dev *hdev, __u16 opcode, __u32 plen,
		 const void *param);

static void (*klpe_mgmt_device_found)(struct hci_dev *hdev, bdaddr_t *bdaddr, u8 link_type,
		       u8 addr_type, u8 *dev_class, s8 rssi, u32 flags,
		       u8 *eir, u16 eir_len, u8 *scan_rsp, u8 scan_rsp_len);

static void (*klpe_mgmt_new_conn_param)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			 u8 bdaddr_type, u8 store_hint, u16 min_interval,
			 u16 max_interval, u16 latency, u16 timeout);

/* klp-ccp: from include/net/bluetooth/mgmt.h */
#define MGMT_DEV_FOUND_NOT_CONNECTABLE 0x04

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/smp.h */
enum {
	SMP_STK,
	SMP_LTK,
	SMP_LTK_SLAVE,
	SMP_LTK_P256,
	SMP_LTK_P256_DEBUG,
};

static inline bool smp_ltk_is_sc(struct smp_ltk *key)
{
	switch (key->type) {
	case SMP_LTK_P256:
	case SMP_LTK_P256_DEBUG:
		return true;
	}

	return false;
}

static inline u8 smp_ltk_sec_level(struct smp_ltk *key)
{
	if (key->authenticated) {
		if (smp_ltk_is_sc(key))
			return BT_SECURITY_FIPS;
		else
			return BT_SECURITY_HIGH;
	}

	return BT_SECURITY_MEDIUM;
}

static bool (*klpe_smp_irk_matches)(struct hci_dev *hdev, const u8 irk[16],
		     const bdaddr_t *bdaddr);

/* klp-ccp: from net/bluetooth/hci_event.c */
static bool has_pending_adv_report(struct hci_dev *hdev)
{
	struct discovery_state *d = &hdev->discovery;

	return bacmp(&d->last_adv_addr, BDADDR_ANY);
}

static void clear_pending_adv_report(struct hci_dev *hdev)
{
	struct discovery_state *d = &hdev->discovery;

	bacpy(&d->last_adv_addr, BDADDR_ANY);
	d->last_adv_data_len = 0;
}

static void klpp_store_pending_adv_report(struct hci_dev *hdev, bdaddr_t *bdaddr,
				     u8 bdaddr_type, s8 rssi, u32 flags,
				     u8 *data, u8 len)
{
	struct discovery_state *d = &hdev->discovery;

	/*
	 * Fix CVE-2020-24490
	 *  +2 lines
	 */
	if (len > HCI_MAX_AD_LENGTH)
		return;

	bacpy(&d->last_adv_addr, bdaddr);
	d->last_adv_addr_type = bdaddr_type;
	d->last_adv_rssi = rssi;
	d->last_adv_flags = flags;
	memcpy(d->last_adv_data, data, len);
	d->last_adv_data_len = len;
}

static void (*klpe_le_conn_complete_evt)(struct hci_dev *hdev, u8 status,
			bdaddr_t *bdaddr, u8 bdaddr_type, u8 role, u16 handle,
			u16 interval, u16 latency, u16 supervision_timeout);

static void klpr_hci_le_conn_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_le_conn_complete *ev = (void *) skb->data;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	(*klpe_le_conn_complete_evt)(hdev, ev->status, &ev->bdaddr, ev->bdaddr_type,
			     ev->role, le16_to_cpu(ev->handle),
			     le16_to_cpu(ev->interval),
			     le16_to_cpu(ev->latency),
			     le16_to_cpu(ev->supervision_timeout));
}

static void klpr_hci_le_enh_conn_complete_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_le_enh_conn_complete *ev = (void *) skb->data;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	(*klpe_le_conn_complete_evt)(hdev, ev->status, &ev->bdaddr, ev->bdaddr_type,
			     ev->role, le16_to_cpu(ev->handle),
			     le16_to_cpu(ev->interval),
			     le16_to_cpu(ev->latency),
			     le16_to_cpu(ev->supervision_timeout));
}

static void klpr_hci_le_ext_adv_term_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_evt_le_ext_adv_set_term *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	if (ev->status)
		return;

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->conn_handle));
	if (conn) {
		struct adv_info *adv_instance;

		if (hdev->adv_addr_type != ADDR_LE_DEV_RANDOM)
			return;

		if (!hdev->cur_adv_instance) {
			bacpy(&conn->resp_addr, &hdev->random_addr);
			return;
		}

		adv_instance = (*klpe_hci_find_adv_instance)(hdev, hdev->cur_adv_instance);
		if (adv_instance)
			bacpy(&conn->resp_addr, &adv_instance->random_addr);
	}
}

static void hci_le_conn_update_complete_evt(struct hci_dev *hdev,
					    struct sk_buff *skb)
{
	struct hci_ev_le_conn_update_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	if (ev->status)
		return;

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn) {
		conn->le_conn_interval = le16_to_cpu(ev->interval);
		conn->le_conn_latency = le16_to_cpu(ev->latency);
		conn->le_supv_timeout = le16_to_cpu(ev->supervision_timeout);
	}

	hci_dev_unlock(hdev);
}

static struct hci_conn *klpr_check_pending_le_conn(struct hci_dev *hdev,
					      bdaddr_t *addr,
					      u8 addr_type, u8 adv_type,
					      bdaddr_t *direct_rpa)
{
	struct hci_conn *conn;
	struct hci_conn_params *params;

	/* If the event is not connectable don't proceed further */
	if (adv_type != LE_ADV_IND && adv_type != LE_ADV_DIRECT_IND)
		return NULL;

	/* Ignore if the device is blocked */
	if ((*klpe_hci_bdaddr_list_lookup)(&hdev->blacklist, addr, addr_type))
		return NULL;

	/* Most controller will fail if we try to create new connections
	 * while we have an existing one in slave role.
	 */
	if (hdev->conn_hash.le_num_slave > 0)
		return NULL;

	/* If we're not connectable only connect devices that we have in
	 * our pend_le_conns list.
	 */
	params = (*klpe_hci_pend_le_action_lookup)(&hdev->pend_le_conns, addr,
					   addr_type);
	if (!params)
		return NULL;

	if (!params->explicit_connect) {
		switch (params->auto_connect) {
		case HCI_AUTO_CONN_DIRECT:
			/* Only devices advertising with ADV_DIRECT_IND are
			 * triggering a connection attempt. This is allowing
			 * incoming connections from slave devices.
			 */
			if (adv_type != LE_ADV_DIRECT_IND)
				return NULL;
			break;
		case HCI_AUTO_CONN_ALWAYS:
			/* Devices advertising with ADV_IND or ADV_DIRECT_IND
			 * are triggering a connection attempt. This means
			 * that incoming connectioms from slave device are
			 * accepted and also outgoing connections to slave
			 * devices are established when found.
			 */
			break;
		default:
			return NULL;
		}
	}

	conn = (*klpe_hci_connect_le)(hdev, addr, addr_type, BT_SECURITY_LOW,
			      HCI_LE_AUTOCONN_TIMEOUT, HCI_ROLE_MASTER,
			      direct_rpa);
	if (!IS_ERR(conn)) {
		/* If HCI_AUTO_CONN_EXPLICIT is set, conn is already owned
		 * by higher layer that tried to connect, if no then
		 * store the pointer since we don't really have any
		 * other owner of the object besides the params that
		 * triggered it. This way we can abort the connection if
		 * the parameters get removed and keep the reference
		 * count consistent once the connection is established.
		 */

		if (!params->explicit_connect)
			params->conn = hci_conn_get(conn);

		return conn;
	}

	switch (PTR_ERR(conn)) {
	case -EBUSY:
		/* If hci_connect() returns -EBUSY it means there is already
		 * an LE connection attempt going on. Since controllers don't
		 * support more than one connection attempt at the time, we
		 * don't consider this an error case.
		 */
		break;
	default:
		BT_DBG("Failed to connect: err %ld", PTR_ERR(conn));
		return NULL;
	}

	return NULL;
}

static void klpp_process_adv_report(struct hci_dev *hdev, u8 type, bdaddr_t *bdaddr,
			       u8 bdaddr_type, bdaddr_t *direct_addr,
			       /*
				* Fix CVE-2020-24490
				*  -1 line, +2 lines
				*/
			       u8 direct_addr_type, s8 rssi, u8 *data, u8 len,
			       bool ext_adv)
{
	struct discovery_state *d = &hdev->discovery;
	struct smp_irk *irk;
	struct hci_conn *conn;
	bool match;
	u32 flags;
	u8 *ptr, real_len;

	switch (type) {
	case LE_ADV_IND:
	case LE_ADV_DIRECT_IND:
	case LE_ADV_SCAN_IND:
	case LE_ADV_NONCONN_IND:
	case LE_ADV_SCAN_RSP:
		break;
	default:
		klpr_bt_dev_err_ratelimited(hdev, "unknown advertising packet "
				       "type: 0x%02x", type);
		return;
	}

	/*
	 * Fix CVE-2020-24490
	 *  +4 lines
	 */
	if (!ext_adv && len > HCI_MAX_AD_LENGTH) {
		klpr_bt_dev_err_ratelimited(hdev, "legacy adv larger than 31 bytes");
		return;
	}

	/* Find the end of the data in case the report contains padded zero
	 * bytes at the end causing an invalid length value.
	 *
	 * When data is NULL, len is 0 so there is no need for extra ptr
	 * check as 'ptr < data + 0' is already false in such case.
	 */
	for (ptr = data; ptr < data + len && *ptr; ptr += *ptr + 1) {
		if (ptr + 1 + *ptr > data + len)
			break;
	}

	real_len = ptr - data;

	/* Adjust for actual length */
	if (len != real_len) {
		klpr_bt_dev_err_ratelimited(hdev, "advertising data len corrected");
		len = real_len;
	}

	/* If the direct address is present, then this report is from
	 * a LE Direct Advertising Report event. In that case it is
	 * important to see if the address is matching the local
	 * controller address.
	 */
	if (direct_addr) {
		/* Only resolvable random addresses are valid for these
		 * kind of reports and others can be ignored.
		 */
		if (!hci_bdaddr_is_rpa(direct_addr, direct_addr_type))
			return;

		/* If the controller is not using resolvable random
		 * addresses, then this report can be ignored.
		 */
		if (!hci_dev_test_flag(hdev, HCI_PRIVACY))
			return;

		/* If the local IRK of the controller does not match
		 * with the resolvable random address provided, then
		 * this report can be ignored.
		 */
		if (!(*klpe_smp_irk_matches)(hdev, hdev->irk, direct_addr))
			return;
	}

	/* Check if we need to convert to identity address */
	irk = klpr_hci_get_irk(hdev, bdaddr, bdaddr_type);
	if (irk) {
		bdaddr = &irk->bdaddr;
		bdaddr_type = irk->addr_type;
	}

	/* Check if we have been requested to connect to this device.
	 *
	 * direct_addr is set only for directed advertising reports (it is NULL
	 * for advertising reports) and is already verified to be RPA above.
	 */
	conn = klpr_check_pending_le_conn(hdev, bdaddr, bdaddr_type, type,
								direct_addr);
	/*
	 * Fix CVE-2020-24490
	 *  -1 line, +1 line
	 */
	if (!ext_adv && conn && type == LE_ADV_IND && len <= HCI_MAX_AD_LENGTH) {
		/* Store report for later inclusion by
		 * mgmt_device_connected
		 */
		memcpy(conn->le_adv_data, data, len);
		conn->le_adv_data_len = len;
	}

	/* Passive scanning shouldn't trigger any device found events,
	 * except for devices marked as CONN_REPORT for which we do send
	 * device found events.
	 */
	if (hdev->le_scan_type == LE_SCAN_PASSIVE) {
		if (type == LE_ADV_DIRECT_IND)
			return;

		if (!(*klpe_hci_pend_le_action_lookup)(&hdev->pend_le_reports,
					       bdaddr, bdaddr_type))
			return;

		if (type == LE_ADV_NONCONN_IND || type == LE_ADV_SCAN_IND)
			flags = MGMT_DEV_FOUND_NOT_CONNECTABLE;
		else
			flags = 0;
		(*klpe_mgmt_device_found)(hdev, bdaddr, LE_LINK, bdaddr_type, NULL,
				  rssi, flags, data, len, NULL, 0);
		return;
	}

	/* When receiving non-connectable or scannable undirected
	 * advertising reports, this means that the remote device is
	 * not connectable and then clearly indicate this in the
	 * device found event.
	 *
	 * When receiving a scan response, then there is no way to
	 * know if the remote device is connectable or not. However
	 * since scan responses are merged with a previously seen
	 * advertising report, the flags field from that report
	 * will be used.
	 *
	 * In the really unlikely case that a controller get confused
	 * and just sends a scan response event, then it is marked as
	 * not connectable as well.
	 */
	if (type == LE_ADV_NONCONN_IND || type == LE_ADV_SCAN_IND ||
	    type == LE_ADV_SCAN_RSP)
		flags = MGMT_DEV_FOUND_NOT_CONNECTABLE;
	else
		flags = 0;

	/* If there's nothing pending either store the data from this
	 * event or send an immediate device found event if the data
	 * should not be stored for later.
	 */
	/*
	 * Fix CVE-2020-24490
	 *  -1 line, +1 line
	 */
	if (!ext_adv && !has_pending_adv_report(hdev)) {
		/* If the report will trigger a SCAN_REQ store it for
		 * later merging.
		 */
		if (type == LE_ADV_IND || type == LE_ADV_SCAN_IND) {
			klpp_store_pending_adv_report(hdev, bdaddr, bdaddr_type,
						 rssi, flags, data, len);
			return;
		}

		(*klpe_mgmt_device_found)(hdev, bdaddr, LE_LINK, bdaddr_type, NULL,
				  rssi, flags, data, len, NULL, 0);
		return;
	}

	/* Check if the pending report is for the same device as the new one */
	match = (!bacmp(bdaddr, &d->last_adv_addr) &&
		 bdaddr_type == d->last_adv_addr_type);

	/* If the pending data doesn't match this report or this isn't a
	 * scan response (e.g. we got a duplicate ADV_IND) then force
	 * sending of the pending data.
	 */
	if (type != LE_ADV_SCAN_RSP || !match) {
		/* Send out whatever is in the cache, but skip duplicates */
		if (!match)
			(*klpe_mgmt_device_found)(hdev, &d->last_adv_addr, LE_LINK,
					  d->last_adv_addr_type, NULL,
					  d->last_adv_rssi, d->last_adv_flags,
					  d->last_adv_data,
					  d->last_adv_data_len, NULL, 0);

		/* If the new report will trigger a SCAN_REQ store it for
		 * later merging.
		 */
		/*
		 * Fix CVE-2020-24490
		 *  -1 line, +2 lines
		 */
		if (!ext_adv && (type == LE_ADV_IND ||
				 type == LE_ADV_SCAN_IND)) {
			klpp_store_pending_adv_report(hdev, bdaddr, bdaddr_type,
						 rssi, flags, data, len);
			return;
		}

		/* The advertising reports cannot be merged, so clear
		 * the pending report and send out a device found event.
		 */
		clear_pending_adv_report(hdev);
		(*klpe_mgmt_device_found)(hdev, bdaddr, LE_LINK, bdaddr_type, NULL,
				  rssi, flags, data, len, NULL, 0);
		return;
	}

	/* If we get here we've got a pending ADV_IND or ADV_SCAN_IND and
	 * the new event is a SCAN_RSP. We can therefore proceed with
	 * sending a merged device found event.
	 */
	(*klpe_mgmt_device_found)(hdev, &d->last_adv_addr, LE_LINK,
			  d->last_adv_addr_type, NULL, rssi, d->last_adv_flags,
			  d->last_adv_data, d->last_adv_data_len, data, len);
	clear_pending_adv_report(hdev);
}

static void klpp_hci_le_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_advertising_info *ev = ptr;
		s8 rssi;

		if (ev->length <= HCI_MAX_AD_LENGTH) {
			rssi = ev->data[ev->length];
			klpp_process_adv_report(hdev, ev->evt_type, &ev->bdaddr,
					   ev->bdaddr_type, NULL, 0, rssi,
					   /*
					    * Fix CVE-2020-24490
					    *  -1 line, +1 line
					    */
					   ev->data, ev->length, false);
		} else {
			klpr_bt_dev_err(hdev, "Dropping invalid advertising data");
		}

		ptr += sizeof(*ev) + ev->length + 1;
	}

	hci_dev_unlock(hdev);
}

static u8 klpr_ext_evt_type_to_legacy(u16 evt_type)
{
	if (evt_type & LE_EXT_ADV_LEGACY_PDU) {
		switch (evt_type) {
		case LE_LEGACY_ADV_IND:
			return LE_ADV_IND;
		case LE_LEGACY_ADV_DIRECT_IND:
			return LE_ADV_DIRECT_IND;
		case LE_LEGACY_ADV_SCAN_IND:
			return LE_ADV_SCAN_IND;
		case LE_LEGACY_NONCONN_IND:
			return LE_ADV_NONCONN_IND;
		case LE_LEGACY_SCAN_RSP_ADV:
		case LE_LEGACY_SCAN_RSP_ADV_SCAN:
			return LE_ADV_SCAN_RSP;
		}

		KLPR_BT_ERR_RATELIMITED("Unknown advertising packet type: 0x%02x",
				   evt_type);

		return LE_ADV_INVALID;
	}

	if (evt_type & LE_EXT_ADV_CONN_IND) {
		if (evt_type & LE_EXT_ADV_DIRECT_IND)
			return LE_ADV_DIRECT_IND;

		return LE_ADV_IND;
	}

	if (evt_type & LE_EXT_ADV_SCAN_RSP)
		return LE_ADV_SCAN_RSP;

	if (evt_type & LE_EXT_ADV_SCAN_IND)
		return LE_ADV_SCAN_IND;

	if (evt_type == LE_EXT_ADV_NON_CONN_IND ||
	    evt_type & LE_EXT_ADV_DIRECT_IND)
		return LE_ADV_NONCONN_IND;

	KLPR_BT_ERR_RATELIMITED("Unknown advertising packet type: 0x%02x",
				   evt_type);

	return LE_ADV_INVALID;
}

static void klpp_hci_le_ext_adv_report_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_ext_adv_report *ev = ptr;
		u8 legacy_evt_type;
		u16 evt_type;

		evt_type = __le16_to_cpu(ev->evt_type);
		legacy_evt_type = klpr_ext_evt_type_to_legacy(evt_type);
		if (legacy_evt_type != LE_ADV_INVALID) {
			klpp_process_adv_report(hdev, legacy_evt_type, &ev->bdaddr,
					   ev->bdaddr_type, NULL, 0, ev->rssi,
					   /*
					    * Fix CVE-2020-24490
					    *  -1 line, +2 lines
					    */
					   ev->data, ev->length,
					   !(evt_type & LE_EXT_ADV_LEGACY_PDU));
		}

		ptr += sizeof(*ev) + ev->length;
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_le_remote_feat_complete_evt(struct hci_dev *hdev,
					    struct sk_buff *skb)
{
	struct hci_ev_le_remote_feat_complete *ev = (void *)skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn) {
		if (!ev->status)
			memcpy(conn->features[0], ev->features, 8);

		if (conn->state == BT_CONFIG) {
			__u8 status;

			/* If the local controller supports slave-initiated
			 * features exchange, but the remote controller does
			 * not, then it is possible that the error code 0x1a
			 * for unsupported remote feature gets returned.
			 *
			 * In this specific case, allow the connection to
			 * transition into connected state and mark it as
			 * successful.
			 */
			if ((hdev->le_features[0] & HCI_LE_SLAVE_FEATURES) &&
			    !conn->out && ev->status == 0x1a)
				status = 0x00;
			else
				status = ev->status;

			conn->state = BT_CONNECTED;
			klpr_hci_connect_cfm(conn, status);
			hci_conn_drop(conn);
		}
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_le_ltk_request_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_le_ltk_req *ev = (void *) skb->data;
	struct hci_cp_le_ltk_reply cp;
	struct hci_cp_le_ltk_neg_reply neg;
	struct hci_conn *conn;
	struct smp_ltk *ltk;

	BT_DBG("%s handle 0x%4.4x", hdev->name, __le16_to_cpu(ev->handle));

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn == NULL)
		goto not_found;

	ltk = (*klpe_hci_find_ltk)(hdev, &conn->dst, conn->dst_type, conn->role);
	if (!ltk)
		goto not_found;

	if (smp_ltk_is_sc(ltk)) {
		/* With SC both EDiv and Rand are set to zero */
		if (ev->ediv || ev->rand)
			goto not_found;
	} else {
		/* For non-SC keys check that EDiv and Rand match */
		if (ev->ediv != ltk->ediv || ev->rand != ltk->rand)
			goto not_found;
	}

	memcpy(cp.ltk, ltk->val, ltk->enc_size);
	memset(cp.ltk + ltk->enc_size, 0, sizeof(cp.ltk) - ltk->enc_size);
	cp.handle = cpu_to_le16(conn->handle);

	conn->pending_sec_level = smp_ltk_sec_level(ltk);

	conn->enc_key_size = ltk->enc_size;

	(*klpe_hci_send_cmd)(hdev, HCI_OP_LE_LTK_REPLY, sizeof(cp), &cp);

	/* Ref. Bluetooth Core SPEC pages 1975 and 2004. STK is a
	 * temporary key used to encrypt a connection following
	 * pairing. It is used during the Encrypted Session Setup to
	 * distribute the keys. Later, security can be re-established
	 * using a distributed LTK.
	 */
	if (ltk->type == SMP_STK) {
		set_bit(HCI_CONN_STK_ENCRYPT, &conn->flags);
		list_del_rcu(&ltk->list);
		kfree_rcu(ltk, rcu);
	} else {
		clear_bit(HCI_CONN_STK_ENCRYPT, &conn->flags);
	}

	hci_dev_unlock(hdev);

	return;

not_found:
	neg.handle = ev->handle;
	(*klpe_hci_send_cmd)(hdev, HCI_OP_LE_LTK_NEG_REPLY, sizeof(neg), &neg);
	hci_dev_unlock(hdev);
}

static void klpr_send_conn_param_neg_reply(struct hci_dev *hdev, u16 handle,
				      u8 reason)
{
	struct hci_cp_le_conn_param_req_neg_reply cp;

	cp.handle = cpu_to_le16(handle);
	cp.reason = reason;

	(*klpe_hci_send_cmd)(hdev, HCI_OP_LE_CONN_PARAM_REQ_NEG_REPLY, sizeof(cp),
		     &cp);
}

static void klpr_hci_le_remote_conn_param_req_evt(struct hci_dev *hdev,
					     struct sk_buff *skb)
{
	struct hci_ev_le_remote_conn_param_req *ev = (void *) skb->data;
	struct hci_cp_le_conn_param_req_reply cp;
	struct hci_conn *hcon;
	u16 handle, min, max, latency, timeout;

	handle = le16_to_cpu(ev->handle);
	min = le16_to_cpu(ev->interval_min);
	max = le16_to_cpu(ev->interval_max);
	latency = le16_to_cpu(ev->latency);
	timeout = le16_to_cpu(ev->timeout);

	hcon = hci_conn_hash_lookup_handle(hdev, handle);
	if (!hcon || hcon->state != BT_CONNECTED)
		return klpr_send_conn_param_neg_reply(hdev, handle,
						 HCI_ERROR_UNKNOWN_CONN_ID);

	if (hci_check_conn_params(min, max, latency, timeout))
		return klpr_send_conn_param_neg_reply(hdev, handle,
						 HCI_ERROR_INVALID_LL_PARAMS);

	if (hcon->role == HCI_ROLE_MASTER) {
		struct hci_conn_params *params;
		u8 store_hint;

		hci_dev_lock(hdev);

		params = (*klpe_hci_conn_params_lookup)(hdev, &hcon->dst,
						hcon->dst_type);
		if (params) {
			params->conn_min_interval = min;
			params->conn_max_interval = max;
			params->conn_latency = latency;
			params->supervision_timeout = timeout;
			store_hint = 0x01;
		} else{
			store_hint = 0x00;
		}

		hci_dev_unlock(hdev);

		(*klpe_mgmt_new_conn_param)(hdev, &hcon->dst, hcon->dst_type,
				    store_hint, min, max, latency, timeout);
	}

	cp.handle = ev->handle;
	cp.interval_min = ev->interval_min;
	cp.interval_max = ev->interval_max;
	cp.latency = ev->latency;
	cp.timeout = ev->timeout;
	cp.min_ce_len = 0;
	cp.max_ce_len = 0;

	(*klpe_hci_send_cmd)(hdev, HCI_OP_LE_CONN_PARAM_REQ_REPLY, sizeof(cp), &cp);
}

static void klpp_hci_le_direct_adv_report_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	u8 num_reports = skb->data[0];
	void *ptr = &skb->data[1];

	hci_dev_lock(hdev);

	while (num_reports--) {
		struct hci_ev_le_direct_adv_info *ev = ptr;

		klpp_process_adv_report(hdev, ev->evt_type, &ev->bdaddr,
				   ev->bdaddr_type, &ev->direct_addr,
				   /*
				    * Fix CVE-2020-24490
				    *  -1 line, +2 lines
				    */
				   ev->direct_addr_type, ev->rssi, NULL, 0,
				   false);

		ptr += sizeof(*ev);
	}

	hci_dev_unlock(hdev);
}

void klpp_hci_le_meta_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_le_meta *le_ev = (void *) skb->data;

	skb_pull(skb, sizeof(*le_ev));

	switch (le_ev->subevent) {
	case HCI_EV_LE_CONN_COMPLETE:
		klpr_hci_le_conn_complete_evt(hdev, skb);
		break;

	case HCI_EV_LE_CONN_UPDATE_COMPLETE:
		hci_le_conn_update_complete_evt(hdev, skb);
		break;

	case HCI_EV_LE_ADVERTISING_REPORT:
		klpp_hci_le_adv_report_evt(hdev, skb);
		break;

	case HCI_EV_LE_REMOTE_FEAT_COMPLETE:
		klpr_hci_le_remote_feat_complete_evt(hdev, skb);
		break;

	case HCI_EV_LE_LTK_REQ:
		klpr_hci_le_ltk_request_evt(hdev, skb);
		break;

	case HCI_EV_LE_REMOTE_CONN_PARAM_REQ:
		klpr_hci_le_remote_conn_param_req_evt(hdev, skb);
		break;

	case HCI_EV_LE_DIRECT_ADV_REPORT:
		klpp_hci_le_direct_adv_report_evt(hdev, skb);
		break;

	case HCI_EV_LE_EXT_ADV_REPORT:
		klpp_hci_le_ext_adv_report_evt(hdev, skb);
		break;

	case HCI_EV_LE_ENHANCED_CONN_COMPLETE:
		klpr_hci_le_enh_conn_complete_evt(hdev, skb);
		break;

	case HCI_EV_LE_EXT_ADV_SET_TERM:
		klpr_hci_le_ext_adv_term_evt(hdev, skb);
		break;

	default:
		break;
	}
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hci_cb_list_lock", (void *)&klpe_hci_cb_list_lock, "bluetooth" },
	{ "hci_cb_list", (void *)&klpe_hci_cb_list, "bluetooth" },
	{ "smp_irk_matches", (void *)&klpe_smp_irk_matches, "bluetooth" },
	{ "bt_err", (void *)&klpe_bt_err, "bluetooth" },
	{ "bt_err_ratelimited", (void *)&klpe_bt_err_ratelimited, "bluetooth" },
	{ "hci_conn_params_lookup", (void *)&klpe_hci_conn_params_lookup,
	  "bluetooth" },
	{ "hci_send_cmd", (void *)&klpe_hci_send_cmd, "bluetooth" },
	{ "hci_find_ltk", (void *)&klpe_hci_find_ltk, "bluetooth" },
	{ "mgmt_device_found", (void *)&klpe_mgmt_device_found, "bluetooth" },
	{ "mgmt_new_conn_param", (void *)&klpe_mgmt_new_conn_param,
	  "bluetooth" },
	{ "hci_find_adv_instance", (void *)&klpe_hci_find_adv_instance,
	  "bluetooth" },
	{ "hci_bdaddr_list_lookup", (void *)&klpe_hci_bdaddr_list_lookup,
	  "bluetooth" },
	{ "hci_connect_le", (void *)&klpe_hci_connect_le, "bluetooth" },
	{ "hci_find_irk_by_rpa", (void *)&klpe_hci_find_irk_by_rpa,
	  "bluetooth" },
	{ "hci_pend_le_action_lookup", (void *)&klpe_hci_pend_le_action_lookup,
	  "bluetooth" },
	{ "le_conn_complete_evt", (void *)&klpe_le_conn_complete_evt,
	  "bluetooth" },
};

static int livepatch_bsc1177727_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1177727_module_nb = {
	.notifier_call = livepatch_bsc1177727_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1177727_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1177727_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1177727_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1177727_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
