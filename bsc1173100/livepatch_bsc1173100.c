/*
 * livepatch_bsc1173100
 *
 * Fix for CVE-2019-14895, bsc#1173100
 *
 *  Upstream commit:
 *  3d94a4a8373b ("mwifiex: fix possible heap overflow in
 *                 mwifiex_process_country_ie()")
 *  65b1aae0d9d5 ("mwifiex: fix unbalanced locking in
 *                 mwifiex_process_country_ie()")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  3c83a1e9107b7e55a1210af5658e71226e8462bf
 *  52d6998e3c9313a3759b8456558ff55e5e9e417d
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d214272a9a383733a9f99afc0ec367eca0811b69
 *  6a8e4237a9659dc59b1e4cd2e3285eb473253469
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

#if IS_ENABLED(CONFIG_MWIFIEX)

#if !IS_MODULE(CONFIG_MWIFIEX)
#error "Live patch supports only CONFIG_MWIFIEX=m"
#endif

#define LIVEPATCHED_MODULE "mwifiex"

#define pr_fmt(fmt)	LIVEPATCHED_MODULE ": " fmt

#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <linux/if_ether.h>
#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <net/lib80211.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/slab.h>
#include    <linux/completion.h>
#include    <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/completion.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_ids.h>
#include <net/cfg80211.h>
#include <net/lib80211.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1173100.h"
#include "../kallsyms_relocs.h"


/* from include/net/cfg80211.h */
static const u8 *(*klpe_ieee80211_bss_get_ie)(struct cfg80211_bss *bss, u8 ie);

static void (*klpe_cfg80211_put_bss)(struct wiphy *wiphy, struct cfg80211_bss *bss);


/* from drivers/net/wireless/marvell/mwifiex/decl.h */
#define MWIFIEX_MAX_BSS_NUM         (3)

struct mwifiex_fw_image;

struct mwifiex_802_11_ssid {
	u32 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
};

struct mwifiex_wait_queue {
	wait_queue_head_t wait;
	int status;
};

enum mwifiex_wmm_ac_e {
	WMM_AC_BK,
	WMM_AC_BE,
	WMM_AC_VI,
	WMM_AC_VO
} __packed;

struct ieee_types_wmm_ac_parameters {
	u8 aci_aifsn_bitmap;
	u8 ecw_bitmap;
	__le16 tx_op_limit;
} __packed;

struct mwifiex_types_wmm_info {
	u8 oui[4];
	u8 subtype;
	u8 version;
	u8 qos_info;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct mwifiex_iface_comb {
	u8 sta_intf;
	u8 uap_intf;
	u8 p2p_intf;
};

struct mwifiex_11h_intf_state {
	bool is_11h_enabled;
	bool is_11h_active;
} __packed;


/* from drivers/net/wireless/marvell/mwifiex/ioctl.h */
enum {
	BAND_B = 1,
	BAND_G = 2,
	BAND_A = 4,
	BAND_GN = 8,
	BAND_AN = 16,
	BAND_AAC = 32,
};

#define MWIFIEX_WPA_PASSHPHRASE_LEN 64
struct wpa_param {
	u8 pairwise_cipher_wpa;
	u8 pairwise_cipher_wpa2;
	u8 group_cipher;
	u32 length;
	u8 passphrase[MWIFIEX_WPA_PASSHPHRASE_LEN];
};

struct wep_key {
	u8 key_index;
	u8 is_default;
	u16 length;
	u8 key[WLAN_KEY_LEN_WEP104];
};

#define MWIFIEX_SUPPORTED_RATES                 14

struct mwifiex_uap_bss_param {
	u8 channel;
	u8 band_cfg;
	u16 rts_threshold;
	u16 frag_threshold;
	u8 retry_limit;
	struct mwifiex_802_11_ssid ssid;
	u8 bcast_ssid_ctl;
	u8 radio_ctl;
	u8 dtim_period;
	u16 beacon_period;
	u16 auth_mode;
	u16 protocol;
	u16 key_mgmt;
	u16 key_mgmt_operation;
	struct wpa_param wpa_cfg;
	struct wep_key wep_cfg[NUM_WEP_KEYS];
	struct ieee80211_ht_cap ht_cap;
	struct ieee80211_vht_cap vht_cap;
	u8 rates[MWIFIEX_SUPPORTED_RATES];
	u32 sta_ao_timer;
	u32 ps_sta_ao_timer;
	u8 qos_info;
	u8 power_constraint;
	struct mwifiex_types_wmm_info wmm_info;
};

#define MAX_NUM_TID     8

#define DBG_CMD_NUM    5
#define MWIFIEX_DBG_SDIO_MP_NUM    10

#define PN_LEN				16

struct mwifiex_ds_mem_rw {
	u32 addr;
	u32 value;
};

#define IEEE_MAX_IE_SIZE		256

struct subsc_evt_cfg {
	u8 abs_value;
	u8 evt_freq;
};

struct mwifiex_ds_misc_subsc_evt {
	u16 action;
	u16 events;
	struct subsc_evt_cfg bcn_l_rssi_cfg;
	struct subsc_evt_cfg bcn_h_rssi_cfg;
};

#define MWIFIEX_MAX_VSIE_LEN       (256)
#define MWIFIEX_MAX_VSIE_NUM       (8)


/* from drivers/net/wireless/marvell/mwifiex/fw.h */
#define WPA_PN_SIZE		8

#define HostCmd_CMD_802_11D_DOMAIN_INFO               0x005b

#define HostCmd_ACT_GEN_SET                   0x0001

#define HostCmd_SCAN_RADIO_TYPE_BG          0

struct mwifiex_ie_type_key_param_set {
	__le16 type;
	__le16 length;
	__le16 key_type_id;
	__le16 key_info;
	__le16 key_len;
	u8 key[50];
} __packed;

#define IGTK_PN_LEN		8

struct mwifiex_wep_param {
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_WEP104];
} __packed;

struct mwifiex_tkip_param {
	u8 pn[WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_TKIP];
} __packed;

struct mwifiex_aes_param {
	u8 pn[WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_CCMP];
} __packed;

struct mwifiex_wapi_param {
	u8 pn[PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_SMS4];
} __packed;

struct mwifiex_cmac_aes_param {
	u8 ipn[IGTK_PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_AES_CMAC];
} __packed;

struct mwifiex_ie_type_key_param_set_v2 {
	__le16 type;
	__le16 len;
	u8 mac_addr[ETH_ALEN];
	u8 key_idx;
	u8 key_type;
	__le16 key_info;
	union {
		struct mwifiex_wep_param wep;
		struct mwifiex_tkip_param tkip;
		struct mwifiex_aes_param aes;
		struct mwifiex_wapi_param wapi;
		struct mwifiex_cmac_aes_param cmac_aes;
	} key_params;
} __packed;

struct host_cmd_ds_802_11_key_material_v2 {
	__le16 action;
	struct mwifiex_ie_type_key_param_set_v2 key_param_set;
} __packed;

struct host_cmd_ds_802_11_key_material {
	__le16 action;
	struct mwifiex_ie_type_key_param_set key_param_set;
} __packed;

struct ieee_types_cf_param_set {
	u8 element_id;
	u8 len;
	u8 cfp_cnt;
	u8 cfp_period;
	__le16 cfp_max_duration;
	__le16 cfp_duration_remaining;
} __packed;

struct ieee_types_ibss_param_set {
	u8 element_id;
	u8 len;
	__le16 atim_window;
} __packed;

union ieee_types_ss_param_set {
	struct ieee_types_cf_param_set cf_param_set;
	struct ieee_types_ibss_param_set ibss_param_set;
} __packed;

struct ieee_types_fh_param_set {
	u8 element_id;
	u8 len;
	__le16 dwell_time;
	u8 hop_set;
	u8 hop_pattern;
	u8 hop_index;
} __packed;

struct ieee_types_ds_param_set {
	u8 element_id;
	u8 len;
	u8 current_chan;
} __packed;

union ieee_types_phy_param_set {
	struct ieee_types_fh_param_set fh_param_set;
	struct ieee_types_ds_param_set ds_param_set;
} __packed;

struct mwifiex_hs_config_param {
	__le32 conditions;
	u8 gpio;
	u8 gap;
} __packed;

#define MWIFIEX_USER_SCAN_CHAN_MAX             50

struct mwifiex_user_scan_chan {
	u8 chan_number;
	u8 radio_type;
	u8 scan_type;
	u8 reserved;
	u32 scan_time;
} __packed;

struct ieee_types_vendor_header {
	u8 element_id;
	u8 len;
	struct {
		u8 oui[3];
		u8 oui_type;
	} __packed oui;
} __packed;

struct ieee_types_wmm_parameter {
	/*
	 * WMM Parameter IE - Vendor Specific Header:
	 *   element_id  [221/0xdd]
	 *   Len         [24]
	 *   Oui         [00:50:f2]
	 *   OuiType     [2]
	 *   OuiSubType  [1]
	 *   Version     [1]
	 */
	struct ieee_types_vendor_header vend_hdr;
	u8 oui_subtype;
	u8 version;

	u8 qos_info_bitmap;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct mwifiex_wmm_ac_status {
	u8 disabled;
	u8 flow_required;
	u8 flow_created;
};

struct mwifiex_ie {
	__le16 ie_index;
	__le16 mgmt_subtype_mask;
	__le16 ie_length;
	u8 ie_buffer[IEEE_MAX_IE_SIZE];
} __packed;

#define MAX_MGMT_IE_INDEX	16


/* from drivers/net/wireless/marvell/mwifiex/main.h */
struct mwifiex_adapter;

#define MWIFIEX_UPLD_SIZE               (2312)

#define MAX_EVENT_SIZE                  2048

#define ARP_FILTER_MAX_BUF_SIZE         68

#define MWIFIEX_KEY_BUFFER_SIZE			16

#define MAX_BITMAP_RATES_SIZE			18

enum MWIFIEX_DEBUG_LEVEL {
	MWIFIEX_DBG_MSG		= 0x00000001,
	MWIFIEX_DBG_FATAL	= 0x00000002,
	MWIFIEX_DBG_ERROR	= 0x00000004,
	MWIFIEX_DBG_DATA	= 0x00000008,
	MWIFIEX_DBG_CMD		= 0x00000010,
	MWIFIEX_DBG_EVENT	= 0x00000020,
	MWIFIEX_DBG_INTR	= 0x00000040,
	MWIFIEX_DBG_IOCTL	= 0x00000080,

	MWIFIEX_DBG_MPA_D	= 0x00008000,
	MWIFIEX_DBG_DAT_D	= 0x00010000,
	MWIFIEX_DBG_CMD_D	= 0x00020000,
	MWIFIEX_DBG_EVT_D	= 0x00040000,
	MWIFIEX_DBG_FW_D	= 0x00080000,
	MWIFIEX_DBG_IF_D	= 0x00100000,

	MWIFIEX_DBG_ENTRY	= 0x10000000,
	MWIFIEX_DBG_WARN	= 0x20000000,
	MWIFIEX_DBG_INFO	= 0x40000000,
	MWIFIEX_DBG_DUMP	= 0x80000000,

	MWIFIEX_DBG_ANY		= 0xffffffff
};

static __printf(3, 4)
void (*klpe__mwifiex_dbg)(const struct mwifiex_adapter *adapter, int mask,
		  const char *fmt, ...);

#define klpr_mwifiex_dbg(adapter, mask, fmt, ...)				\
	(*klpe__mwifiex_dbg)(adapter, MWIFIEX_DBG_##mask, fmt, ##__VA_ARGS__)

struct mwifiex_dbg {
	u32 num_cmd_host_to_card_failure;
	u32 num_cmd_sleep_cfm_host_to_card_failure;
	u32 num_tx_host_to_card_failure;
	u32 num_event_deauth;
	u32 num_event_disassoc;
	u32 num_event_link_lost;
	u32 num_cmd_deauth;
	u32 num_cmd_assoc_success;
	u32 num_cmd_assoc_failure;
	u32 num_tx_timeout;
	u16 timeout_cmd_id;
	u16 timeout_cmd_act;
	u16 last_cmd_id[DBG_CMD_NUM];
	u16 last_cmd_act[DBG_CMD_NUM];
	u16 last_cmd_index;
	u16 last_cmd_resp_id[DBG_CMD_NUM];
	u16 last_cmd_resp_index;
	u16 last_event[DBG_CMD_NUM];
	u16 last_event_index;
	u32 last_mp_wr_bitmap[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_wr_ports[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_wr_len[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_curr_wr_port[MWIFIEX_DBG_SDIO_MP_NUM];
	u8 last_sdio_mp_index;
};

enum MWIFIEX_HARDWARE_STATUS {
	MWIFIEX_HW_STATUS_READY,
	MWIFIEX_HW_STATUS_INITIALIZING,
	MWIFIEX_HW_STATUS_INIT_DONE,
	MWIFIEX_HW_STATUS_RESET,
	MWIFIEX_HW_STATUS_NOT_READY
};

struct mwifiex_tx_param;

struct mwifiex_add_ba_param {
	u32 tx_win_size;
	u32 rx_win_size;
	u32 timeout;
	u8 tx_amsdu;
	u8 rx_amsdu;
};

struct mwifiex_tx_aggr {
	u8 ampdu_user;
	u8 ampdu_ap;
	u8 amsdu;
};

struct mwifiex_tid_tbl {
	struct list_head ra_list;
};

#define WMM_HIGHEST_PRIORITY		7

struct mwifiex_wmm_desc {
	struct mwifiex_tid_tbl tid_tbl_ptr[MAX_NUM_TID];
	u32 packets_out[MAX_NUM_TID];
	u32 pkts_paused[MAX_NUM_TID];
	/* spin lock to protect ra_list */
	spinlock_t ra_list_spinlock;
	struct mwifiex_wmm_ac_status ac_status[IEEE80211_NUM_ACS];
	enum mwifiex_wmm_ac_e ac_down_graded_vals[IEEE80211_NUM_ACS];
	u32 drv_pkt_delay_max;
	u8 queue_priority[IEEE80211_NUM_ACS];
	u32 user_pri_pkt_tx_ctrl[WMM_HIGHEST_PRIORITY + 1];	/* UP: 0 to 7 */
	/* Number of transmit packets queued */
	atomic_t tx_pkts_queued;
	/* Tracks highest priority with a packet queued */
	atomic_t highest_queued_prio;
};

struct mwifiex_802_11_security {
	u8 wpa_enabled;
	u8 wpa2_enabled;
	u8 wapi_enabled;
	u8 wapi_key_on;
	u8 wep_enabled;
	u32 authentication_mode;
	u8 is_authtype_auto;
	u32 encryption_mode;
};

struct mwifiex_bssdescriptor {
	u8 mac_address[ETH_ALEN];
	struct cfg80211_ssid ssid;
	u32 privacy;
	s32 rssi;
	u32 channel;
	u32 freq;
	u16 beacon_period;
	u8 erp_flags;
	u32 bss_mode;
	u8 supported_rates[MWIFIEX_SUPPORTED_RATES];
	u8 data_rates[MWIFIEX_SUPPORTED_RATES];
	/* Network band.
	 * BAND_B(0x01): 'b' band
	 * BAND_G(0x02): 'g' band
	 * BAND_A(0X04): 'a' band
	 */
	u16 bss_band;
	u64 fw_tsf;
	u64 timestamp;
	union ieee_types_phy_param_set phy_param_set;
	union ieee_types_ss_param_set ss_param_set;
	u16 cap_info_bitmap;
	struct ieee_types_wmm_parameter wmm_ie;
	u8  disable_11n;
	struct ieee80211_ht_cap *bcn_ht_cap;
	u16 ht_cap_offset;
	struct ieee80211_ht_operation *bcn_ht_oper;
	u16 ht_info_offset;
	u8 *bcn_bss_co_2040;
	u16 bss_co_2040_offset;
	u8 *bcn_ext_cap;
	u16 ext_cap_offset;
	struct ieee80211_vht_cap *bcn_vht_cap;
	u16 vht_cap_offset;
	struct ieee80211_vht_operation *bcn_vht_oper;
	u16 vht_info_offset;
	struct ieee_types_oper_mode_ntf *oper_mode;
	u16 oper_mode_offset;
	u8 disable_11ac;
	struct ieee_types_vendor_specific *bcn_wpa_ie;
	u16 wpa_offset;
	struct ieee_types_generic *bcn_rsn_ie;
	u16 rsn_offset;
	struct ieee_types_generic *bcn_wapi_ie;
	u16 wapi_offset;
	u8 *beacon_buf;
	u32 beacon_buf_size;
	u8 sensed_11h;
	u8 local_constraint;
	u8 chan_sw_ie_present;
};

struct mwifiex_current_bss_params {
	struct mwifiex_bssdescriptor bss_descriptor;
	u8 wmm_enabled;
	u8 wmm_uapsd_enabled;
	u8 band;
	u32 num_of_rates;
	u8 data_rates[MWIFIEX_SUPPORTED_RATES];
};

struct mwifiex_sleep_params {
	u16 sp_error;
	u16 sp_offset;
	u16 sp_stable_time;
	u8 sp_cal_control;
	u8 sp_ext_sleep_clk;
	u16 sp_reserved;
};

struct mwifiex_sleep_period {
	u16 period;
	u16 reserved;
};

struct mwifiex_wep_key {
	u32 length;
	u32 key_index;
	u32 key_length;
	u8 key_material[MWIFIEX_KEY_BUFFER_SIZE];
};

struct mwifiex_chan_freq_power {
	u16 channel;
	u32 freq;
	u16 max_tx_power;
	u8 unsupported;
};

#define MWIFIEX_MAX_TRIPLET_802_11D		83

struct mwifiex_802_11d_domain_reg {
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	u8 no_of_triplet;
	struct ieee80211_country_ie_triplet
		triplet[MWIFIEX_MAX_TRIPLET_802_11D];
};

struct mwifiex_vendor_spec_cfg_ie {
	u16 mask;
	u16 flag;
	u8 ie[MWIFIEX_MAX_VSIE_LEN];
};

struct wps {
	u8 session_enable;
};

struct mwifiex_roc_cfg {
	u64 cookie;
	struct ieee80211_channel chan;
};

struct mwifiex_private {
	struct mwifiex_adapter *adapter;
	u8 bss_type;
	u8 bss_role;
	u8 bss_priority;
	u8 bss_num;
	u8 bss_started;
	u8 frame_type;
	u8 curr_addr[ETH_ALEN];
	u8 media_connected;
	u8 port_open;
	u8 usb_port;
	u32 num_tx_timeout;
	/* track consecutive timeout */
	u8 tx_timeout_cnt;
	struct net_device *netdev;
	struct net_device_stats stats;
	u32 curr_pkt_filter;
	u32 bss_mode;
	u32 pkt_tx_ctrl;
	u16 tx_power_level;
	u8 max_tx_power_level;
	u8 min_tx_power_level;
	u32 tx_ant;
	u32 rx_ant;
	u8 tx_rate;
	u8 tx_htinfo;
	u8 rxpd_htinfo;
	u8 rxpd_rate;
	u16 rate_bitmap;
	u16 bitmap_rates[MAX_BITMAP_RATES_SIZE];
	u32 data_rate;
	u8 is_data_rate_auto;
	u16 bcn_avg_factor;
	u16 data_avg_factor;
	s16 data_rssi_last;
	s16 data_nf_last;
	s16 data_rssi_avg;
	s16 data_nf_avg;
	s16 bcn_rssi_last;
	s16 bcn_nf_last;
	s16 bcn_rssi_avg;
	s16 bcn_nf_avg;
	struct mwifiex_bssdescriptor *attempted_bss_desc;
	struct cfg80211_ssid prev_ssid;
	u8 prev_bssid[ETH_ALEN];
	struct mwifiex_current_bss_params curr_bss_params;
	u16 beacon_period;
	u8 dtim_period;
	u16 listen_interval;
	u16 atim_window;
	u8 adhoc_channel;
	u8 adhoc_is_link_sensed;
	u8 adhoc_state;
	struct mwifiex_802_11_security sec_info;
	struct mwifiex_wep_key wep_key[NUM_WEP_KEYS];
	u16 wep_key_curr_index;
	u8 wpa_ie[256];
	u16 wpa_ie_len;
	u8 wpa_is_gtk_set;
	struct host_cmd_ds_802_11_key_material aes_key;
	struct host_cmd_ds_802_11_key_material_v2 aes_key_v2;
	u8 wapi_ie[256];
	u16 wapi_ie_len;
	u8 *wps_ie;
	u16 wps_ie_len;
	u8 wmm_required;
	u8 wmm_enabled;
	u8 wmm_qosinfo;
	struct mwifiex_wmm_desc wmm;
	atomic_t wmm_tx_pending[IEEE80211_NUM_ACS];
	struct list_head sta_list;
	/* spin lock for associated station/TDLS peers list */
	spinlock_t sta_list_spinlock;
	struct list_head auto_tdls_list;
	/* spin lock for auto TDLS peer list */
	spinlock_t auto_tdls_lock;
	struct list_head tx_ba_stream_tbl_ptr;
	/* spin lock for tx_ba_stream_tbl_ptr queue */
	spinlock_t tx_ba_stream_tbl_lock;
	struct mwifiex_tx_aggr aggr_prio_tbl[MAX_NUM_TID];
	struct mwifiex_add_ba_param add_ba_param;
	u16 rx_seq[MAX_NUM_TID];
	u8 tos_to_tid_inv[MAX_NUM_TID];
	struct list_head rx_reorder_tbl_ptr;
	/* spin lock for rx_reorder_tbl_ptr queue */
	spinlock_t rx_reorder_tbl_lock;
#define MWIFIEX_ASSOC_RSP_BUF_SIZE  500
	u8 assoc_rsp_buf[MWIFIEX_ASSOC_RSP_BUF_SIZE];
	u32 assoc_rsp_size;

#define MWIFIEX_GENIE_BUF_SIZE      256
	u8 gen_ie_buf[MWIFIEX_GENIE_BUF_SIZE];
	u8 gen_ie_buf_len;

	struct mwifiex_vendor_spec_cfg_ie vs_ie[MWIFIEX_MAX_VSIE_NUM];

#define MWIFIEX_ASSOC_TLV_BUF_SIZE  256
	u8 assoc_tlv_buf[MWIFIEX_ASSOC_TLV_BUF_SIZE];
	u8 assoc_tlv_buf_len;

	u8 *curr_bcn_buf;
	u32 curr_bcn_size;
	/* spin lock for beacon buffer */
	spinlock_t curr_bcn_buf_lock;
	struct wireless_dev wdev;
	struct mwifiex_chan_freq_power cfp;
	u32 versionstrsel;
	char version_str[128];
#ifdef CONFIG_DEBUG_FS
	struct dentry *dfs_dev_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u16 current_key_index;
	struct mutex async_mutex;
	struct cfg80211_scan_request *scan_request;
	u8 cfg_bssid[6];
	struct wps wps;
	u8 scan_block;
	s32 cqm_rssi_thold;
	u32 cqm_rssi_hyst;
	u8 subsc_evt_rssi_state;
	struct mwifiex_ds_misc_subsc_evt async_subsc_evt_storage;
	struct mwifiex_ie mgmt_ie[MAX_MGMT_IE_INDEX];
	u16 beacon_idx;
	u16 proberesp_idx;
	u16 assocresp_idx;
	u16 gen_idx;
	u8 ap_11n_enabled;
	u8 ap_11ac_enabled;
	u32 mgmt_frame_mask;
	struct mwifiex_roc_cfg roc_cfg;
	bool scan_aborting;
	u8 sched_scanning;
	u8 csa_chan;
	unsigned long csa_expire_time;
	u8 del_list_idx;
	bool hs2_enabled;
	struct mwifiex_uap_bss_param bss_cfg;
	struct cfg80211_chan_def bss_chandef;
	struct station_parameters *sta_params;
	struct sk_buff_head tdls_txq;
	u8 check_tdls_tx;
	struct timer_list auto_tdls_timer;
	bool auto_tdls_timer_active;
	struct idr ack_status_frames;
	/* spin lock for ack status */
	spinlock_t ack_status_lock;
	/** rx histogram data */
	struct mwifiex_histogram_data *hist_data;
	struct cfg80211_chan_def dfs_chandef;
	struct workqueue_struct *dfs_cac_workqueue;
	struct delayed_work dfs_cac_work;
	struct timer_list dfs_chan_switch_timer;
	struct workqueue_struct *dfs_chan_sw_workqueue;
	struct delayed_work dfs_chan_sw_work;
	struct cfg80211_beacon_data beacon_after;
	struct mwifiex_11h_intf_state state_11h;
	struct mwifiex_ds_mem_rw mem_rw;
	struct sk_buff_head bypass_txq;
	struct mwifiex_user_scan_chan hidden_chan[MWIFIEX_USER_SCAN_CHAN_MAX];
	u8 assoc_resp_ht_param;
	bool ht_param_present;
};

struct mwifiex_bss_prio_tbl {
	struct list_head bss_prio_head;
	/* spin lock for bss priority  */
	spinlock_t bss_prio_lock;
	struct mwifiex_bss_prio_node *bss_prio_cur;
};

struct bus_aggr_params {
	u16 enable;
	u16 mode;
	u16 tx_aggr_max_size;
	u16 tx_aggr_max_num;
	u16 tx_aggr_align;
};

struct mwifiex_if_ops {
	int (*init_if) (struct mwifiex_adapter *);
	void (*cleanup_if) (struct mwifiex_adapter *);
	int (*check_fw_status) (struct mwifiex_adapter *, u32);
	int (*check_winner_status)(struct mwifiex_adapter *);
	int (*prog_fw) (struct mwifiex_adapter *, struct mwifiex_fw_image *);
	int (*register_dev) (struct mwifiex_adapter *);
	void (*unregister_dev) (struct mwifiex_adapter *);
	int (*enable_int) (struct mwifiex_adapter *);
	void (*disable_int) (struct mwifiex_adapter *);
	int (*process_int_status) (struct mwifiex_adapter *);
	int (*host_to_card) (struct mwifiex_adapter *, u8, struct sk_buff *,
			     struct mwifiex_tx_param *);
	int (*wakeup) (struct mwifiex_adapter *);
	int (*wakeup_complete) (struct mwifiex_adapter *);

	/* Interface specific functions */
	void (*update_mp_end_port) (struct mwifiex_adapter *, u16);
	void (*cleanup_mpa_buf) (struct mwifiex_adapter *);
	int (*cmdrsp_complete) (struct mwifiex_adapter *, struct sk_buff *);
	int (*event_complete) (struct mwifiex_adapter *, struct sk_buff *);
	int (*init_fw_port) (struct mwifiex_adapter *);
	int (*dnld_fw) (struct mwifiex_adapter *, struct mwifiex_fw_image *);
	void (*card_reset) (struct mwifiex_adapter *);
	int (*reg_dump)(struct mwifiex_adapter *, char *);
	void (*device_dump)(struct mwifiex_adapter *);
	int (*clean_pcie_ring) (struct mwifiex_adapter *adapter);
	void (*iface_work)(struct work_struct *work);
	void (*submit_rem_rx_urbs)(struct mwifiex_adapter *adapter);
	void (*deaggr_pkt)(struct mwifiex_adapter *, struct sk_buff *);
	void (*multi_port_resync)(struct mwifiex_adapter *);
	bool (*is_port_ready)(struct mwifiex_private *);
	void (*down_dev)(struct mwifiex_adapter *);
	void (*up_dev)(struct mwifiex_adapter *);
};

struct mwifiex_adapter {
	u8 iface_type;
	unsigned int debug_mask;
	struct mwifiex_iface_comb iface_limit;
	struct mwifiex_iface_comb curr_iface_comb;
	struct mwifiex_private *priv[MWIFIEX_MAX_BSS_NUM];
	u8 priv_num;
	const struct firmware *firmware;
	char fw_name[32];
	int winner;
	struct device *dev;
	struct wiphy *wiphy;
	u8 perm_addr[ETH_ALEN];
	unsigned long work_flags;
	u32 fw_release_number;
	u8 intf_hdr_len;
	u16 init_wait_q_woken;
	wait_queue_head_t init_wait_q;
	void *card;
	struct mwifiex_if_ops if_ops;
	atomic_t bypass_tx_pending;
	atomic_t rx_pending;
	atomic_t tx_pending;
	atomic_t cmd_pending;
	atomic_t tx_hw_pending;
	struct workqueue_struct *workqueue;
	struct work_struct main_work;
	struct workqueue_struct *rx_workqueue;
	struct work_struct rx_work;
	struct workqueue_struct *dfs_workqueue;
	struct work_struct dfs_work;
	bool rx_work_enabled;
	bool rx_processing;
	bool delay_main_work;
	bool rx_locked;
	bool main_locked;
	struct mwifiex_bss_prio_tbl bss_prio_tbl[MWIFIEX_MAX_BSS_NUM];
	/* spin lock for main process */
	spinlock_t main_proc_lock;
	u32 mwifiex_processing;
	u8 more_task_flag;
	u16 tx_buf_size;
	u16 curr_tx_buf_size;
	/* sdio single port rx aggregation capability */
	bool host_disable_sdio_rx_aggr;
	bool sdio_rx_aggr_enable;
	u16 sdio_rx_block_size;
	u32 ioport;
	enum MWIFIEX_HARDWARE_STATUS hw_status;
	u16 number_of_antenna;
	u32 fw_cap_info;
	/* spin lock for interrupt handling */
	spinlock_t int_lock;
	u8 int_status;
	u32 event_cause;
	struct sk_buff *event_skb;
	u8 upld_buf[MWIFIEX_UPLD_SIZE];
	u8 data_sent;
	u8 cmd_sent;
	u8 cmd_resp_received;
	u8 event_received;
	u8 data_received;
	u16 seq_num;
	struct cmd_ctrl_node *cmd_pool;
	struct cmd_ctrl_node *curr_cmd;
	/* spin lock for command */
	spinlock_t mwifiex_cmd_lock;
	u16 last_init_cmd;
	struct timer_list cmd_timer;
	struct list_head cmd_free_q;
	/* spin lock for cmd_free_q */
	spinlock_t cmd_free_q_lock;
	struct list_head cmd_pending_q;
	/* spin lock for cmd_pending_q */
	spinlock_t cmd_pending_q_lock;
	struct list_head scan_pending_q;
	/* spin lock for scan_pending_q */
	spinlock_t scan_pending_q_lock;
	/* spin lock for RX processing routine */
	spinlock_t rx_proc_lock;
	struct sk_buff_head tx_data_q;
	atomic_t tx_queued;
	u32 scan_processing;
	u16 region_code;
	struct mwifiex_802_11d_domain_reg domain_reg;
	u16 scan_probes;
	u32 scan_mode;
	u16 specific_scan_time;
	u16 active_scan_time;
	u16 passive_scan_time;
	u16 scan_chan_gap_time;
	u8 fw_bands;
	u8 adhoc_start_band;
	u8 config_bands;
	struct mwifiex_chan_scan_param_set *scan_channels;
	u8 tx_lock_flag;
	struct mwifiex_sleep_params sleep_params;
	struct mwifiex_sleep_period sleep_period;
	u16 ps_mode;
	u32 ps_state;
	u8 need_to_wakeup;
	u16 multiple_dtim;
	u16 local_listen_interval;
	u16 null_pkt_interval;
	struct sk_buff *sleep_cfm;
	u16 bcn_miss_time_out;
	u16 adhoc_awake_period;
	u8 is_deep_sleep;
	u8 delay_null_pkt;
	u16 delay_to_ps;
	u16 enhanced_ps_mode;
	u8 pm_wakeup_card_req;
	u16 gen_null_pkt;
	u16 pps_uapsd_mode;
	u32 pm_wakeup_fw_try;
	struct timer_list wakeup_timer;
	struct mwifiex_hs_config_param hs_cfg;
	u8 hs_activated;
	u16 hs_activate_wait_q_woken;
	wait_queue_head_t hs_activate_wait_q;
	u8 event_body[MAX_EVENT_SIZE];
	u32 hw_dot_11n_dev_cap;
	u8 hw_dev_mcs_support;
	u8 user_dev_mcs_support;
	u8 adhoc_11n_enabled;
	u8 sec_chan_offset;
	struct mwifiex_dbg dbg;
	u8 arp_filter[ARP_FILTER_MAX_BUF_SIZE];
	u32 arp_filter_size;
	struct mwifiex_wait_queue cmd_wait_q;
	u8 scan_wait_q_woken;
	spinlock_t queue_lock;		/* lock for tx queues */
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	u16 max_mgmt_ie_index;
	const struct firmware *cal_data;
	struct device_node *dt_node;

	/* 11AC */
	u32 is_hw_11ac_capable;
	u32 hw_dot_11ac_dev_cap;
	u32 hw_dot_11ac_mcs_support;
	u32 usr_dot_11ac_dev_cap_bg;
	u32 usr_dot_11ac_dev_cap_a;
	u32 usr_dot_11ac_mcs_support;

	atomic_t pending_bridged_pkts;

	/* For synchronizing FW initialization with device lifecycle. */
	struct completion *fw_done;

	bool ext_scan;
	u8 fw_api_ver;
	u8 key_api_major_ver, key_api_minor_ver;
	struct memory_type_mapping *mem_type_mapping_tbl;
	u8 num_mem_types;
	bool scan_chan_gap_enabled;
	struct sk_buff_head rx_data_q;
	bool mfg_mode;
	struct mwifiex_chan_stats *chan_stats;
	u32 num_in_chan_stats;
	int survey_idx;
	bool auto_tdls;
	u8 coex_scan;
	u8 coex_min_scan_time;
	u8 coex_max_scan_time;
	u8 coex_win_size;
	u8 coex_tx_win_size;
	u8 coex_rx_win_size;
	bool drcs_enabled;
	u8 active_scan_triggered;
	bool usb_mc_status;
	bool usb_mc_setup;
	struct cfg80211_wowlan_nd_info *nd_info;
	struct ieee80211_regdomain *regd;

	/* Wake-on-WLAN (WoWLAN) */
	int irq_wakeup;
	bool wake_by_wifi;
	/* Aggregation parameters*/
	struct bus_aggr_params bus_aggr;
	/* Device dump data/length */
	void *devdump_data;
	int devdump_len;
	struct timer_list devdump_timer;
};

static void (*klpe_mwifiex_stop_net_dev_queue)(struct net_device *netdev,
		struct mwifiex_adapter *adapter);

static int (*klpe_mwifiex_send_cmd)(struct mwifiex_private *priv, u16 cmd_no,
		     u16 cmd_action, u32 cmd_oid, void *data_buf, bool sync);

static s32 (*klpe_mwifiex_ssid_cmp)(struct cfg80211_ssid *ssid1, struct cfg80211_ssid *ssid2);
static int (*klpe_mwifiex_associate)(struct mwifiex_private *priv,
		      struct mwifiex_bssdescriptor *bss_desc);

static u8 (*klpe_mwifiex_band_to_radio_type)(u8 band);

static int (*klpe_mwifiex_adhoc_start)(struct mwifiex_private *priv,
			struct cfg80211_ssid *adhoc_ssid);
static int (*klpe_mwifiex_adhoc_join)(struct mwifiex_private *priv,
		       struct mwifiex_bssdescriptor *bss_desc);

static inline u8
mwifiex_11h_get_csa_closed_channel(struct mwifiex_private *priv)
{
	if (!priv->csa_chan)
		return 0;

	/* Clear csa channel, if DFS channel move time has passed */
	if (time_after(jiffies, priv->csa_expire_time)) {
		priv->csa_chan = 0;
		priv->csa_expire_time = 0;
	}

	return priv->csa_chan;
}

static int (*klpe_mwifiex_fill_new_bss_desc)(struct mwifiex_private *priv,
			      struct cfg80211_bss *bss,
			      struct mwifiex_bssdescriptor *bss_desc);

static int (*klpe_mwifiex_check_network_compatibility)(struct mwifiex_private *priv,
					struct mwifiex_bssdescriptor *bss_desc);

static void (*klpe_mwifiex_dnld_txpwr_table)(struct mwifiex_private *priv);


/* from drivers/net/wireless/marvell/mwifiex/sta_ioctl.c */
static int klpp_mwifiex_process_country_ie(struct mwifiex_private *priv,
				      struct cfg80211_bss *bss)
{
	const u8 *country_ie;
	u8 country_ie_len;
	struct mwifiex_802_11d_domain_reg *domain_info =
					&priv->adapter->domain_reg;

	rcu_read_lock();
	country_ie = (*klpe_ieee80211_bss_get_ie)(bss, WLAN_EID_COUNTRY);
	if (!country_ie) {
		rcu_read_unlock();
		return 0;
	}

	country_ie_len = country_ie[1];
	if (country_ie_len < IEEE80211_COUNTRY_IE_MIN_LEN) {
		rcu_read_unlock();
		return 0;
	}

	if (!strncmp(priv->adapter->country_code, &country_ie[2], 2)) {
		rcu_read_unlock();
		klpr_mwifiex_dbg(priv->adapter, INFO,
			    "11D: skip setting domain info in FW\n");
		return 0;
	}

	/*
	 * Fix CVE-2019-14895
	 *  +8 lines
	 */
	if (country_ie_len >
	    (IEEE80211_COUNTRY_STRING_LEN + MWIFIEX_MAX_TRIPLET_802_11D)) {
		rcu_read_unlock();
		klpr_mwifiex_dbg(priv->adapter, ERROR,
			    "11D: country_ie_len overflow!, deauth AP\n");
		return -EINVAL;
	}

	memcpy(priv->adapter->country_code, &country_ie[2], 2);

	domain_info->country_code[0] = country_ie[2];
	domain_info->country_code[1] = country_ie[3];
	domain_info->country_code[2] = ' ';

	country_ie_len -= IEEE80211_COUNTRY_STRING_LEN;

	domain_info->no_of_triplet =
		country_ie_len / sizeof(struct ieee80211_country_ie_triplet);

	memcpy((u8 *)domain_info->triplet,
	       &country_ie[2] + IEEE80211_COUNTRY_STRING_LEN, country_ie_len);

	rcu_read_unlock();

	if ((*klpe_mwifiex_send_cmd)(priv, HostCmd_CMD_802_11D_DOMAIN_INFO,
			     HostCmd_ACT_GEN_SET, 0, NULL, false)) {
		klpr_mwifiex_dbg(priv->adapter, ERROR,
			    "11D: setting domain info in FW fail\n");
		return -1;
	}

	(*klpe_mwifiex_dnld_txpwr_table)(priv);

	return 0;
}

int klpp_mwifiex_bss_start(struct mwifiex_private *priv, struct cfg80211_bss *bss,
		      struct cfg80211_ssid *req_ssid)
{
	int ret;
	struct mwifiex_adapter *adapter = priv->adapter;
	struct mwifiex_bssdescriptor *bss_desc = NULL;

	priv->scan_block = false;

	if (bss) {
		/*
		 * Fix CVE-2019-14895
		 *  -1 line, +3 lines
		 */
		if (adapter->region_code == 0x00 &&
		    klpp_mwifiex_process_country_ie(priv, bss))
			return -EINVAL;

		/* Allocate and fill new bss descriptor */
		bss_desc = kzalloc(sizeof(struct mwifiex_bssdescriptor),
				   GFP_KERNEL);
		if (!bss_desc)
			return -ENOMEM;

		ret = (*klpe_mwifiex_fill_new_bss_desc)(priv, bss, bss_desc);
		if (ret)
			goto done;
	}

	if (priv->bss_mode == NL80211_IFTYPE_STATION ||
	    priv->bss_mode == NL80211_IFTYPE_P2P_CLIENT) {
		u8 config_bands;

		if (!bss_desc)
			return -1;

		if ((*klpe_mwifiex_band_to_radio_type)(bss_desc->bss_band) ==
						HostCmd_SCAN_RADIO_TYPE_BG) {
			config_bands = BAND_B | BAND_G | BAND_GN;
		} else {
			config_bands = BAND_A | BAND_AN;
			if (adapter->fw_bands & BAND_AAC)
				config_bands |= BAND_AAC;
		}

		if (!((config_bands | adapter->fw_bands) & ~adapter->fw_bands))
			adapter->config_bands = config_bands;

		ret = (*klpe_mwifiex_check_network_compatibility)(priv, bss_desc);
		if (ret)
			goto done;

		if (mwifiex_11h_get_csa_closed_channel(priv) ==
							(u8)bss_desc->channel) {
			klpr_mwifiex_dbg(adapter, ERROR,
				    "Attempt to reconnect on csa closed chan(%d)\n",
				    bss_desc->channel);
			ret = -1;
			goto done;
		}

		klpr_mwifiex_dbg(adapter, INFO,
			    "info: SSID found in scan list ...\t"
			    "associating...\n");

		(*klpe_mwifiex_stop_net_dev_queue)(priv->netdev, adapter);
		if (netif_carrier_ok(priv->netdev))
			netif_carrier_off(priv->netdev);

		/* Clear any past association response stored for
		 * application retrieval */
		priv->assoc_rsp_size = 0;
		ret = (*klpe_mwifiex_associate)(priv, bss_desc);

		/* If auth type is auto and association fails using open mode,
		 * try to connect using shared mode */
		if (ret == WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG &&
		    priv->sec_info.is_authtype_auto &&
		    priv->sec_info.wep_enabled) {
			priv->sec_info.authentication_mode =
						NL80211_AUTHTYPE_SHARED_KEY;
			ret = (*klpe_mwifiex_associate)(priv, bss_desc);
		}

		if (bss)
			(*klpe_cfg80211_put_bss)(priv->adapter->wiphy, bss);
	} else {
		/* Adhoc mode */
		/* If the requested SSID matches current SSID, return */
		if (bss_desc && bss_desc->ssid.ssid_len &&
		    (!(*klpe_mwifiex_ssid_cmp)(&priv->curr_bss_params.bss_descriptor.
				       ssid, &bss_desc->ssid))) {
			ret = 0;
			goto done;
		}

		priv->adhoc_is_link_sensed = false;

		ret = (*klpe_mwifiex_check_network_compatibility)(priv, bss_desc);

		(*klpe_mwifiex_stop_net_dev_queue)(priv->netdev, adapter);
		if (netif_carrier_ok(priv->netdev))
			netif_carrier_off(priv->netdev);

		if (!ret) {
			klpr_mwifiex_dbg(adapter, INFO,
				    "info: network found in scan\t"
				    " list. Joining...\n");
			ret = (*klpe_mwifiex_adhoc_join)(priv, bss_desc);
			if (bss)
				(*klpe_cfg80211_put_bss)(priv->adapter->wiphy, bss);
		} else {
			klpr_mwifiex_dbg(adapter, INFO,
				    "info: Network not found in\t"
				    "the list, creating adhoc with ssid = %s\n",
				    req_ssid->ssid);
			ret = (*klpe_mwifiex_adhoc_start)(priv, req_ssid);
		}
	}

done:
	/* beacon_ie buffer was allocated in function
	 * mwifiex_fill_new_bss_desc(). Free it now.
	 */
	if (bss_desc)
		kfree(bss_desc->beacon_buf);
	kfree(bss_desc);

	if (ret < 0)
		priv->attempted_bss_desc = NULL;

	return ret;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ieee80211_bss_get_ie", (void *)&klpe_ieee80211_bss_get_ie,
	  "cfg80211" },
	{ "cfg80211_put_bss", (void *)&klpe_cfg80211_put_bss, "cfg80211" },
	{ "_mwifiex_dbg", (void *)&klpe__mwifiex_dbg, "mwifiex" },
	{ "mwifiex_stop_net_dev_queue",
	  (void *)&klpe_mwifiex_stop_net_dev_queue, "mwifiex" },
	{ "mwifiex_send_cmd", (void *)&klpe_mwifiex_send_cmd, "mwifiex" },
	{ "mwifiex_ssid_cmp", (void *)&klpe_mwifiex_ssid_cmp, "mwifiex" },
	{ "mwifiex_associate", (void *)&klpe_mwifiex_associate, "mwifiex" },
	{ "mwifiex_band_to_radio_type",
	  (void *)&klpe_mwifiex_band_to_radio_type, "mwifiex" },
	{ "mwifiex_adhoc_start", (void *)&klpe_mwifiex_adhoc_start, "mwifiex" },
	{ "mwifiex_adhoc_join", (void *)&klpe_mwifiex_adhoc_join, "mwifiex" },
	{ "mwifiex_fill_new_bss_desc",
	  (void *)&klpe_mwifiex_fill_new_bss_desc, "mwifiex" },
	{ "mwifiex_check_network_compatibility",
	  (void *)&klpe_mwifiex_check_network_compatibility, "mwifiex" },
	{ "mwifiex_dnld_txpwr_table",
	  (void *)&klpe_mwifiex_dnld_txpwr_table, "mwifiex" },
};

static int livepatch_bsc1173100_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1173100_module_nb = {
	.notifier_call = livepatch_bsc1173100_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1173100_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1173100_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1173100_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1173100_module_nb);
}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
