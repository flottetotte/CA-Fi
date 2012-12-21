#include <linux/list.h>

/*O-Fi Debug output*/
//#define OFI_DEBUG 						

/*O-Fi Header Sizes*/
#define OFI_HDR_LEN   					14
#define OFI_CHUNKHDR_LEN   				18

#define OFI_BLOOM_LEN                   12
#define OFI_NLMSGHDR_LEN                4

#define OFFSET_TO_OFI  					16

#define TRUE							1
#define FALSE							0

#define IEEE_OFI_SYTPE					0x04

#define OFI_QUEUE_CHECK_FREQ			3

/*O-Fi Types/Traffic Classes*/
#define OFI_TYPE_MIN					0
#define OFI_TYPE_URG					10
#define OFI_TYPE_MGMT					20
#define OFI_TYPE_USR					50
#define OFI_TYPE_MAX					255
/*Number of OFI Types*/
#define OFI_TYPE_COUNT					3

/*Netlink message types*/
#define OFI_NETLINK_MSG		 			28
#define OFI_NETLINK_MAX_PAYLOAD       	1504

#define OFI_NL_CTRL     				1
/*OFI CTRL Subtypes*/
#define OFI_NL_CTRL_REG					1
#define OFI_NL_CTRL_ID_REG  			2
#define OFI_NL_CTRL_ID_DEL  			3

#define OFI_NL_DATA     				2

#define OFI_NL_DBG      				3

/*O-Fi allowed frame sizes*/
#define OFI_FRAME_SIZE_MIN				OFFSET_TO_OFI + OFI_HDR_LEN + OFI_CHUNKHDR_LEN
#define OFI_FRAME_SIZE_MAX				1500 + OFFSET_TO_OFI

/*O-Fi circular transmit buffer*/
#define OFI_TRANSMIT_FIFO_ENTRY_SIZE	1500
#define OFI_TRANSMIT_FIFO_MAX_ELEMS		2
#define OFI_URG_ELEMENTS_MAX			2

/*O-Fi max number of own fcs items*/
#define OFI_OWN_FCS_ITEMS_MAX			1

#define OFI_INTERFACE					"wlan0"

/*IEEE 802.11 Channel Frequencies*/
#define IEEE80211_CHAN_FREQ_1			0x096c	/* 2412 */
#define IEEE80211_CHAN_FREQ_2			0x0971	/* 2417 */
#define IEEE80211_CHAN_FREQ_3			0x0976	/* 2422 */
#define IEEE80211_CHAN_FREQ_4			0x097b	/* 2427 */
#define IEEE80211_CHAN_FREQ_5			0x0980	/* 2432 */
#define IEEE80211_CHAN_FREQ_6			0x0985	/* 2437 */
#define IEEE80211_CHAN_FREQ_7			0x098a	/* 2442 */
#define IEEE80211_CHAN_FREQ_8			0x098f	/* 2447 */
#define IEEE80211_CHAN_FREQ_9			0x0994	/* 2452 */
#define IEEE80211_CHAN_FREQ_10			0x0999	/* 2457 */
#define IEEE80211_CHAN_FREQ_11			0x099e	/* 2452 */
#define IEEE80211_CHAN_FREQ_12			0x09a3	/* 2457 */
#define IEEE80211_CHAN_FREQ_13			0x09a8	/* 2462 */

#define	timercmp(tvp, uvp, cmp)	\
	((tvp)->tv_sec cmp (uvp)->tv_sec || \
	 (tvp)->tv_sec == (uvp)->tv_sec && (tvp)->tv_usec cmp (uvp)->tv_usec)

/*IeeeHdr workpiece*/
struct ieee80211_ofi_hdr {
	u16 	frame_control;
	u16 	duration_id;
	u8 		addr1[ETH_ALEN];
	u8 		addr2[ETH_ALEN];
} __packed;

/*Main O-Fi Header*/
struct ofi_hdr {
	unsigned char	bloom[12];	
	u16 			len;
};

/*Chunk O-Fi Header*/
struct ofi_chunk_hdr {
	unsigned char	bloom[12];
	u8 				type;
	u8				ttl;
	u8				rtx;
	u8				rsvd;	
	u16 			len;
};

/*O-Fi subscribed bloom ids list item*/
struct ofi_subscription_entry {
    struct list_head 		list;
    unsigned char			id[256];
};

/*O-Fi already seen subscribed chunks*/
struct ofi_seen_entry {
    struct list_head 		list;
    int						fcs;
};

/*O-Fi chunk queue list item*/
struct ofi_queue_entry {
    struct list_head 		list;
    struct ofi_chunk_hdr	*chunkh;
    unsigned char			*data;
    u8						local_rtx;
    struct timeval 			local_time;
    int						fcs;
};

/*O-Fi intermediate buffer*/
struct ofi_inter_entry {
    struct list_head 		list;
    u16						len;
    unsigned char			*data;
};

/*O-Fi possible packing list*/
struct ofi_transmit_packing_entry {
    struct list_head 		list;
    u16						size;
    u8						urg_count;
    struct list_head 		packing;
};

/*O-Fi packing item*/
struct ofi_packing_entry {
	struct list_head 		list;
	struct list_head 		*entry;
};

/*O-Fi transmit buffer item*/
typedef struct {
    unsigned char			data[OFI_TRANSMIT_FIFO_ENTRY_SIZE];
} ofi_transmit_entry;

/*O-Fi Circular transmit buffer*/
typedef struct {
    int         			size;   	//maximum number of elements 
    int         			start;
    int         			end;
    ofi_transmit_entry   	*elems;
} ofi_circular_transmit_buffer;

/*O-Fi Netlink Message Hdr*/
struct ofi_nl_msg_hdr {
  unsigned char 			type;
  unsigned char				param;
  u16	        			len;
};

static const unsigned char OFi_IEEE_Hdr[] = {
	0x04, 								// subtype type (reserverd control frame type)
	0x00, 								// flags (more frags, no sense for CF-End)
	0x00, 0x00, 						// duration
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dest mac
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src mac
};
