#include "ieee80211_i.h"
/**
 * Copy the skbuff and convert OFI stuff into a netlink frame
 *
 * @param rx		       	reference to the received data
 */
void ofi_msg_handler(struct ieee80211_rx_data *rx);

/**
 * Init stuff needed by O-Fi. This simply sets the 
 * kernel timer, inits a list as a queue. Should be called
 * when device is brought up
 */
int ofi_init(void);

/**
 * Clean stuff needed by O-Fi. This kills the 
 * kernel timer and clears the queue. Should be called
 * when device is brought down
 */
void ofi_clean(void);

/**
 * check bloom id in rx
 */
//int ofi_check_sub_fast(unsigned char *bloom_filter);
