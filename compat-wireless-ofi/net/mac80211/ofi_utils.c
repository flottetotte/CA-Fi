#include <linux/module.h> 
#include <linux/crc32.h>
#include <linux/ieee80211.h>
#include "ofidefines.h"
#include "bloom.h"
#include "ieee80211_i.h"

/*Getting IP in Kernelspace*/
#include <linux/inetdevice.h> 
#include <linux/netdevice.h>    

/*Kernel Timer*/
#include <linux/timer.h>

/*Double Linked List*/
#include <linux/list.h>

/*Includes for Netlink Stuff*/
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/netlink.h>

/*Spinlocks*/
#include <linux/spinlock.h>
#include <linux/mutex.h>

/*Delaying execution*/
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>

/*freq to chan*/
#include "../wireless/core.h"

/*Globals*/
bool ofi_stop_task = FALSE;
bool ofi_stop_proc_task = FALSE;
bool ofi_work_process = FALSE;
int ofi_pid = 0;
struct sock* nl_sk = NULL;
struct timer_list ofi_timer;
struct timeval last_process_round;
ofi_circular_transmit_buffer ofi_circular_tb; 
int ofi_fcs_count = 0;
int ofi_types[OFI_TYPE_COUNT] = {OFI_TYPE_MIN, OFI_TYPE_URG, OFI_TYPE_MAX};
#ifdef OFI_DEBUG
	int chunkcount = 0;
#endif	

spinlock_t ofi_queue_lock;
spinlock_t ofi_seen_lock;
spinlock_t ofi_subscription_lock;
spinlock_t ofi_transmit_lock;
spinlock_t ofi_buffer_lock;
spinlock_t ofi_work_process_signal_lock;
spinlock_t ofi_transmit_list_lock;

static struct mutex ofi_queue_mutex;
static struct mutex ofi_seen_mutex;
static struct mutex ofi_subscription_mutex;
static struct mutex ofi_transmit_mutex;
static struct mutex ofi_buffer_mutex;
static struct mutex ofi_transmit_list_mutex;

struct task_struct *ofi_tr_task, *ofi_process_task;

int ofi_transmit_task(void*);

LIST_HEAD(ofi_chunk_queue);
LIST_HEAD(ofi_chunks_seen);
LIST_HEAD(ofi_subscribed_ids);
LIST_HEAD(ofi_transmit_list);
DECLARE_WAIT_QUEUE_HEAD(ofi_wait_queue);
DECLARE_WAIT_QUEUE_HEAD(ofi_proc_queue);

void ofi_circular_transmit_buff_init(ofi_circular_transmit_buffer *tb, int size) 
{
	printk("ofi buffer init\n");
    tb->size  = size + 1; /* include empty elem */
    tb->start = 0;
    tb->end   = 0;
    tb->elems = (ofi_transmit_entry *)kmalloc((tb->size * sizeof(ofi_transmit_entry)), GFP_KERNEL);
    printk(KERN_DEBUG "ofi transmit buffer init has allocated buffer with size %lu Bytes\n", tb->size * sizeof(ofi_transmit_entry));
}
 
void ofi_circular_transmit_buff_free(ofi_circular_transmit_buffer *tb) 
{
    kfree(tb->elems); /* OK if null */ 
}
 
int ofi_circular_transmit_buff_is_full(ofi_circular_transmit_buffer *tb) 
{
    return (tb->end + 1) % tb->size == tb->start; 
}
 
int ofi_circular_transmit_buff_is_empty(ofi_circular_transmit_buffer *tb) 
{
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi circ buff check empty\n");
	#endif	
    return tb->end == tb->start; 
}

/* Write an element, overwriting oldest element if buffer is full. Can
   choose to avoid the overwrite by checking ofi_circular_transmit_buff_is_full(). */
void ofi_circular_transmit_buff_write(ofi_circular_transmit_buffer *tb, unsigned char *data, int data_len) 
{
	#ifdef OFI_DEBUG
		printk("ofi circ transmit buff write\n");
	#endif	
    memset(&tb->elems[tb->end], 0, OFI_TRANSMIT_FIFO_ENTRY_SIZE);
    memcpy(&tb->elems[tb->end], data, data_len);
    tb->end = (tb->end + 1) % tb->size;
    if (tb->end == tb->start)
        tb->start = (tb->start + 1) % tb->size; /* full, overwrite */
}
 
/* Read oldest element. Must ensure !ofi_circular_transmit_buff_is_empty() first. */
void ofi_circular_transmit_buff_read(ofi_circular_transmit_buffer *tb, ofi_transmit_entry *elem) 
{
    *elem = tb->elems[tb->start];
    tb->start = (tb->start + 1) % tb->size;
}

static enum work_done_result ofi_xmit_done(struct ieee80211_work *wk, struct sk_buff *skb)
{
	/*
	 * Use the data embedded in the work struct for reporting
	 * here so if the driver mangled the SKB before dropping
	 * it (which is the only way we really should get here)
	 * then we don't report mangled data.
	 *
	 * If there was no wait time, then by the time we get here
	 * the driver will likely not have reported the status yet,
	 * so in that case userspace will have to deal with it.
	 */
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi xmit_done, wk->offchan_tx.status = %i\n", wk->offchan_tx.status);
	#endif	
	if (wk->offchan_tx.wait && !wk->offchan_tx.status) {
		cfg80211_mgmt_tx_status(wk->sdata->dev,
					(unsigned long) wk->offchan_tx.frame,
					wk->data, wk->data_len, false, GFP_ATOMIC);
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi xmit_done if (wk->offchan_tx.wait && !wk->offchan_tx.status)\n");
		#endif	
	}	

	return WORK_DONE_DESTROY;
}

int ofi_xmit(unsigned char* data, int data_len, int freq)
{
	struct ieee80211_channel *chan;
	struct sk_buff *skb;
	struct ieee80211_work *wk;
	u32 flags;
	int len, wait;
	//int i;
	struct net_device *ofi_net_dev = NULL;
	struct ieee80211_sub_if_data* ofi_sdata_glb = NULL;
	struct ieee80211_local *ofi_local = NULL;
	struct wireless_dev *ofi_wdev = NULL;
	struct cfg80211_registered_device *ofi_rdev = NULL;

	if(!data)
		return -1;

	if(!ofi_net_dev) {
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi net dev set once\n");
		#endif	
		ofi_net_dev = dev_get_by_name(&init_net, OFI_INTERFACE);
		ofi_sdata_glb = IEEE80211_DEV_TO_SUB_IF(ofi_net_dev);
		ofi_local = ofi_sdata_glb->local;
		ofi_wdev = ofi_net_dev->ieee80211_ptr;
		ofi_rdev = wiphy_to_dev(ofi_wdev->wiphy);
	}

	if(freq == 0){
		freq = ofi_local->oper_channel->center_freq;
	}
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi xmit\n");
	#endif	

	rcu_read_lock();

	/* setting len of data and wait to 0*/
	len = data_len + sizeof(OFi_IEEE_Hdr);
	
	wait = 0;
	
	chan = rdev_freq_to_chan(ofi_rdev, freq, NL80211_CHAN_NO_HT);

	/* Setting flags to no ack */
	flags = IEEE80211_TX_CTL_NO_ACK;
	flags |= IEEE80211_TX_CTL_NO_CCK_RATE;

	skb = dev_alloc_skb(ofi_local->hw.extra_tx_headroom + len);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, ofi_local->hw.extra_tx_headroom);

	memcpy(skb_put(skb, sizeof(OFi_IEEE_Hdr)), OFi_IEEE_Hdr, sizeof(OFi_IEEE_Hdr));
	memcpy(skb_put(skb, data_len), data, data_len);
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi work item len %i\n", len);
	#endif	

	IEEE80211_SKB_CB(skb)->flags = flags;

	if (flags & IEEE80211_TX_CTL_TX_OFFCHAN)
		IEEE80211_SKB_CB(skb)->hw_queue =
			ofi_local->hw.offchannel_tx_hw_queue;

	skb->dev = ofi_sdata_glb->dev;

	/*create the work item and put it in the queue*/
	wk = kzalloc(sizeof(*wk) + len, GFP_KERNEL);
	if (!wk) {
		kfree_skb(skb);
		return -ENOMEM;
	}

	wk->type = IEEE80211_WORK_OFFCHANNEL_TX;
	wk->chan = chan;
	wk->chan_type = NL80211_CHAN_NO_HT;
	wk->sdata = ofi_sdata_glb;
	wk->done = ofi_xmit_done;
	wk->offchan_tx.frame = skb;
	wk->offchan_tx.wait = wait;
	wk->data_len = len;

	memcpy(wk->data, skb, len);

	ieee80211_add_work(wk);	

	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi xmit work item added\n");
	#endif	


	rcu_read_unlock();
	dev_put(ofi_net_dev);
	ofi_net_dev = NULL;
	return NETDEV_TX_OK;
}

int ofi_user_xmit(unsigned char* data, int freq)
{
	int data_len;
	struct ofi_hdr *ofih;

	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi user xmit\n");
	#endif	
	ofih = (struct ofi_hdr *)data;
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofih->len %i\n", ofih->len);
	#endif	
	data_len = ofih->len + OFI_HDR_LEN;
	return ofi_xmit(data, data_len, freq);
}

int ofi_transmit_task(void* unused)
{
	int res;
	ofi_transmit_entry *ofientry;
	struct net_device *ofi_net_dev = NULL;
	struct ieee80211_sub_if_data* ofi_sdata_glb = NULL;
	struct ieee80211_local *ofi_local = NULL;
	struct wireless_dev *ofi_wdev = NULL;
	struct cfg80211_registered_device *ofi_rdev = NULL;

	allow_signal(SIGKILL);

	ofientry = (ofi_transmit_entry *)kmalloc(sizeof(ofi_transmit_entry), GFP_KERNEL);
	while(!kthread_should_stop()){
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi packing transmit task has called from queue.\n");
		#endif	
		res = wait_event_interruptible(ofi_wait_queue, (!ofi_circular_transmit_buff_is_empty(&ofi_circular_tb) || ofi_stop_task));
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi packing transmit wait_event_interruptible res %i.\n", res);
			printk(KERN_DEBUG "ofi packing transmit task call.\n");
		#endif	
		spin_lock(&ofi_buffer_lock);
		if(ofi_circular_transmit_buff_is_empty(&ofi_circular_tb)) {
			spin_unlock(&ofi_buffer_lock);
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi packing transmit task nothing to do here.\n");
			#endif	
		} else {
			spin_unlock(&ofi_buffer_lock);
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi transmit task has been awakened.\n");
			#endif	
			if(!ofi_net_dev) {
				#ifdef OFI_DEBUG
					printk(KERN_DEBUG "ofi net dev set once\n");
				#endif	
				ofi_net_dev = dev_get_by_name(&init_net, OFI_INTERFACE);
				ofi_sdata_glb = IEEE80211_DEV_TO_SUB_IF(ofi_net_dev);
				ofi_local = ofi_sdata_glb->local;
				ofi_wdev = ofi_net_dev->ieee80211_ptr;
				ofi_rdev = wiphy_to_dev(ofi_wdev->wiphy);
			}
			while(!ofi_circular_transmit_buff_is_empty(&ofi_circular_tb)){
				spin_lock(&ofi_buffer_lock);
				ofi_circular_transmit_buff_read(&ofi_circular_tb, ofientry);
				spin_unlock(&ofi_buffer_lock);
				switch(ofi_local->oper_channel->center_freq){
					case IEEE80211_CHAN_FREQ_1:
					case IEEE80211_CHAN_FREQ_6:
					case IEEE80211_CHAN_FREQ_11:
						/*Send on those anyway*/
					break;
					default:
						ofi_user_xmit(ofientry->data, 0);
					break;
				}
				ofi_user_xmit(ofientry->data, IEEE80211_CHAN_FREQ_1);
				ofi_user_xmit(ofientry->data, IEEE80211_CHAN_FREQ_6);
				ofi_user_xmit(ofientry->data, IEEE80211_CHAN_FREQ_11);
			}
			dev_put(ofi_net_dev);
			ofi_net_dev = NULL;	
		}
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi transmit task end of run.\n");
		#endif	
	}
	kfree(ofientry);
	return 0;

}

void ofi_add_subscription(char *sub_id)
{
	struct list_head *pos;
	struct ofi_subscription_entry *ofisubent;
	int cmp_res = 1;

	if(!list_empty(&ofi_subscribed_ids)){
		spin_lock(&ofi_subscription_lock);
	    list_for_each(pos, &ofi_subscribed_ids) {
	    	ofisubent = list_entry(pos, struct ofi_subscription_entry, list);
	    	cmp_res = strcmp(sub_id, ofisubent->id);
	    	#ifdef OFI_DEBUG
	    		printk(KERN_DEBUG "sub_id %s, ofisubent->id %s.\n", sub_id, ofisubent->id);
	    	#endif	
	  	}
		spin_unlock(&ofi_subscription_lock);
	} 
	/*strcmp returns 0 if equal*/
	if(cmp_res){
		ofisubent = (struct ofi_subscription_entry*)kmalloc(sizeof(struct ofi_subscription_entry), GFP_KERNEL);
		strcpy(ofisubent->id, sub_id);
		spin_lock(&ofi_subscription_lock);
		list_add_tail(&ofisubent->list, &ofi_subscribed_ids);
		spin_unlock(&ofi_subscription_lock);
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi added id to subscriptions %s.\n", ofisubent->id);
		#endif	
	}	
}

void ofi_del_subscription(char *sub_id)
{
	struct list_head *pos, *q;
	struct list_head *store = NULL;
	struct ofi_subscription_entry *ofisubent;
	int cmp_res = 1;

	if(!list_empty(&ofi_subscribed_ids)){
		spin_lock(&ofi_subscription_lock);
	    list_for_each_safe(pos, q, &ofi_subscribed_ids) {
	    	ofisubent = list_entry(pos, struct ofi_subscription_entry, list);
	    	cmp_res = strcmp(sub_id, ofisubent->id);
	    	if(!cmp_res){
	    		#ifdef OFI_DEBUG
	    			printk(KERN_DEBUG "ofi found id to del %s\n", ofisubent->id);
	    		#endif	
	    		store = pos;
	    		break;
	    	}
	  	}
		spin_unlock(&ofi_subscription_lock);
	}

	if(store) {
		spin_lock(&ofi_subscription_lock);
  		list_del(store);
  		#ifdef OFI_DEBUG
  			printk(KERN_DEBUG "ofi del entry %s\n", ofisubent->id);
  		#endif	
  		kfree(ofisubent);
		spin_unlock(&ofi_subscription_lock);
	}	
}

int ofi_check_subscription(unsigned char *bloom_filter)
{
	struct list_head *pos;
	struct ofi_subscription_entry *ofisubent;
	int res = 0;

	spin_lock(&ofi_subscription_lock);
	list_for_each(pos, &ofi_subscribed_ids) {
	    ofisubent = list_entry(pos, struct ofi_subscription_entry, list);
	    res += bloom_check(ofisubent->id, bloom_filter);
	    #ifdef OFI_DEBUG
	    	printk("ofi chunk for me result %i\n", res);
	    #endif	
	}
	spin_unlock(&ofi_subscription_lock);
	return res;
}

void ofi_comm_input(struct sk_buff* skb)
{
	struct nlmsghdr *nlh;
  	int pid, i;
  	struct sk_buff* skb_out;
  	int res;
  	int tmp_ttl;
  	unsigned char *ofinldata, *d;
  	struct ofi_nl_msg_hdr *ofinlmsg;
  	struct ofi_nl_msg_hdr *ofinlh;
  	char* bloom_id;
  	struct ofi_queue_entry *ofiquent;
  	struct ofi_chunk_hdr *ofichunkh;
  	unsigned long chunk_fcs = 0;
	#ifdef OFI_DEBUG
  		printk("ofi_comm_input\n");
  	#endif	

  	nlh = (struct nlmsghdr*) skb->data;
  	
	ofinlmsg = (struct ofi_nl_msg_hdr *)NLMSG_DATA(nlh);
	ofinldata = (unsigned char *)((char *)ofinlmsg + OFI_NLMSGHDR_LEN); 

	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi Netlink user space sent %i %i\n", ofinlmsg->type, ofinlmsg->param);
	#endif	
	switch(ofinlmsg->type){
		case OFI_NL_CTRL:
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi Netlink received msg type OFI_NL_CTRL param %i len %i\n", ofinlmsg->param, ofinlmsg->len);
			#endif				
			if(ofinlmsg->param == OFI_NL_CTRL_REG){
				ofi_pid = nlh->nlmsg_pid;
				#ifdef OFI_DEBUG
					printk(KERN_DEBUG "ofi Netlink user space pid set to %i\n", ofi_pid);
				#endif	
			}
			if(ofinlmsg->param == OFI_NL_CTRL_ID_REG){
				bloom_id = (char*)(NLMSG_DATA(nlh) + sizeof(struct ofi_nl_msg_hdr));
				ofi_add_subscription(bloom_id);
			}
			if(ofinlmsg->param == OFI_NL_CTRL_ID_DEL){
				bloom_id = (char*)(NLMSG_DATA(nlh) + sizeof(struct ofi_nl_msg_hdr));
				ofi_del_subscription(bloom_id);
			}
		break;
		case OFI_NL_DATA:
			ofichunkh = (struct ofi_chunk_hdr *)(ofinldata + OFI_HDR_LEN);
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi Netlink received msg type OFI_NL_DATA param %i len %i\n", ofinlmsg->param, ofinlmsg->len);
			#endif	
			ofiquent = (struct ofi_queue_entry *) kmalloc(sizeof(struct ofi_queue_entry), GFP_KERNEL);
			ofiquent->chunkh = (struct ofi_chunk_hdr *) kmalloc(sizeof(struct ofi_chunk_hdr), GFP_KERNEL);
			ofiquent->data = (unsigned char *) kmalloc(ofichunkh->len, GFP_KERNEL);
			memcpy(ofiquent->chunkh, ofichunkh, OFI_CHUNKHDR_LEN);
			memcpy(ofiquent->data, (unsigned char *)ofichunkh + OFI_CHUNKHDR_LEN, ofichunkh->len);
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi Netlink received 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", ofichunkh->bloom[0], ofichunkh->bloom[1], ofichunkh->bloom[2],
					ofichunkh->bloom[3], ofichunkh->bloom[4], ofichunkh->bloom[5], ofichunkh->bloom[6], ofichunkh->bloom[7], ofichunkh->bloom[8], 
					ofichunkh->bloom[9], ofichunkh->bloom[10], ofichunkh->bloom[11]);
				printk(KERN_DEBUG "ofi Netlink received type %i ttl %i rtx %i rsvd %i len %i\n", ofichunkh->type, ofichunkh->ttl, 
					ofichunkh->rtx, ofichunkh->rsvd, ofichunkh->len);
				
				d = (unsigned char*) ofinldata;
				for(i=0; i < OFI_HDR_LEN + OFI_CHUNKHDR_LEN; i++){
					printk(KERN_DEBUG "ofi Netlink ofichunkh[%i] = %02x\n", i ,d[i]);
				}	
			#endif	
			ofiquent->local_rtx = ofichunkh->rtx;
			ofiquent->local_time.tv_sec = 0;
			ofiquent->local_time.tv_usec = 0;

			tmp_ttl = ofichunkh->ttl;
			ofichunkh->ttl = 0;
			chunk_fcs = crc32_le(~0, (unsigned char*)ofichunkh, OFI_CHUNKHDR_LEN + ofichunkh->len);
			/*re-set*/
			ofichunkh->ttl = tmp_ttl;
			ofiquent->fcs = chunk_fcs;
			spin_lock(&ofi_queue_lock);
			list_add_tail(&ofiquent->list, &ofi_chunk_queue);
			spin_unlock(&ofi_queue_lock);
		break;
		case OFI_NL_DBG:
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi Netlink received msg type OFI_NL_DBG, trigger ofi xmit\n");
			#endif	
		break;
		default:
		break;
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi nl unknown message type\n");
			#endif	
	}

  	pid = nlh->nlmsg_pid;

  	skb_out = nlmsg_new(ofinlmsg->len, 0);

	if (!skb_out) {
		#ifdef OFI_DEBUG
			printk("ofi Failed to allocate new skb\n");
		#endif	
    	return;
 	} 

  	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(struct ofi_nl_msg_hdr), 0);  
  	NETLINK_CB(skb_out).dst_group = 0;
  	ofinlh = (struct ofi_nl_msg_hdr *)NLMSG_DATA(nlh);
  	ofinlh->type = OFI_NL_CTRL;
  	ofinlh->len = 0;
  	ofinlh->param = 0;
  	res = nlmsg_unicast(nl_sk, skb_out, pid);
  	#ifdef OFI_DEBUG
	  	if (res > 0) {
	    	printk(KERN_INFO "ofi Error while sending back to user\n");
	    } else {
	    	printk(KERN_INFO "ofi sending back to user\n");
	    }
	#endif    	
}

int ofi_process_queue(void* unused)
{
	int i, c, k, cc;
	int data_len = 0;
	struct list_head *pos, *q;
	struct list_head *packpos, *packq;
	struct list_head *chunkpos, *chunkq;
	struct ofi_hdr *ofih;
	struct ofi_queue_entry *ofiquent, *ofiquentcmp;
	struct ofi_transmit_packing_entry *ofixmitentry, *ofixmitcand;
	struct ofi_packing_entry *ofixmitchunk;
	unsigned char* data;
	unsigned char* offset = NULL;
	int type_l = 0;
	int type_u = 1;
	int urg_count = 0;
	bool still_process = TRUE;
	bool reset, del, chunkadded = FALSE;
	bool found_match = FALSE;
	int items = 0;

	data = (unsigned char *)kmalloc(OFI_TRANSMIT_FIFO_ENTRY_SIZE, GFP_ATOMIC);
	ofih = (struct ofi_hdr *)kmalloc(sizeof(struct ofi_hdr), GFP_ATOMIC);
	if (ofih == NULL) 
		return -ENOMEM;

		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi process start\n");
		#endif	

		spin_lock(&ofi_queue_lock);
		
		still_process = TRUE;
		urg_count = 0;
		type_l = 0;
		type_u = 1;
		items = 0;
	    while(still_process){
	    	del = FALSE;
			reset = TRUE;
			pos = NULL;
			q = NULL;
			offset = NULL;
			c = 0;
			#ifdef OFI_DEBUG
				printk(KERN_DEBUG "ofi chunk queue round interval from %i to %i\n", ofi_types[type_l], ofi_types[type_u]);
			#endif	
		    list_for_each_safe(pos, q, &ofi_chunk_queue) {
		    	ofiquent = list_entry(pos, struct ofi_queue_entry, list);
		    	/*Are we allowed to merge this?*/
			    if((ofiquent->chunkh->type >= ofi_types[type_l]) && (ofiquent->chunkh->type < ofi_types[type_u])) {
			    	spin_lock(&ofi_buffer_lock);	
			    	if(ofi_circular_transmit_buff_is_full(&ofi_circular_tb)) {
			    		spin_unlock(&ofi_buffer_lock);
			    		break;
			    	}
			    	spin_unlock(&ofi_buffer_lock);
			    	spin_lock(&ofi_transmit_list_lock);
			    	if(list_empty(&ofi_transmit_list)) {
				    	ofixmitentry = (struct ofi_transmit_packing_entry*)kzalloc(sizeof(struct ofi_transmit_packing_entry), GFP_ATOMIC);
				    	/* Reserve room for aggregated Hdr */
				    	ofixmitentry->size = OFI_HDR_LEN;
				    	INIT_LIST_HEAD(&ofixmitentry->packing);
				    	list_add_tail(&ofixmitentry->list, &ofi_transmit_list);
				    	items++;
				    }
				    chunkadded = FALSE;
				    list_for_each_entry(ofixmitcand, &ofi_transmit_list, list) {
				    	/*Is there room in this transmit item ?*/
				    	if((ofiquent->chunkh->type <= OFI_TYPE_URG) && (ofixmitcand->urg_count == OFI_URG_ELEMENTS_MAX)){
				    		/*is urgent chunk but max number for urgent chunks in this candidate exceeded*/
				    	} else {
						    if((OFI_TRANSMIT_FIFO_ENTRY_SIZE - ofixmitcand->size - ofiquent->chunkh->len - OFI_CHUNKHDR_LEN) >= 0) {
						    	ofixmitchunk = (struct ofi_packing_entry*)kzalloc(sizeof(struct ofi_packing_entry), GFP_ATOMIC);
						    	ofixmitcand->size += ofiquent->chunkh->len + OFI_CHUNKHDR_LEN;
						    	ofixmitchunk->entry = pos;
						    	list_add_tail(&ofixmitchunk->list, &ofixmitcand->packing);
						    	chunkadded = TRUE;
						    	if(ofiquent->chunkh->type <= OFI_TYPE_URG) {
						    		ofixmitcand->urg_count++;
						    	}
						    	c++;
						    	break;
						    }
						}    		
				    }
				    if(!chunkadded) {
				    	/* Chunk was not added, is there room for another transmit packing entry? 
						 * Just check if total number of items is at OFI_TRANSMIT_FIFO_MAX_ELEMS.	
				    	*/
				    	if(items < OFI_TRANSMIT_FIFO_MAX_ELEMS) {
					    	ofixmitentry = (struct ofi_transmit_packing_entry*)kzalloc(sizeof(struct ofi_transmit_packing_entry), GFP_ATOMIC);
					    	ofixmitentry->size = OFI_HDR_LEN;
					    	INIT_LIST_HEAD(&ofixmitentry->packing);
					    	list_add_tail(&ofixmitentry->list, &ofi_transmit_list);
					    	items++;
					    	ofixmitchunk = (struct ofi_packing_entry*)kzalloc(sizeof(struct ofi_packing_entry), GFP_ATOMIC);
					    	ofixmitentry->size += ofiquent->chunkh->len + OFI_CHUNKHDR_LEN;
					    	ofixmitchunk->entry = pos;
					    	list_add_tail(&ofixmitchunk->list, &ofixmitentry->packing);
					    	if(ofiquent->chunkh->type <= OFI_TYPE_URG) {
						    	ofixmitentry->urg_count++;
						    }
					    	c++;
					    } else {
					    	/* We already have all items packed up, so now iterate and check if we can remove 
							 * an item which has already been considered in order to be fair to newer chunks	
					    	 */
							list_for_each_entry(ofixmitcand, &ofi_transmit_list, list) {	
								found_match = FALSE;				
								list_for_each_safe(chunkpos, chunkq, &ofixmitcand->packing) {
									ofixmitchunk = list_entry(chunkpos, struct ofi_packing_entry, list);
									ofiquentcmp = list_entry(ofixmitchunk->entry, struct ofi_queue_entry, list);
									if(!(ofiquentcmp->chunkh->type <= OFI_TYPE_URG) && 
										((OFI_TRANSMIT_FIFO_ENTRY_SIZE - (ofixmitcand->size - ofiquentcmp->chunkh->len)) >= (ofiquent->chunkh->len)) && 
										(timercmp(&ofiquent->local_time, &ofiquentcmp->local_time, <))) {
										found_match = TRUE;
										/*Set values and pointer to the new chunk*/
										ofixmitcand->size -= ofiquentcmp->chunkh->len;
										ofixmitcand->size += ofiquent->chunkh->len;
										ofixmitchunk->entry = pos;
										break;
									}
								}
								if(found_match)
									break;
							}
					    }	
				    }		    
				    spin_unlock(&ofi_transmit_list_lock);
			    }
		    }	
			if(type_l < OFI_TYPE_COUNT - 1) {
				type_l++;
			}	
			if(type_u < OFI_TYPE_COUNT - 1)
				type_u++;
		  	if(type_l == type_u)
	    		still_process = FALSE;
	    }
	    spin_lock(&ofi_transmit_list_lock);
	    i = 0;
		list_for_each_entry(ofixmitentry, &ofi_transmit_list, list) {
			i++;
			cc = 0;
			#ifdef OFI_DEBUG
		    	printk(KERN_DEBUG "ofi chunk queue packing %i ofixmitentry size %i\n", i, ofixmitentry->size);
		    #endif	
		   	list_for_each_entry(ofixmitchunk, &ofixmitentry->packing, list) {
		   		cc++;
		   		ofiquent = list_entry(ofixmitchunk->entry, struct ofi_queue_entry, list);
		   		#ifdef OFI_DEBUG
		   			printk(KERN_DEBUG "ofi %i chunk queue fcs %x size (+hdr) %i type %i\n", cc, ofiquent->fcs, ofiquent->chunkh->len + OFI_CHUNKHDR_LEN, ofiquent->chunkh->type);
		   		#endif	
		   		do_gettimeofday(&ofiquent->local_time);
		   	}	
		}
		/*Put the packages in the circular transmit buffer*/
		list_for_each_entry(ofixmitcand, &ofi_transmit_list, list) {
			/*Prepare circular transmit buffer item*/
			if(!list_empty(&ofixmitcand->packing)) {
				#ifdef OFI_DEBUG
					printk(KERN_DEBUG "ofi transmit packing candidate size of %i\n", ofixmitcand->size);
				#endif	
				memset(data, 0, OFI_TRANSMIT_FIFO_ENTRY_SIZE);
				offset = (unsigned char*)data;
				memset(ofih->bloom, 0, OFI_BLOOM_LEN);
				ofih->len = 0; 
				data_len = OFI_HDR_LEN;
				offset = offset + OFI_HDR_LEN;
				/*Add chunks to transmit buffer item*/
				del = FALSE;
				list_for_each_safe(chunkpos, chunkq, &ofixmitcand->packing) {
					/*To delete chunk during iteration, if its rtx is <= 1*/
					if(del) {
						list_del(ofixmitchunk->entry);
						#ifdef OFI_DEBUG
							printk(KERN_DEBUG "ofi packing chunk with csum %x deleted\n", ofiquent->fcs);
						#endif	
						kfree(ofiquent);
						del = FALSE;
					}
					ofixmitchunk = list_entry(chunkpos, struct ofi_packing_entry, list);
					ofiquent = list_entry(ofixmitchunk->entry, struct ofi_queue_entry, list);
					for(k=0; k<OFI_BLOOM_LEN; k++) {
						ofih->bloom[k] |= ofiquent->chunkh->bloom[k];
					}
					ofih->len += OFI_CHUNKHDR_LEN + ofiquent->chunkh->len;;  
					memcpy(offset, ofiquent->chunkh, OFI_CHUNKHDR_LEN);
					memcpy(offset + OFI_CHUNKHDR_LEN, ofiquent->data, ofiquent->chunkh->len);
					do_gettimeofday(&ofiquent->local_time);
					data_len += ofiquent->chunkh->len + OFI_CHUNKHDR_LEN;  
					offset = offset + OFI_CHUNKHDR_LEN + ofiquent->chunkh->len;
					if(ofiquent->local_rtx > 1) {
						/*Chunk needs to be re-send later on*/
						#ifdef OFI_DEBUG
							printk(KERN_DEBUG "ofi packing chunk rtx was %i\n", ofiquent->local_rtx);
						#endif	
						ofiquent->local_rtx -= 1;
						/*Set new last touched time for this chunk*/
						#ifdef OFI_DEBUG
							printk(KERN_DEBUG "ofi packing chunk rtx is now %i\n", ofiquent->local_rtx);
						#endif	
					} else if(ofiquent->local_rtx <= 1) {
						/*Last re-send for this chunk*/
						#ifdef OFI_DEBUG
							printk(KERN_DEBUG "ofi packing chunk last rtx, is now %i\n", ofiquent->local_rtx);
						#endif	
						del = TRUE;
					}

				}
				/*To delete the last remaining chunk, if its rtx is <= 1*/
				if(del) {
					list_del(ofixmitchunk->entry);
					#ifdef OFI_DEBUG
						printk(KERN_DEBUG "ofi packing chunk with csum %x deleted\n", ofiquent->fcs);
					#endif	
					kfree(ofiquent);
					del = FALSE;
				}
				memcpy(data, ofih, OFI_HDR_LEN); 
				spin_lock(&ofi_buffer_lock);
				ofi_circular_transmit_buff_write(&ofi_circular_tb, data, data_len);
				spin_unlock(&ofi_buffer_lock);
			}		
		}
		/* Delete packing list */
		list_for_each_safe(packpos, packq, &ofi_transmit_list) {
			ofixmitentry = list_entry(packpos, struct ofi_transmit_packing_entry, list);
			list_del(packpos);
  			kfree(ofixmitentry);
		}
	spin_unlock(&ofi_transmit_list_lock);
	spin_unlock(&ofi_queue_lock);
	spin_lock(&ofi_work_process_signal_lock);
	ofi_work_process = FALSE;
	spin_unlock(&ofi_work_process_signal_lock);
	#ifdef OFI_DEBUG
	  	printk(KERN_DEBUG "ofi packing wake up transmit\n");
	#endif	
	wake_up_interruptible(&ofi_wait_queue);  
	kfree(ofih);
	kfree(data);
	return 0;
}

static void ofi_timeout(unsigned long arg)
{
	spin_lock(&ofi_work_process_signal_lock);
	ofi_work_process = TRUE;
	spin_unlock(&ofi_work_process_signal_lock);
	ofi_process_queue(NULL);
	if(!ofi_stop_task) {
		ofi_timer.expires =	 jiffies + HZ/OFI_QUEUE_CHECK_FREQ;
		add_timer(&ofi_timer);
	}	
}

void ofi_register_timer(void)
{
	printk(KERN_DEBUG "ofi register timer\n");
	init_timer(&ofi_timer);
	add_timer(&ofi_timer);
}

int ofi_init(void)
{
 	/*Init the queue timer*/
	ofi_timer.expires = jiffies + HZ/OFI_QUEUE_CHECK_FREQ;
	ofi_timer.data = (unsigned long)NULL;
	ofi_timer.function = &ofi_timeout;

	/*Setup netlink socket to communicat with user space*/
  	nl_sk = netlink_kernel_create(&init_net, OFI_NETLINK_MSG, 0, ofi_comm_input, NULL, THIS_MODULE);

  	if (!nl_sk) {
    	printk(KERN_ALERT "ofi Error creating socket.\n");
    	return -ENOMEM;
  	}
	printk(KERN_ALERT "ofi init HZ %i.\n", HZ);
  	/*Init spinlock for queue access*/
  	spin_lock_init(&ofi_queue_lock);
  	spin_lock_init(&ofi_seen_lock);
  	spin_lock_init(&ofi_subscription_lock);
	spin_lock_init(&ofi_transmit_lock);
	spin_lock_init(&ofi_buffer_lock);
	spin_lock_init(&ofi_work_process_signal_lock);
	spin_lock_init(&ofi_transmit_list_lock);

	mutex_init(&ofi_queue_mutex);
	mutex_init(&ofi_seen_mutex);
	mutex_init(&ofi_subscription_mutex);
	mutex_init(&ofi_transmit_mutex);
	mutex_init(&ofi_buffer_mutex);
	mutex_init(&ofi_transmit_list_mutex);

  	/*Init circular transmit buff*/
	ofi_circular_transmit_buff_init(&ofi_circular_tb, OFI_TRANSMIT_FIFO_MAX_ELEMS);

  	/*Init queue*/
  	init_waitqueue_head(&ofi_wait_queue);
  	init_waitqueue_head(&ofi_proc_queue);

	ofi_tr_task = kthread_run(&ofi_transmit_task, NULL, "ofi_transmit_task");
	ofi_register_timer();
	printk(KERN_DEBUG "ofi init done\n");

  	return 0;
}
EXPORT_SYMBOL(ofi_init);

void ofi_clean(void)
{
	int ret;
	struct ofi_queue_entry *ofiquent;
	struct ofi_subscription_entry *ofisubent;
	struct list_head *pos, *q;

  	/*Stop and unregister kernel timer*/
	del_timer_sync(&ofi_timer);

	/*Release the reserved netlink socket*/
	printk(KERN_INFO "ofi: communication breakdown\n");
  	netlink_kernel_release(nl_sk);

  	/*Clean and free the ofi chunk list*/

  	spin_lock(&ofi_queue_lock);
  	list_for_each_safe(pos, q, &ofi_chunk_queue) {
    	ofiquent = list_entry(pos, struct ofi_queue_entry, list);
  		list_del(pos);
  		kfree(ofiquent);
  	}
  	spin_unlock(&ofi_queue_lock);

  	spin_lock(&ofi_subscription_lock);
  	list_for_each_safe(pos, q, &ofi_subscribed_ids) {
    	ofisubent = list_entry(pos, struct ofi_subscription_entry, list);
  		list_del(pos);
  		kfree(ofisubent);
  	}
  	spin_unlock(&ofi_subscription_lock);

	spin_lock(&ofi_buffer_lock);
	ofi_circular_transmit_buff_free(&ofi_circular_tb);
  	spin_unlock(&ofi_buffer_lock);

	printk(KERN_INFO "ofi: end of cleaning data structures\n");

	ofi_stop_task = TRUE;
	ofi_stop_proc_task = TRUE;
	
	ret = kthread_stop(ofi_tr_task);
	printk(KERN_INFO "ofi: kthread_stop %i\n", ret);

	wake_up_interruptible(&ofi_wait_queue);
	wake_up_interruptible(&ofi_proc_queue);
	printk(KERN_INFO "ofi: wake up call in ofi clean\n");
}
EXPORT_SYMBOL(ofi_clean);

void ofi_add_own_chunks_seen(struct ofi_seen_entry *new)
{
	struct list_head *pos, *q;
	struct list_head *store = NULL;
	struct ofi_seen_entry *ofiseen = NULL;
	int i = 0;

	spin_lock(&ofi_seen_lock);
	if(ofi_fcs_count < OFI_OWN_FCS_ITEMS_MAX) {
		list_add_tail(&new->list, &ofi_chunks_seen);
		ofi_fcs_count++;
	} else {
		/*
		 *	iterate to get oldest element, which is currently the first
		 *	to delete it in fifo style and make room for new ones.
		 */
		list_for_each_safe(pos, q, &ofi_chunks_seen) {
			ofiseen = list_entry(pos, struct ofi_seen_entry, list);
			store = pos;
			i++;
			/* Break after first element */
			break;
		}
		list_del(store);
		kfree(ofiseen);
		ofi_fcs_count--;
		list_add_tail(&new->list, &ofi_chunks_seen);
		ofi_fcs_count++;
	}	
	spin_unlock(&ofi_seen_lock);
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi ofi_fcs_count %i\n", ofi_fcs_count);
	#endif
}

int ofi_has_seen_own_chunk(int fcs)
{
	struct list_head *pos, *q;
	struct ofi_seen_entry *ofiseen;

	spin_lock(&ofi_seen_lock);
	list_for_each_safe(pos, q, &ofi_chunks_seen) {
	    ofiseen = list_entry(pos, struct ofi_seen_entry, list);
	    #ifdef OFI_DEBUG
	    	printk(KERN_DEBUG "ofi list ofi_has_seen_own_chunk current csum %x and ofiseen->fcs %x\n", fcs, ofiseen->fcs);
	    #endif	
	    if(ofiseen->fcs == fcs) {
	    	spin_unlock(&ofi_seen_lock);
	    	#ifdef OFI_DEBUG
	    		printk(KERN_DEBUG "ofi list ofi_has_seen_own_chunk csum %x\n", fcs);
	    	#endif	
	    	return 1;
	    }
	}
	spin_unlock(&ofi_seen_lock);
	
	return 0;
}

int ofi_already_has_forward_chunk(int fcs)
{	
	struct list_head *pos, *q;
	struct ofi_queue_entry *ofiquent;

	spin_lock(&ofi_queue_lock);
	list_for_each_safe(pos, q, &ofi_chunk_queue) {
	    ofiquent = list_entry(pos, struct ofi_queue_entry, list);
	    if(ofiquent->fcs == fcs) {
	    	#ifdef OFI_DEBUG
	    		printk(KERN_DEBUG "ofi chunk csum %x of chunk with len %i already in forward\n", ofiquent->fcs, ofiquent->chunkh->len);
	    	#endif		
	    	spin_unlock(&ofi_queue_lock);
	    	return 1;
	    }
	}
	spin_unlock(&ofi_queue_lock);
	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi chunk csum %x of chunk _not_ in forward\n", fcs);
	#endif	
	return 0;
}

void ofi_msg_handler(struct ieee80211_rx_data *rx)
{
	int k,c,res, i;
	int prev_chunk_frame, prev_chunk_nl, len, offset, nl_offset;
	u8 tmp_ttl;
	struct ofi_hdr *ofih = (struct ofi_hdr *)(rx->skb->data + OFFSET_TO_OFI);
	struct ofi_chunk_hdr *ofichunkh = (struct ofi_chunk_hdr *)(rx->skb->data + OFFSET_TO_OFI + OFI_HDR_LEN);
	struct ofi_queue_entry *ofiquent;
	struct ofi_nl_msg_hdr *ofinlh = NULL;
	struct sk_buff* skb_out = NULL;
	struct nlmsghdr* nlh = NULL;
	unsigned long chunk_fcs = 0;
	struct ofi_seen_entry *ofiseen = NULL;
	bool ofi_nl_has_data = FALSE;
	unsigned char *d;

	#ifdef OFI_DEBUG
		printk(KERN_DEBUG "ofi: call to msg_handler!\n");
	#endif	

	if(rx->skb->len < OFI_FRAME_SIZE_MIN || rx->skb->len > OFI_FRAME_SIZE_MAX){
		return;
	}

	k = 0;
	c = 0;
	len = ofih->len;
	prev_chunk_frame = 0;
	prev_chunk_nl = 0;
	offset = 0;
	nl_offset = sizeof(struct ofi_nl_msg_hdr);
	while(len > 0) {
		#ifdef OFI_DEBUG
			printk(KERN_DEBUG "ofi check for id %s\n", ofichunkh->bloom);
		#endif	

		/*intermediate storage of ttl in order to set ttl to zero for fcs calculation*/
		tmp_ttl = ofichunkh->ttl;
		ofichunkh->ttl = 0;
		chunk_fcs = crc32_le(~0, (unsigned char*)ofichunkh, OFI_CHUNKHDR_LEN + ofichunkh->len);
		/*re-set ttl*/
		ofichunkh->ttl = tmp_ttl;

		if (ofi_check_subscription(ofichunkh->bloom)) {
			//#ifdef OFI_DEBUG
				printk(KERN_INFO "ofi chunk for me!\n");
			//#endif	
			if(!ofi_has_seen_own_chunk(chunk_fcs)) {
				printk(KERN_INFO "ofi chunk not seen!\n");
				if(skb_out == NULL){
						skb_out = nlmsg_new(ofih->len, GFP_ATOMIC);
						if(!skb_out){
							#ifdef OFI_DEBUG
								printk(KERN_INFO "ofi: couldn't allocate skbuff!\n");
							#endif	
							break;
						}
						
						nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, ofih->len + sizeof(struct ofi_nl_msg_hdr), 0);  
					  	NETLINK_CB(skb_out).dst_group = 0;
					  	ofinlh = (struct ofi_nl_msg_hdr *)NLMSG_DATA(nlh);
					  	ofinlh->type = OFI_NL_DATA;
					  	ofinlh->len = 0;
					  	ofinlh->param = 0;

					  	if(!nlh){
					  		#ifdef OFI_DEBUG
								printk(KERN_INFO "ofi: couldn't allocate nlh!\n");
							#endif	
							break;
						}
				}
				ofiseen = (struct ofi_seen_entry *) kmalloc(sizeof(struct ofi_seen_entry), GFP_ATOMIC);
				memcpy(NLMSG_DATA(nlh) + nl_offset, ofichunkh, ofichunkh->len + OFI_CHUNKHDR_LEN);
				d = (unsigned char *)(NLMSG_DATA(nlh) + nl_offset);
				#ifdef OFI_DEBUG
					for(i=0; i < ofichunkh->len + OFI_CHUNKHDR_LEN; i++){
						printk(KERN_INFO "ofi: now in netlink to user data[%i] = %x!\n", i, d[i]);
					}
				#endif	
				prev_chunk_nl = ofichunkh->len;
				ofinlh->len += OFI_CHUNKHDR_LEN + ofichunkh->len; 
				nl_offset = nl_offset + OFI_CHUNKHDR_LEN + prev_chunk_nl;
				ofiseen->fcs = chunk_fcs;
				ofi_add_own_chunks_seen(ofiseen);
				ofi_nl_has_data = TRUE;
			}
		} else {
			printk(KERN_INFO "ofi chunk _not_ for me!\n");
			if(!ofi_already_has_forward_chunk(chunk_fcs)) {
				if(ofichunkh->ttl > 0) {
					#ifdef OFI_DEBUG
						printk(KERN_DEBUG "ofi ttl %i\n", ofichunkh->ttl);
						chunkcount++;
					#endif	
					ofiquent = (struct ofi_queue_entry *) kmalloc(sizeof(struct ofi_queue_entry), GFP_ATOMIC);
					ofiquent->chunkh = (struct ofi_chunk_hdr *) kmalloc(sizeof(struct ofi_chunk_hdr), GFP_ATOMIC);
					ofiquent->data = (unsigned char *) kmalloc(ofichunkh->len, GFP_ATOMIC);
					ofichunkh->ttl -= 1;
					memcpy(ofiquent->chunkh, ofichunkh, OFI_CHUNKHDR_LEN);
					memcpy(ofiquent->data, (unsigned char *)ofichunkh + OFI_CHUNKHDR_LEN, ofichunkh->len);
					ofiquent->local_rtx = ofichunkh->rtx;
					ofiquent->fcs = chunk_fcs;
					do_gettimeofday(&ofiquent->local_time);
					spin_lock(&ofi_queue_lock);
					list_add_tail(&ofiquent->list, &ofi_chunk_queue);
					spin_unlock(&ofi_queue_lock);
				}
			}		
		}
		prev_chunk_frame = ofichunkh->len;
		len = len - OFI_CHUNKHDR_LEN - prev_chunk_frame;
		ofichunkh = (struct ofi_chunk_hdr *)((unsigned char*)rx->skb->data + OFFSET_TO_OFI + OFI_HDR_LEN + (ofih->len - len));
	}

	if(!ofi_pid) {
		return;
	}
	if(ofi_nl_has_data){
	  	res = nlmsg_unicast(nl_sk, skb_out, ofi_pid);
	  	#ifdef OFI_DEBUG
		  	if(res) {
		  		printk(KERN_INFO "ofi: nlmsg_unicast err!\n");
		  	}
		  	printk(KERN_INFO "ofi: nlmsg_unicast send!\n");
		#endif	
	} 	
}
EXPORT_SYMBOL(ofi_msg_handler);
