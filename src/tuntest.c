/*
 * tuntest.c
 *
 *  Created on: Jan 27, 2016
 *      Author: grutz
 */

#include <linux/if_tun.h>
#include <linux/types.h>
#include <sys/ioctl.h>

#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>

#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define BUFSIZE 2048
#define TUN_DEV_NAME "tun0"

static uint8_t tunnel_configured = 0;

static int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    // Attempt to open the clone device
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("ERROR Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    ifr.ifr_flags = IFF_TUN;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ERROR Opening TUN:");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

static int configure_tunnel(int if_index, struct nl_sock *msgsock) {

    struct nl_msg *outmsg = NULL;
    struct nl_addr *addr_local = NULL, *addr_brcst = NULL;

    struct rtnl_addr *rtaddr = rtnl_addr_alloc();
    rtnl_addr_set_ifindex(rtaddr, if_index);
    rtnl_addr_set_prefixlen(rtaddr, 24);

    // Local Address
    if (nl_addr_parse("10.10.0.100", AF_INET, &addr_local) < 0) {
        perror("ERROR Creating local address");
        goto done;
    }
    rtnl_addr_set_local(rtaddr, addr_local);

    // Broadcast address
    if (nl_addr_parse("10.10.0.255", AF_INET, &addr_brcst) < 0) {
        perror("ERROR Creating broadcast address");
        goto done;
    }
    rtnl_addr_set_broadcast(rtaddr, addr_brcst);

    // Send the message and cleanup
    rtnl_addr_add(msgsock, rtaddr, 0);
    nl_addr_put(addr_local);
    addr_local = NULL;
    nl_addr_put(addr_brcst);
    addr_brcst = NULL;

    // Update the interface link state to UP
    outmsg = nlmsg_alloc_simple(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    struct ifinfomsg ifm = {
        .ifi_index = if_index,
        .ifi_flags = IFF_UP,
        .ifi_change = IFF_UP,
    };
    if (nlmsg_append(outmsg, &ifm, sizeof(ifm), NLMSG_ALIGNTO) < 0) {
        perror("ERROR "
                "Appending ifinfomsg");
        goto done;
    }
    if (nl_send_auto(msgsock, outmsg) < 0) {
        perror("ERROR Sending message");
        goto done;
    }
    nlmsg_free(outmsg);
    outmsg = NULL;
    tunnel_configured = 1;

  done:
    if (outmsg) {
        nlmsg_free(outmsg);
    }
    if (addr_local) {
        nl_addr_put(addr_local);
    }
    if (addr_brcst) {
        nl_addr_put(addr_brcst);
    }

    return 0;
}

static void route_iterator(struct nl_object *obj, void *arg) {
    struct rtnl_route *route = (struct rtnl_route*)obj;
    const int sz = 128;
    char strbuf[sz];

    if (rtnl_route_get_family(route) == AF_INET) {
	    printf("------------ ROUTE START -------------\n");

	    printf("SRC_ADDR: %s\n", nl_addr2str(rtnl_route_get_src(route), strbuf, sz));
	    printf("DST_ADDR: %s\n", nl_addr2str(rtnl_route_get_dst(route), strbuf, sz));
	    printf("TYPE: %d\n", rtnl_route_get_type(route));

	    printf("------------ ROUTE END -------------\n");
	    printf("\n");
    }
}

static void link_iterator(struct nl_object *obj, void *arg) {
    struct rtnl_link *link = (struct rtnl_link*)obj;
    if (!strcmp(rtnl_link_get_name(link), TUN_DEV_NAME))
    {
        printf("Found tunnel device!  name = %s, index = %d\n", rtnl_link_get_name(link), rtnl_link_get_ifindex(link));
        *((int*)arg) = rtnl_link_get_ifindex(link);
    }
}

static int get_tun_link_index(struct nl_sock *sock) {
    struct nl_cache *links;

    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &links) < 0) {
        perror("ERROR Retrieving links");
        return -1;
    }

    printf("Number of links = %d\n", nl_cache_nitems(links));

    int index = -1;
    nl_cache_foreach(links, link_iterator, &index);

    nl_cache_free(links);

    return index;
}

static int get_routes(struct nl_sock *sock) {
    struct nl_cache *routes;

    if (rtnl_route_alloc_cache(sock, AF_INET, 0, &routes) < 0) {
        perror("ERROR Retrieving routes");
        return -1;
    }

    printf("Number of routes = %d\n", nl_cache_nitems(routes));

    nl_cache_foreach(routes, route_iterator, NULL);

    nl_cache_free(routes);

    return 0;
}

static int link_notification_cb(struct nl_msg *msg, void *arg) {

    struct nl_sock *msgsock = (struct nl_sock*)arg;
    struct nlmsghdr* msghdr = nlmsg_hdr(msg);
    struct ifinfomsg *ifmsghdr = nlmsg_data(msghdr);
    struct nlattr *attr = nlmsg_attrdata(msghdr, sizeof(struct ifinfomsg));
    switch (msghdr->nlmsg_type) {
    case RTM_NEWLINK:
    {
        printf("Received RTM_NEWLINK msg\n");
        if (!tunnel_configured) {
            printf("Configuring tunnel...\n");
            struct nlattr *name_attr = nla_find(attr, nlmsg_attrlen(msghdr, 0), IFLA_IFNAME);
            if (name_attr && strcmp(TUN_DEV_NAME, nla_get_string(name_attr)) == 0) {
                printf("This is our 'tun0' tunnel!  Interface index = %d\n", ifmsghdr->ifi_index);

                if (configure_tunnel(ifmsghdr->ifi_index, msgsock) < 0) {
                    perror("ERROR Setting tunnel address and state");
                }
            }
        }
        break;
    }
    case RTM_DELLINK:
        printf("Received RTM_DELLINK msg\n");
        break;
    case RTM_GETLINK:
        printf("Received RTM_GETLINK msg\n");
        break;
    case RTM_SETLINK:
        printf("Received RTM_SETLINK msg\n");
        break;
    default:
        printf("Got unexpeted msg type -- %d\n", msghdr->nlmsg_type);
        return 0;
    }

    char buf[128];
    printf("Flags = %s\n", rtnl_link_flags2str(ifmsghdr->ifi_flags, buf, sizeof(buf)));

    int remaining = nlmsg_attrlen(msghdr, 0);

    while (nla_ok(attr, remaining)) {
        attr = nla_next(attr, &remaining);
        printf("ATTR TYPE = %d\n", nla_type(attr));
    }
    return 0;
}

static int genl_response_cb(struct nl_msg *msg, void *arg) {

    struct nl_sock *genlsock = (struct nl_sock*)arg;
    struct nlmsghdr* msghdr = nlmsg_hdr(msg);
}

static int link_response_cb(struct nl_msg *msg, void *arg) {

    struct nlmsghdr* msghdr = nlmsg_hdr(msg);
    if (msghdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *errhdr = (struct nlmsgerr*)nlmsg_data(msghdr);
        if (errhdr->error != 0) {
            perror("ERROR Error in response CB");
        } else {
            printf("ACK!");
        }
    }
    return 0;
}

static void* recv_msg_func(void* arg) {

    struct nl_sock *sock = (struct nl_sock *)arg;

    while (1) {
        nl_recvmsgs_default(sock);
    }

    return NULL;
}

int main(int argc, char** argv) {

    // Allocate socket
    struct nl_sock *notification_sock;
    struct nl_sock *genl_sock;
    struct nl_sock *route_sock;
    if ((notification_sock = nl_socket_alloc()) == NULL) {
        perror("ERROR Allocating notification socket");
        return -1;
    }
    if ((route_sock = nl_socket_alloc()) == NULL) {
        perror("ERROR Allocating response socket");
        return -1;
    }

    // Disable sequence numbers for notification sockets
    nl_socket_disable_seq_check(notification_sock);

    // Set our callback function on the socket
    if (nl_socket_modify_cb(notification_sock, NL_CB_VALID, NL_CB_CUSTOM, link_notification_cb, (void*)route_sock) != 0) {
        perror("ERROR Setting notification callback function");
        return -1;
    }
    if (nl_socket_modify_cb(route_sock, NL_CB_VALID, NL_CB_CUSTOM, link_response_cb, NULL) != 0) {
        perror("ERROR Setting response callback function");
        return -1;
    }
    if (nl_socket_modify_cb(genl_sock, NL_CB_VALID, NL_CB_CUSTOM, genl_response_cb, NULL) != 0) {
        perror("ERROR Setting response callback function");
        return -1;
    }

    // Connect to the routing protocol
    if (nl_connect(notification_sock, NETLINK_ROUTE) != 0) {
        perror("ERROR Connecting to NETLINK_ROUTE protocol");
        return -1;
    }
    if (nl_connect(route_sock, NETLINK_ROUTE) != 0) {
        perror("ERROR Connecting to NETLINK_ROUTE protocol");
        return -1;
    }
    if (nl_connect(genl_sock, NETLINK_GENERIC) != 0) {
        perror("ERROR Connecting to NETLINK_ROUTE protocol");
        return -1;
    }

    int gen80211id;
    if ((gen80211id = genl_ctrl_resolve(genl_sock,  "nl80211")) < 0) {
        perror("ERROR resolving 'nl80211' family ID");
        return -1; 
    }

    // Subscribe to LINK notifications
    if (nl_socket_add_memberships(notification_sock, RTNLGRP_LINK, 0) != 0) {
        perror("ERROR Subscribing to LINK notifications");
        return -1;
    }

    // Spawn a thread to receive messages
    pthread_t notification_thread;
    if (pthread_create(&notification_thread, NULL, recv_msg_func, (void*)notification_sock) != 0) {
        perror("ERROR Creating notification message thread");
    }

    char devname[IFNAMSIZ];
    strncpy(devname, "tun0", IFNAMSIZ);
    int tunfd;
    if ((tunfd = tun_alloc(devname)) < 0) {
        return -1;
    }

    int tun_idx = get_tun_link_index(route_sock);
    if (tun_idx == -1) {
        perror("Could not find our tun device!");
        exit(1);
    }
    // Can only do this as root
    //configure_tunnel(tun_idx, message_sock);

    //get_routes(message_sock);

    /*
    if (pthread_join(response_thread, &retval) != 0) {
        perror("ERROR Joining response message thread");
    }
    */

    uint8_t buf[BUFSIZE];
    while (1) {
        int ret;

        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(tunfd, &readset);

        ret = select(tunfd + 1, &readset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno = EINTR)
                continue;
            else 
                perror("Error in select()");
        }

        if (FD_ISSET(tunfd, &readset)) {
          int numread = read(tunfd, buf, BUFSIZE);
          printf("Numread = %d\n", numread);
        }
    }

    // Join the recv message thread before exiting
    void* retval;
    if (pthread_join(notification_thread, &retval) != 0) {
        perror("ERROR Joining notification message thread");
    }

    return 0;
}
