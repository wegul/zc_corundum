#ifndef DEBUG_H
#define DEBUG_H

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <net/netmem.h>


static void print_pg(struct page* page, int length) {
    char* pg_chars = (char*)page_address(page);
    // pr_cont("Data in page %lx, len= %d: \n", page_address(page), length);
    for (int i = 0; i < length; i++) {
        char c = pg_chars[i];
        pr_cont("%02x,", (unsigned int)c);
    }
    pr_cont("\n");
};
static void print_net(netmem_ref page, int length) {
    char* pg_chars = (char*)page_address(netmem_to_page(page));
    // pr_cont("Data in page %lx, len= %d: \n", page_address(netmem_to_page(page)), length);
    // pr_cont("\"");
    // for (int i = 0; i < length; i++) {
    //     char c = pg_chars[i];
    //     if (isprint(c)) {
    //         pr_cont("%c", c);
    //     }
    //     else {
    //         pr_cont(".");
    //     }
    // }
    // pr_cont("\"\n");
    pr_cont("\"");
    for (int i = 0; i < length; i++) {
        char c = pg_chars[i];
        pr_cont("%02x,", (unsigned int)c);
    }
    pr_cont("\"\n");

};


#endif