#ifndef DEBUG_H
#define DEBUG_H

#include <linux/kernel.h>
#include<linux/mm.h>
#include <linux/ctype.h>


static void print_pg(struct page* page, int length) {
    char* pg_chars = (char*)page_address(page);
    pr_cont("Data in page %lx, len= %d: \n", page_address(page), length);
    for (int i = 0; i < length+256; i++) {
        char c = pg_chars[i];
        if (isprint(c) && c != '\n') {
            pr_cont("%c", c, (unsigned char)c);
        }
        else {
            pr_cont(".");
        }
    }
    pr_cont("\n");
    for (int i = 0; i < length+256; i++) {
        char c = pg_chars[i];
        pr_cont("%02x,", (unsigned int)c);
    }
};


#endif