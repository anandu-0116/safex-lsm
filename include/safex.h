#ifndef SAFEX_H
#define SAFEX_H

#define MAX_PATH_LEN 512
#define DENYLIST_PATH "/etc/safex.denylist"
#define MAX_LOAD_ATTEMPTS 12 

bool is_path_denied(const char *path);
int load_denylist(void);
void cleanup_denylist(void);

#endif