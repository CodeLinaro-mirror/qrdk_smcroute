/* SMCRoute script API */
#ifndef SMCROUTE_SCRIPT_H_
#define SMCROUTE_SCRIPT_H_

#include "mroute.h"

int script_init  (char *script);
int script_exec  (struct mroute *mroute);
int script_member(const char *action, const char *ifname, inet_addr_t *group);

#endif /* SMCROUTE_SCRIPT_H_ */
