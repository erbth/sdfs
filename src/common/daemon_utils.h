#ifndef __DAEMON_UTILS_H
#define __DAEMON_UTILS_H

/* Utility functions for use in daemons */

#include <string>

/* To avoid pulling in entire libsystemd as dependency, but still support
 * startup notifications for systemd, a simple sd_notify replacement is
 * implemented here.
 *
 * If the $NOTIFY_SOCKET environment variable is unset, simply does nothing. */
void sdfs_systemd_notify(const std::string& msg);
void sdfs_systemd_notify_ready();

#endif /* __DAEMON_UTILS_H */
