#ifndef AEGIS_H
#define AEGIS_H

// Aegis Privacy Agent API

int aegis_init(void);
int aegis_monitor_ipc(const char *from, const char *to, const void *data, size_t size);
int aegis_get_trust_score(const char *app_id);

#endif // AEGIS_H
