#ifndef PRIVATE_H
#define PRIVATE_H

typedef struct {
    void* (*open)(const char *policy);
    int (*write)(void *handle, const char *outfile);
    int (*close)(void *handle);
    int (*add_rule)(void *handle, const char *source, const char *target, const char *class, const char *perm);
    int (*set_permissive)(void *handle, const char *source, int value);
} sepolicy_if_t;

typedef struct {
    void *pdata;
    sepolicy_if_t *interface;
} handle_t;

extern sepolicy_if_t interface_selinux6;
extern sepolicy_if_t interface_selinux7;

#endif // PRIVATE_H
