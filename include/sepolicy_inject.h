#ifndef SEPOLICY_INJECT_H
#define SEPOLICY_INJECT_H

void* sepolicy_inject_open(const char *policy);
int sepolicy_inject_write(void *handle, const char *outfile);
int sepolicy_inject_close(void *handle);
int sepolicy_inject_add_rule(void *handle, const char *source, const char *target, const char *class, const char *perm);
int sepolicy_inject_set_permissive(void *handle, const char *source, int value);

#endif // SEPOLICY_INJECT_H
