#ifndef SEPOLICY_INJECT_H
#define SEPOLICY_INJECT_H

int sepolicy_inject_rule(const char *source, const char *target, const char *class, const char *perm, const char *policy, const char *outfile);
int sepolicy_set_permissive(const char *source, int value, const char *policy, const char *outfile);

#endif // SEPOLICY_INJECT_H
