#ifndef PRIVATE_H
#define PRIVATE_H

#define SEL_ADD_RULE 1
#define SEL_PERMISSIVE 2

typedef struct {
	// common
	const char *policy;
	const char *outfile;
	const char *source;
	int selected;

	// SEL_ADD_RULE
	const char *target;
	const char *class;
	char *perm;

	// SEL_PERMISSIVE
	int permissive_value;
} context_t;

int sepolicy_inject_internal_run_action(context_t *context);

#endif // PRIVATE_H
