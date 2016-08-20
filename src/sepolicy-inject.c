/*
 * This was derived from public domain works with updates to
 * work with more modern SELinux libraries.
 *
 * It is released into the public domain.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sepol/debug.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include <sepol/policydb/link.h>
#include <sepol/policydb/services.h>
#include <sepol/policydb/avrule_block.h>
#include <sepol/policydb/conditional.h>

#include "private.h"
#include "tokenize.h"

static void *cmalloc(size_t s)
{
	void *t = malloc(s);
	if (t == NULL) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	return t;
}

static void set_attr(const char *type, policydb_t *policy, int value)
{
	type_datum_t *attr = hashtab_search(policy->p_types.table, (const hashtab_key_t)type);
	if (!attr) {
		fprintf(stderr, "%s not present in the policy\n", type);
		exit(1);
	}

	if (attr->flavor != TYPE_ATTRIB) {
		fprintf(stderr, "%s is not an attribute\n", type);
		exit(1);
	}

	if (ebitmap_set_bit(&attr->types, value - 1, 1)) {
		fprintf(stderr, "error setting attibute: %s\n", type);
		exit(1);
	}
}

static int create_domain(const char *d, policydb_t *policy)
{
	symtab_datum_t *src = hashtab_search(policy->p_types.table, (const hashtab_key_t)d);
	if (src)
		return src->value;

	type_datum_t *typdatum = (type_datum_t *) cmalloc(sizeof(type_datum_t));
	type_datum_init(typdatum);
	typdatum->primary = 1;
	typdatum->flavor = TYPE_TYPE;

	uint32_t value = 0;
	char *type = strdup(d);
	if (type == NULL)  {
		exit(1);
	}
	int r = symtab_insert(policy, SYM_TYPES, type, typdatum, SCOPE_DECL, 1, &value);
	if (r) {
		fprintf(stderr, "Failed to insert type into symtab\n");
		exit(1);
	}
	typdatum->s.value = value;

	if (ebitmap_set_bit(&policy->global->branch_list->declared.scope[SYM_TYPES], value - 1, 1)) {
		exit(1);
	}

	policy->type_attr_map = realloc(policy->type_attr_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	policy->attr_type_map = realloc(policy->attr_type_map, sizeof(ebitmap_t)*policy->p_types.nprim);
	ebitmap_init(&policy->type_attr_map[value-1]);
	ebitmap_init(&policy->attr_type_map[value-1]);
	ebitmap_set_bit(&policy->type_attr_map[value-1], value-1, 1);

	//Add the domain to all roles
	for (unsigned i=0; i<policy->p_roles.nprim; ++i) {
		//Not sure all those three calls are needed
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.negset, value-1, 0);
		ebitmap_set_bit(&policy->role_val_to_struct[i]->types.types, value-1, 1);
		type_set_expand(&policy->role_val_to_struct[i]->types, &policy->role_val_to_struct[i]->cache, policy, 0);
	}

	src = hashtab_search(policy->p_types.table, (const hashtab_key_t)d);
	if (!src) {
		fprintf(stderr, "creating %s failed\n",d);
		exit(1);
	}

	extern int policydb_index_decls(policydb_t *p);
	if (policydb_index_decls(policy)) {
		exit(1);
	}

	set_attr("domain", policy, value);
	return value;
}

static int add_rule(const char *s, const char *t, const char *c, char **p, policydb_t *policy)
{
	type_datum_t *src, *tgt;
	class_datum_t *cls;
	perm_datum_t *perm;
	avtab_datum_t *av;
	avtab_key_t key;

	src = hashtab_search(policy->p_types.table, (const hashtab_key_t)s);
	if (src == NULL) {
		fprintf(stderr, "source type %s does not exist\n", s);
		return 1;
	}
	tgt = hashtab_search(policy->p_types.table, (const hashtab_key_t)t);
	if (tgt == NULL) {
		fprintf(stderr, "target type %s does not exist\n", t);
		return 1;
	}
	cls = hashtab_search(policy->p_classes.table, (const hashtab_key_t)c);
	if (cls == NULL) {
		fprintf(stderr, "class %s does not exist\n", c);
		return 1;
	}

	uint32_t data = 0;

	int i = 0;
	while (p[i]) {
		perm = hashtab_search(cls->permissions.table, p[i]);
		if (perm == NULL) {
			if (cls->comdatum == NULL) {
				fprintf(stderr, "perm %s does not exist in class %s\n", p[i], c);
				return 1;
			}
			perm = hashtab_search(cls->comdatum->permissions.table, p[i]);
			if (perm == NULL) {
				fprintf(stderr, "perm %s does not exist in class %s\n", p[i], c);
				return 1;
			}
		}
		data |= 1U << (perm->s.value - 1);
		i++;
	}

	// See if there is already a rule
	key.source_type = src->s.value;
	key.target_type = tgt->s.value;
	key.target_class = cls->s.value;
	key.specified = AVTAB_ALLOWED;
	av = avtab_search(&policy->te_avtab, &key);

	if (av == NULL) {
		av = cmalloc(sizeof av);
		av->data = data;
		int ret = avtab_insert(&policy->te_avtab, &key, av);
		if (ret) {
			fprintf(stderr, "Error inserting into avtab\n");
			return 1;
		}
	}

	av->data |= data;

	return 0;
}


static int load_policy(const char *filename, policydb_t *policydb, struct policy_file *pf)
{
	int fd;
	struct stat sb;
	void *map;
	int ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open '%s':  %s\n",
		        filename, strerror(errno));
		return 1;
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "Can't stat '%s':  %s\n",
		        filename, strerror(errno));
		return 1;
	}
	map = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	           fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "Can't mmap '%s':  %s\n",
		        filename, strerror(errno));
		close(fd);
		return 1;
	}

	policy_file_init(pf);
	pf->type = PF_USE_MEMORY;
	pf->data = map;
	pf->len = sb.st_size;
	if (policydb_init(policydb)) {
		fprintf(stderr, "policydb_init: Out of memory!\n");
		munmap(map, sb.st_size);
		close(fd);
		return 1;
	}
	ret = policydb_read(policydb, pf, 1);
	if (ret) {
		fprintf(stderr, "error(s) encountered while parsing configuration\n");
		munmap(map, sb.st_size);
		close(fd);
		return 1;
	}

	munmap(map, sb.st_size);
	close(fd);
	return 0;
}

int sepolicy_inject_internal_run_action(context_t *context)
{
	char **perms = NULL;
	policydb_t policydb;
	struct policy_file pf, outpf;
	sidtab_t sidtab;
	FILE *fp;
	int typeval;
	type_datum_t *type;

	int selected = context->selected;
	int permissive_value = context->permissive_value;
	const char *policy = context->policy;
	const char *source = context->source;
	const char *target = context->target;
	const char *class = context->class;
	const char *outfile = context->outfile;

	if (!selected || !policy)
		return 2;

	if (!outfile)
		outfile = policy;

	if (context->perm) {
		perms = str_split(context->perm, ',');
		if (perms == NULL) {
			fprintf(stderr, "Could not tokenize permissions\n");
			return 1;
		}
	}

	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (load_policy(policy, &policydb, &pf)) {
		fprintf(stderr, "Could not load policy\n");
		return 1;
	}

	if (policydb_load_isids(&policydb, &sidtab))
		return 1;

	type = hashtab_search(policydb.p_types.table, (const hashtab_key_t)source);
	if (type == NULL) {
		fprintf(stderr, "type %s does not exist, creating\n", source);
		typeval = create_domain(source, &policydb);
	} else {
		typeval = type->s.value;
	}

	if (selected == SEL_PERMISSIVE) {
		if (ebitmap_set_bit(&policydb.permissive_map, typeval, permissive_value)) {
			fprintf(stderr, "Could not set bit in permissive map\n");
			return 1;
		}
	} else if (selected == SEL_ADD_RULE) {
		if (add_rule(source, target, class, perms, &policydb)) {
			fprintf(stderr, "Could not add rule\n");
			return 1;
		}
	} else {
		fprintf(stderr, "Something strange happened\n");
		return 1;
	}

	fp = fopen(outfile, "w");
	if (!fp) {
		fprintf(stderr, "Could not open outfile\n");
		return 1;
	}

	policy_file_init(&outpf);
	outpf.type = PF_USE_STDIO;
	outpf.fp = fp;

	if (policydb_write(&policydb, &outpf)) {
		fprintf(stderr, "Could not write policy\n");
		fclose(fp);
		return 1;
	}

	policydb_destroy(&policydb);
	fclose(fp);

	return 0;
}

int sepolicy_inject_rule(const char *source, const char *target, const char *class, const char *perm, const char *policy, const char *outfile)
{
	context_t context = {
		.policy = policy,
		.outfile = outfile,
		.source = source,
		.selected = SEL_ADD_RULE,

		.target = target,
		.class = class,
		.perm = strdup(perm),

		.permissive_value = 0,
	};

	int rc = sepolicy_inject_internal_run_action(&context);
	free(context.perm);
	return rc;
}

int sepolicy_set_permissive(const char *source, int value, const char *policy, const char *outfile)
{
	context_t context = {
		.policy = policy,
		.outfile = outfile,
		.source = source,
		.selected = SEL_PERMISSIVE,

		.permissive_value = value,
	};

	return sepolicy_inject_internal_run_action(&context);
}
