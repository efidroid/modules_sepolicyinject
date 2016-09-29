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

#include "tokenize.h"
#include "private.h"

typedef struct {
	policydb_t policydb;
	struct policy_file pf;
	sidtab_t sidtab;
    sepolicy_if_t interface;
} pdata_t;

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

static void* sepolicy_inject_open(const char *policy)
{
	pdata_t *pdata;

	pdata = calloc(sizeof(*pdata), 1);
	if(!pdata)
		goto err_free;

	if (!policy)
		goto err_free;

	sepol_set_policydb(&pdata->policydb);
	sepol_set_sidtab(&pdata->sidtab);

	if (load_policy(policy, &pdata->policydb, &pdata->pf)) {
		fprintf(stderr, "Could not load policy\n");
		goto err_free;
	}

	if (policydb_load_isids(&pdata->policydb, &pdata->sidtab))
		goto err_free;

	return pdata;

err_free:
	free(pdata);
	return NULL;
}

static int sepolicy_inject_write(void *handle, const char *outfile) {
	FILE *fp;
	struct policy_file outpf;
	pdata_t *pdata = handle;

	fp = fopen(outfile, "w");
	if (!fp) {
		fprintf(stderr, "Could not open outfile\n");
		return -1;
	}

	policy_file_init(&outpf);
	outpf.type = PF_USE_STDIO;
	outpf.fp = fp;

	if (policydb_write(&pdata->policydb, &outpf)) {
		fprintf(stderr, "Could not write policy\n");
		fclose(fp);
		return -1;
	}

	fclose(fp);

	return 0;
}

static int sepolicy_inject_close(void *handle) {
	pdata_t *pdata = handle;

	policydb_destroy(&pdata->policydb);
	free(pdata);

	return 0;
}

static int sepolicy_inject_create_type(pdata_t *pdata, const char *source) {
	int typeval;
	type_datum_t *type;

	type = hashtab_search(pdata->policydb.p_types.table, (const hashtab_key_t)source);
	if (type == NULL) {
		fprintf(stderr, "type %s does not exist, creating\n", source);
		typeval = create_domain(source, &pdata->policydb);
	} else {
		typeval = type->s.value;
	}

	return typeval;
}

static int sepolicy_inject_rule(void *handle, const char *source, const char *target, const char *class, const char *perm)
{
	int i;
	char **p;
	int rc;
	char **perms = NULL;
	pdata_t *pdata = handle;

	char* permcpy = strdup(perm);
	if(!permcpy)
		return -ENOMEM;

	perms = str_split(permcpy, ',');
	free(permcpy);
	if (perms == NULL) {
		fprintf(stderr, "Could not tokenize permissions\n");
		return -1;
	}

	sepolicy_inject_create_type(pdata, source);

	if (add_rule(source, target, class, perms, &pdata->policydb)) {
		fprintf(stderr, "Could not add rule\n");
		rc = -1;
		goto do_free_perms;
	}

	rc = 0;

do_free_perms:
	for (i=0,p=perms; p[i]; i++) {
		free(p[i]);
	}
	free(perms);

	return rc;
}

static int sepolicy_set_permissive(void *handle, const char *source, int value)
{
	int typeval;
	pdata_t *pdata = handle;

	typeval = sepolicy_inject_create_type(pdata, source);

	if (ebitmap_set_bit(&pdata->policydb.permissive_map, typeval, value)) {
		fprintf(stderr, "Could not set bit in permissive map\n");
		return 1;
	}

	return 0;
}

sepolicy_if_t INTERFACE_NAME = {
    .open = sepolicy_inject_open,
    .write = sepolicy_inject_write,
    .close = sepolicy_inject_close,
    .add_rule = sepolicy_inject_rule,
    .set_permissive = sepolicy_set_permissive,
};
