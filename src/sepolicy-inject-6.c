#include <selinux6/sepol/debug.h>
#include <selinux6/sepol/policydb/policydb.h>
#include <selinux6/sepol/policydb/expand.h>
#include <selinux6/sepol/policydb/link.h>
#include <selinux6/sepol/policydb/services.h>
#include <selinux6/sepol/policydb/avrule_block.h>
#include <selinux6/sepol/policydb/conditional.h>

#define hashtab_search selinux6_hashtab_search
#define symtab_insert selinux6_symtab_insert
#define policydb_read selinux6_policydb_read
#define sepol_set_policydb selinux6_sepol_set_policydb
#define ebitmap_set_bit selinux6_ebitmap_set_bit
#define type_datum_init selinux6_type_datum_init
#define avtab_search selinux6_avtab_search
#define avtab_insert selinux6_avtab_insert
#define type_set_expand selinux6_type_set_expand
#define policy_file_init selinux6_policy_file_init
#define policydb_init selinux6_policydb_init
#define policydb_load_isids selinux6_policydb_load_isids
#define policydb_write selinux6_policydb_write
#define policydb_destroy selinux6_policydb_destroy
#define sepol_set_sidtab selinux6_sepol_set_sidtab
#define policydb_index_decls selinux6_policydb_index_decls

#define INTERFACE_NAME interface_selinux6

#include "sepolicy-inject-common.c"
