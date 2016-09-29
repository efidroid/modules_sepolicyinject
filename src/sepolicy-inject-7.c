#include <selinux7/sepol/debug.h>
#include <selinux7/sepol/policydb/policydb.h>
#include <selinux7/sepol/policydb/expand.h>
#include <selinux7/sepol/policydb/link.h>
#include <selinux7/sepol/policydb/services.h>
#include <selinux7/sepol/policydb/avrule_block.h>
#include <selinux7/sepol/policydb/conditional.h>

#define hashtab_search selinux7_hashtab_search
#define symtab_insert selinux7_symtab_insert
#define policydb_read selinux7_policydb_read
#define sepol_set_policydb selinux7_sepol_set_policydb
#define ebitmap_set_bit selinux7_ebitmap_set_bit
#define type_datum_init selinux7_type_datum_init
#define avtab_search selinux7_avtab_search
#define avtab_insert selinux7_avtab_insert
#define type_set_expand selinux7_type_set_expand
#define policy_file_init selinux7_policy_file_init
#define policydb_init selinux7_policydb_init
#define policydb_load_isids selinux7_policydb_load_isids
#define policydb_write selinux7_policydb_write
#define policydb_destroy selinux7_policydb_destroy
#define sepol_set_sidtab selinux7_sepol_set_sidtab
#define policydb_index_decls selinux7_policydb_index_decls

#define INTERFACE_NAME interface_selinux7

#include "sepolicy-inject-common.c"
