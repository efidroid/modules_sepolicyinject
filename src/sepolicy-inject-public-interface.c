#include <stdlib.h>

#include <sepolicy_inject.h>
#include "private.h"

void* sepolicy_inject_open(const char *policy)
{
    handle_t *handle = NULL;

    handle = malloc(sizeof(handle_t));
    if(!handle) {
        return NULL;
    }

    handle->interface = &interface_selinux6;
    handle->pdata = handle->interface->open(policy);
    if(!handle->pdata) {
        handle->interface = &interface_selinux7;
        handle->pdata = handle->interface->open(policy);
    }

    if(!handle->pdata)
        goto err_free;

    return handle;

err_free:
    free(handle);

    return NULL;
}

int sepolicy_inject_write(void *handle_, const char *outfile) {
	handle_t *handle = handle_;
	return handle->interface->write(handle->pdata, outfile);
}

int sepolicy_inject_close(void *handle_) {
	handle_t *handle = handle_;

	int rc = handle->interface->close(handle->pdata);
    free(handle);
    return rc;
}

int sepolicy_inject_add_rule(void *handle_, const char *source, const char *target, const char *class, const char *perm)
{
	handle_t *handle = handle_;
	return handle->interface->add_rule(handle->pdata, source, target, class, perm);
}

int sepolicy_inject_set_permissive(void *handle_, const char *source, int value)
{
	handle_t *handle = handle_;
	return handle->interface->set_permissive(handle->pdata, source, value);
}
