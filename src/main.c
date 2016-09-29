/*
 * This was derived from public domain works with updates to
 * work with more modern SELinux libraries.
 *
 * It is released into the public domain.
 *
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include <sepolicy_inject.h>

#define SEL_ADD_RULE 1
#define SEL_PERMISSIVE 2

void usage(char *arg0)
{
	fprintf(stderr, "Only one of the following can be run at a time\n");
	fprintf(stderr, "%s -s <source type> -t <target type> -c <class> -p <perm> -P <policy file> [-o <output file>]\n", arg0);
	fprintf(stderr, "%s -Z type_to_make_permissive -P <policy file> [-o <output file>]\n", arg0);
	fprintf(stderr, "%s -z type_to_make_nonpermissive -P <policy file> [-o <output file>]\n", arg0);
	exit(1);
}

int main(int argc, char **argv)
{
	char *policy = NULL, *source = NULL, *target = NULL, *class = NULL, *outfile = NULL;
	char *perm = NULL;
	int ch;
	int permissive_value = 0;
	int selected = 0;
	int rc;

	struct option long_options[] = {
		{"source", required_argument, NULL, 's'},
		{"target", required_argument, NULL, 't'},
		{"class", required_argument, NULL, 'c'},
		{"perm", required_argument, NULL, 'p'},
		{"policy", required_argument, NULL, 'P'},
		{"output", required_argument, NULL, 'o'},
		{"permissive", required_argument, NULL, 'Z'},
		{"not-permissive", required_argument, NULL, 'z'},
		{NULL, 0, NULL, 0}
	};

	while ((ch = getopt_long(argc, argv, "s:t:c:p:P:o:Z:z:", long_options, NULL)) != -1) {
		switch (ch) {
			case 's':
				if (selected) {
					usage(argv[0]);
				}
				selected = SEL_ADD_RULE;
				source = optarg;
				break;
			case 't':
				target = optarg;
				break;
			case 'c':
				class = optarg;
				break;
			case 'p': {
				perm = optarg;
				break;
			}
			case 'P':
				policy = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'Z':
				if (selected) {
					usage(argv[0]);
				}
				selected = SEL_PERMISSIVE;
				source = optarg;
				permissive_value = 1;
				break;
			case 'z':
				if (selected) {
					usage(argv[0]);
				}
				selected = SEL_PERMISSIVE;
				source = optarg;
				permissive_value = 0;
				break;
			default:
				usage(argv[0]);
		}
	}

    if(!policy) {
        usage(argv[0]);
        return 1;
    }

    void *handle = sepolicy_inject_open(policy);
    if(!handle) {
        fprintf(stderr, "can't open policy\n");
        return 1;
    }

    if(selected==SEL_PERMISSIVE) {
        if(!source) {
            usage(argv[0]);
            return 1;
        }

        rc = sepolicy_inject_set_permissive(handle, source, permissive_value);
        if (rc) {
            fprintf(stderr, "can't change permissive value\n");
            return 1;
        }
    }
    else if(selected==SEL_ADD_RULE) {
        if(!source || !target || !class || !perm) {
            usage(argv[0]);
            return 1;
        }

        rc = sepolicy_inject_add_rule(handle, source, target, class, perm);
        if (rc) {
            fprintf(stderr, "can't add rules\n");
            return 1;
        }
    }

    if(!outfile)
        outfile = policy;
    rc = sepolicy_inject_write(handle, outfile);
    if (rc) {
        fprintf(stderr, "can't write policy\n");
        return 1;
    }

    sepolicy_inject_close(handle);

    return 0;
}
