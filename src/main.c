/*
 * SPDX-FileCopyrightText: Copyright 2025-2026 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "streams.h"
#include <dirent.h>
#include <gta_api/gta_api.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern const struct gta_function_list_t * gta_sw_provider_init(
    gta_context_handle_t,
    gtaio_istream_t *,
    gtaio_ostream_t *,
    void **,
    void (**)(void *),
    gta_errinfo_t *);

#define MAXLEN_PROFILE 160
#define MAXLEN_IDENTIFIER_TYPE 100
#define MAXLEN_IDENTIFIER_NAME 100
#define MAXLEN_PERSONALITY_NAME 100
#define MAXLEN_ATTRIBUTE 150
#define MAXLEN_STATEDIR_PATH 150

/* List of all profiles supported by gta-cli */
static char profiles_to_register[][MAXLEN_PROFILE] = {
    "ch.iec.30168.basic.local_data_protection",
    "ch.iec.30168.basic.local_data_integrity_only",
    "com.github.generic-trust-anchor-api.basic.rsa",
    "com.github.generic-trust-anchor-api.basic.ec",
    "com.github.generic-trust-anchor-api.basic.tls",
    "com.github.generic-trust-anchor-api.basic.signature",
    "com.github.generic-trust-anchor-api.basic.jwt",
    "com.github.generic-trust-anchor-api.basic.enroll",
    "org.opcfoundation.ECC-nistP256"};

bool gta_sw_provider_gta_register_provider(
    gta_instance_handle_t h_inst,
    gtaio_istream_t * init_config,
    gta_profile_name_t profile,
    gta_errinfo_t * p_errinfo)
{
    struct gta_provider_info_t provider_info = {
        .version = 0,
        .type = GTA_PROVIDER_INFO_CALLBACK,
        .provider_init = gta_sw_provider_init,
        .provider_init_config = init_config,
        .profile_info = {.profile_name = profile, .protection_properties = {0}, .priority = 0}};

    return gta_register_provider(h_inst, &provider_info, p_errinfo);
}

/* Enum for function selection */
enum functions {
    identifier_assign,
    personality_create,
    seal_data,
    unseal_data,
    identifier_enumerate,
    personality_enumerate,
    personality_enumerate_application,
    personality_add_attribute,
    personality_add_trusted_attribute,
    personality_get_attribute,
    personality_remove_attribute,
    personality_attributes_enumerate,
    authenticate_data_detached,
    verify_data_detached,
    personality_enroll,
    personality_remove,
    devicestate_transition,
    devicestate_recede,
    access_policy_simple,
    FUNC_UNKNOWN
};

/* struct for an attribute */
typedef struct t_attribute {
    char * p_type;
    char * p_val; /* could be the actual attribute value as string
                  or the path to binary file with the actual attribute value as binary */
} t_attribute;

/* struct for list of context attributes */
typedef struct t_ctx_attributes {
    size_t num;
    t_attribute * p_attr;
} t_ctx_attributes;

/* Structure to store the parsed arguments */
struct arguments {
    enum functions func;
    char * app_name;
    char * id_type;
    char * id_val;
    char * pers;
    char * prof;
    gta_access_policy_handle_t h_auth_use;
    gta_access_policy_handle_t h_auth_admin;
    char * pers_flag;
    char * attr_type;
    char * attr_name;
    char * attr_val;
    char * data;
    char * seal;
    t_ctx_attributes ctx_attributes;     /* list of context attributes for arguments --ctx_attr and --ctx_attr_file
                                         one attribute consists of a pair ATTR_TYPE=ATTR_VALUE
                                         ATTR_VALUE is the actual attribute value as string */
    t_ctx_attributes ctx_attributes_bin; /* list of context attributes for argument --ctx_attr_bin
                                         one attribute consists of a pair ATTR_TYPE=FILE
                                         FILE is the path to binary file with
                                         the actual attribute value as binary */
    gta_access_policy_handle_t h_auth_recede;
    size_t * owner_lock_count;
    char * descr_type;
};

/* Function prototypes */
void show_help();
void show_function_help(enum functions func);
int parse_attributes(const char * p_attr, t_attribute * p_attribute);
void free_ctx_attributes(t_ctx_attributes * p_ctx_attributes);
int pers_add_attribute(
    gta_instance_handle_t h_inst,
    gta_context_handle_t h_ctx,
    struct arguments * arguments,
    bool trusted);
int parse_handle(const char * p_handle_string, enum functions func, gta_access_policy_handle_t * p_handle);
int parse_pers_flag(const struct arguments * arguments, gta_personality_enum_flags_t * pers_flag);
int parse_descr_type(const struct arguments * arguments, gta_access_descriptor_type_t * descr_type);
int init_ifilestream(const char * data, myio_ifilestream_t * ifilestream);
void init_ofilestream(myio_ofilestream_t * ofilestream);
int encode_b64(const unsigned char * p_token, size_t in_len, unsigned char ** pp_b64);
int decode_b64(const unsigned char * p_b64, size_t in_len, unsigned char ** pp_bytes, size_t * p_out_len);

/* Parse function to handle command line arguments */
int parse_args(int argc, char * argv[], struct arguments * arguments)
{
    bool b_options = true;

    /* Default values */
    arguments->func = FUNC_UNKNOWN;
    arguments->app_name = NULL;
    arguments->id_type = NULL;
    arguments->id_val = NULL;
    arguments->pers = NULL;
    arguments->prof = NULL;
    arguments->h_auth_use = GTA_HANDLE_INVALID;
    arguments->h_auth_admin = GTA_HANDLE_INVALID;
    arguments->pers_flag = NULL;
    arguments->attr_type = NULL;
    arguments->attr_name = NULL;
    arguments->attr_val = NULL;
    arguments->data = NULL;
    arguments->seal = NULL;
    arguments->ctx_attributes.num = 0;
    arguments->ctx_attributes.p_attr = NULL;
    arguments->ctx_attributes_bin.num = 0;
    arguments->ctx_attributes_bin.p_attr = NULL;
    arguments->h_auth_recede = GTA_HANDLE_INVALID;
    arguments->owner_lock_count = NULL;
    arguments->descr_type = NULL;

    /* Parse the arguments */

    if (1 >= argc) {
        show_help();
        return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "--help") == 0) {
        show_help();
        exit(EXIT_SUCCESS);
    } else if (strcmp(argv[1], "identifier_assign") == 0) {
        arguments->func = identifier_assign;
    } else if (strcmp(argv[1], "personality_create") == 0) {
        arguments->func = personality_create;
    } else if (strcmp(argv[1], "seal_data") == 0) {
        arguments->func = seal_data;
    } else if (strcmp(argv[1], "unseal_data") == 0) {
        arguments->func = unseal_data;
    } else if (strcmp(argv[1], "identifier_enumerate") == 0) {
        arguments->func = identifier_enumerate;
        b_options = false;
    } else if (strcmp(argv[1], "personality_enumerate") == 0) {
        arguments->func = personality_enumerate;
    } else if (strcmp(argv[1], "personality_enumerate_application") == 0) {
        arguments->func = personality_enumerate_application;
    } else if (strcmp(argv[1], "personality_add_attribute") == 0) {
        arguments->func = personality_add_attribute;
    } else if (strcmp(argv[1], "personality_add_trusted_attribute") == 0) {
        arguments->func = personality_add_trusted_attribute;
    } else if (strcmp(argv[1], "personality_get_attribute") == 0) {
        arguments->func = personality_get_attribute;
    } else if (strcmp(argv[1], "personality_remove_attribute") == 0) {
        arguments->func = personality_remove_attribute;
    } else if (strcmp(argv[1], "personality_attributes_enumerate") == 0) {
        arguments->func = personality_attributes_enumerate;
    } else if (strcmp(argv[1], "authenticate_data_detached") == 0) {
        arguments->func = authenticate_data_detached;
    } else if (strcmp(argv[1], "verify_data_detached") == 0) {
        arguments->func = verify_data_detached;
    } else if (strcmp(argv[1], "personality_enroll") == 0) {
        arguments->func = personality_enroll;
    } else if (strcmp(argv[1], "personality_remove") == 0) {
        arguments->func = personality_remove;
    } else if (strcmp(argv[1], "devicestate_transition") == 0) {
        arguments->func = devicestate_transition;
    } else if (strcmp(argv[1], "devicestate_recede") == 0) {
        arguments->func = devicestate_recede;
        b_options = false;
    } else if (strcmp(argv[1], "access_policy_simple") == 0) {
        arguments->func = access_policy_simple;
        b_options = false;
    } else {
        fprintf(stderr, "Unknown argument: %s\n", argv[1]);
        show_help();
        return EXIT_FAILURE;
    }

    if (b_options && (2 >= argc)) {
        fprintf(stderr, "Missing function arguments \n");
        show_function_help(arguments->func);
        return EXIT_FAILURE;
    }

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--app_name=", 11) == 0) {
            arguments->app_name = argv[i] + 11;
        } else if (strncmp(argv[i], "--id_type=", 10) == 0) {
            arguments->id_type = argv[i] + 10;
        } else if (strncmp(argv[i], "--id_val=", 9) == 0) {
            arguments->id_val = argv[i] + 9;
        } else if (strncmp(argv[i], "--pers=", 7) == 0) {
            arguments->pers = argv[i] + 7;
        } else if (strncmp(argv[i], "--prof=", 7) == 0) {
            arguments->prof = argv[i] + 7;
        } else if (strncmp(argv[i], "--acc_pol_use=", 14) == 0) {
            if (EXIT_FAILURE == parse_handle(argv[i] + 14, arguments->func, &arguments->h_auth_use)) {
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--acc_pol_admin=", 16) == 0) {
            if (EXIT_FAILURE == parse_handle(argv[i] + 16, arguments->func, &arguments->h_auth_admin)) {
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--pers_flag=", 12) == 0) {
            arguments->pers_flag = argv[i] + 12;
        } else if (strncmp(argv[i], "--attr_type=", 12) == 0) {
            arguments->attr_type = argv[i] + 12;
        } else if (strncmp(argv[i], "--attr_name=", 12) == 0) {
            arguments->attr_name = argv[i] + 12;
        } else if (strncmp(argv[i], "--attr_val=", 11) == 0) {
            arguments->attr_val = argv[i] + 11;
        } else if (strncmp(argv[i], "--data=", 7) == 0) {
            arguments->data = argv[i] + 7;
        } else if (strncmp(argv[i], "--seal=", 7) == 0) {
            arguments->seal = argv[i] + 7;
        } else if (strncmp(argv[i], "--ctx_attr_file=", 16) == 0) {
            FILE * p_file_attributes = NULL;
            char str_temp[MAXLEN_ATTRIBUTE] = {0};

            p_file_attributes = fopen(argv[i] + 16, "r");
            if (NULL == p_file_attributes) {
                fprintf(stderr, "Cannot open file %s\n", argv[i] + 16);
                return EXIT_FAILURE;
            }

            /* read ATTR_TYPE=ATTR_VAL pairs line by line from file
               create new attribute in list of attributes for every new line
               call parsing function to set attr_type and attr_val to attribute

               file content must be in the form:
               ATTR_TYPE=ATTR_VAL
               ATTR_TYPE=ATTR_VAL
               ATTR_TYPE=ATTR_VAL
               ...
            */

            while (fgets(str_temp, sizeof(str_temp) - 1, p_file_attributes)) {
                if (0 != strnlen(str_temp, sizeof(str_temp))) {

                    t_attribute * p_new_attribute = NULL;
                    ++arguments->ctx_attributes.num;
                    p_new_attribute =
                        realloc(arguments->ctx_attributes.p_attr, arguments->ctx_attributes.num * sizeof(t_attribute));
                    if (NULL != p_new_attribute) {
                        arguments->ctx_attributes.p_attr = p_new_attribute;
                        if (EXIT_SUCCESS !=
                            parse_attributes(
                                str_temp, &(arguments->ctx_attributes.p_attr[arguments->ctx_attributes.num - 1]))) {
                            fprintf(stderr, "Missing function arguments\n");
                            fclose(p_file_attributes);
                            return EXIT_FAILURE;
                        }
                    } else {
                        fprintf(stderr, "Memory allocation error\n");
                        fclose(p_file_attributes);
                        return EXIT_FAILURE;
                    }
                }
            }
            fclose(p_file_attributes);

        } else if (strncmp(argv[i], "--ctx_attr_bin", 14) == 0) {
            t_attribute * p_new_attribute = NULL;
            i++;
            if (NULL == argv[i]) {
                fprintf(stderr, "Missing function arguments\n");
                show_function_help(arguments->func);
                return EXIT_FAILURE;
            }

            /* create new attribute in list of attributes
               call parsing function to set attr_type and attr_val to attribute */

            ++arguments->ctx_attributes_bin.num;
            p_new_attribute =
                realloc(arguments->ctx_attributes_bin.p_attr, arguments->ctx_attributes_bin.num * sizeof(t_attribute));
            if (NULL != p_new_attribute) {
                arguments->ctx_attributes_bin.p_attr = p_new_attribute;
                if (EXIT_SUCCESS !=
                    parse_attributes(
                        argv[i], &(arguments->ctx_attributes_bin.p_attr[arguments->ctx_attributes_bin.num - 1]))) {
                    fprintf(stderr, "Missing function arguments\n");
                    return EXIT_FAILURE;
                }
            } else {
                fprintf(stderr, "Memory allocation error\n");
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--ctx_attr", 10) == 0) {
            t_attribute * p_new_attribute = NULL;
            i++;
            if (NULL == argv[i]) {
                fprintf(stderr, "Missing function arguments\n");
                show_function_help(arguments->func);
                return EXIT_FAILURE;
            }

            /* create new attribute in list of attributes
               call parsing function to set attr_type and attr_val to attribute */

            ++arguments->ctx_attributes.num;
            p_new_attribute =
                realloc(arguments->ctx_attributes.p_attr, arguments->ctx_attributes.num * sizeof(t_attribute));
            if (NULL != p_new_attribute) {
                arguments->ctx_attributes.p_attr = p_new_attribute;
                if (EXIT_SUCCESS !=
                    parse_attributes(argv[i], &(arguments->ctx_attributes.p_attr[arguments->ctx_attributes.num - 1]))) {
                    fprintf(stderr, "Missing function arguments\n");
                    return EXIT_FAILURE;
                }
            } else {
                fprintf(stderr, "Memory allocation error\n");
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--acc_pol_recede=", 17) == 0) {
            if (EXIT_FAILURE == parse_handle(argv[i] + 17, arguments->func, &arguments->h_auth_recede)) {
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--owner_lock_count=", 19) == 0) {
            char * p_endptr = NULL;
            /* Check if argument is missing (NULL-terminater after '=') */
            if (19 == strnlen(argv[i], 20)) {
                fprintf(stderr, "Missing function argument\n");
                return EXIT_FAILURE;
            }

            arguments->owner_lock_count = (size_t *)malloc(sizeof(size_t));
            if (NULL == arguments->owner_lock_count) {
                fprintf(stderr, "Memory allocation error\n");
                return EXIT_FAILURE;
            }

            (*arguments->owner_lock_count) = strtoul(argv[i] + 19, &p_endptr, 10);

            if ('\0' != *p_endptr) {
                fprintf(stderr, "Invalid input: '%s' is not a valid numeric value\n", argv[i] + 19);
                free(arguments->owner_lock_count);
                return EXIT_FAILURE;
            }
        } else if (strncmp(argv[i], "--descr_type=", 13) == 0) {
            arguments->descr_type = argv[i] + 13;
        } else if (strcmp(argv[i], "--help") == 0) {
            show_function_help(arguments->func);
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "Unknown function argument: %s\n", argv[i]);
            show_function_help(arguments->func);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

void show_help()
{
    printf("To print help:\ngta-cli --help \n");
    printf("cli usage: gta-cli <FUNCTION> --options\n");
    printf("\nSupported functions:\n");
    printf("  identifier_assign                  assign an identifier to the device\n");
    printf("  personality_create                 create a personality on the device for a given identifier\n");
    printf("  seal_data                          protect a piece of data according to the given profile and "
           "personality\n");
    printf("  unseal_data                        recover a piece of data according to the given profile and "
           "personality\n");
    printf("  identifier_enumerate               enumerate all identifiers managed by GTA API\n");
    printf("  personality_enumerate              enumerate all personalities that are known to GTA API by their "
           "identifier\n");
    printf("  personality_enumerate_application  enumerate all personalities that are known to GTA API by their "
           "application name\n");
    printf("  personality_add_attribute          assign an additional general attribute to an existing personality\n");
    printf("  personality_add_trusted_attribute  assign an additional trusted attribute to an existing personality\n");
    printf("  personality_get_attribute          get attribute of a personality\n");
    printf("  personality_remove_attribute       remove attribute of a personality\n");
    printf("  personality_attributes_enumerate   enumerate all attributes belonging to a personality\n");
    printf("  authenticate_data_detached         calculate a cryptographic seal for the provided data according to the "
           "given profile and personality\n");
    printf("  verify_data_detached               verify a cryptographic seal for the provided data according to the "
           "profile and personality\n");
    printf("  personality_enroll                 create an enrollment request for a personality according to the given "
           "profile\n");
    printf("  personality_remove                 remove a personality\n");
    printf("  devicestate_transition             advance into a new transition device state (push)\n");
    printf("  devicestate_recede                 recede into the previous transition device state (pop)\n");
    printf("  access_policy_simple               get handle for a simple (static) access policy\n");

    printf("\nSupported profiles:\n");
    for (size_t i = 0; i < (sizeof(profiles_to_register) / sizeof(profiles_to_register[0])); ++i) {
        printf("  %s\n", profiles_to_register[i]);
    }

    printf("\nFor function-specific help, use: gta-cli <FUNCTION> --help\n");
}

void show_function_help(enum functions func)
{
    switch (func) {
    case identifier_assign:
        printf("Usage: gta-cli identifier_assign --options\n");
        printf("Options:\n");
        printf("  --id_type=IDENTIFIER_TYPE  type for the identifier being assigned\n");
        printf("  --id_val=IDENTIFIER_VALUE  value for the identifier being assigned\n");
        break;
    case personality_create:
        printf("Usage: gta-cli personality_create --options\n");
        printf("Options:\n");
        printf("  --id_val=IDENTIFIER_VALUE    value of the identifier to which the new personality belongs\n");
        printf("  --pers=PERSONALITY_NAME      name to reference the new personality\n");
        printf("  --app_name=APPLICATION_NAME  application defined filter criteria to discover the personality using "
               "personality_enumerate_application\n");
        printf("  --prof=PROFILE_NAME          profile indicating a type and format of the personality\n");
        printf("  [--acc_pol_use=HANDLE]       access policy defining usage of the personality [default: initial "
               "access policy]\n");
        printf("  [--acc_pol_admin=HANDLE]     access policy defining administration of the personality [default: "
               "initial access policy]\n");
        break;
    case seal_data:
        printf("Usage: gta-cli seal_data --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME  personality to use for the operation\n");
        printf("  --prof=PROFILE_NAME      profile to use for the operation\n");
        printf("  [--data=FILE]            data to be sealed, if --data is not set data will be read from stdin\n");
        break;
    case unseal_data:
        printf("Usage: gta-cli unseal_data --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME  personality to use for the operation\n");
        printf("  --prof=PROFILE_NAME      profile to use for the operation\n");
        printf("  [--data=FILE]            data to be unsealed, if --data is not set data will be read from stdin\n");
        break;
    case identifier_enumerate:
        printf("Usage: gta-cli identifier_enumerate --options\n");
        printf("Options:\n");
        printf("  none\n");
        break;
    case personality_enumerate:
        printf("Usage: gta-cli personality_enumerate --options\n");
        printf("Options:\n");
        printf(
            "  --id_val=IDENTIFIER_VALUE           identifier for which the available personalities are enumerated\n");
        printf("  [--pers_flag={ALL|ACTIVE|INACTIVE}] select between active and deactivated personalities [default: "
               "ALL]\n");
        break;
    case personality_enumerate_application:
        printf("Usage: gta-cli personality_enumerate_application --options\n");
        printf("Options:\n");
        printf(
            "  --app_name=APPLICATION_NAME         application for which the available personalities are enumerated\n");
        printf("  [--pers_flag={ALL|ACTIVE|INACTIVE}] select between active and deactivated personalities [default: "
               "ALL]\n");
        break;
    case personality_add_attribute:
        printf("Usage: gta-cli personality_add_attribute --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME     personality to add the general attribute to\n");
        printf("  --prof=PROFILE              profile to use\n");
        printf("  --attr_type=ATTRIBUTE_TYPE  type of the general attribute\n");
        printf("  --attr_name=ATTRIBUTE_NAME  name of the general attribute\n");
        printf("  [--attr_val=FILE]           value for the general attribute, if --attr_val is not set the value will "
               "be read from stdin\n");
        break;
    case personality_add_trusted_attribute:
        printf("Usage: gta-cli personality_add_trusted_attribute --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME     personality to add the trusted attribute to\n");
        printf("  --prof=PROFILE              profile to use\n");
        printf("  --attr_type=ATTRIBUTE_TYPE  type of the trusted attribute\n");
        printf("  --attr_name=ATTRIBUTE_NAME  name of the trusted attribute\n");
        printf("  [--attr_val=FILE]           value for the trusted attribute, if --attr_val is not set the value will "
               "be read from stdin\n");
        break;
    case personality_get_attribute:
        printf("Usage: gta-cli personality_get_attribute --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME     personality to get general attribute from\n");
        printf("  --prof=PROFILE              profile to use\n");
        printf("  --attr_name=ATTRIBUTE_NAME  attribute to be queried\n");
        break;
    case personality_remove_attribute:
        printf("Usage: gta-cli personality_remove_attribute --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME     personality to remove general attribute from\n");
        printf("  --prof=PROFILE              profile to use\n");
        printf("  --attr_name=ATTRIBUTE_NAME  attribute to be removed\n");
        break;
    case personality_attributes_enumerate:
        printf("Usage: gta-cli personality_attributes_enumerate --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME  personality for which the available attributes are enumerated\n");
        break;
    case authenticate_data_detached:
        printf("Usage: gta-cli authenticate_data_detached --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME  personality to use for the operation\n");
        printf("  --prof=PROFILE           profile to use for the operation\n");
        printf(
            "  --data=FILE              data to be protected, if --data is not set the data will be read from stdin\n");
        break;
    case verify_data_detached:
        printf("Usage: gta-cli verify_data_detached --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME  personality to use for the operation\n");
        printf("  --prof=PROFILE           profile to use for the operation\n");
        printf(
            "  --data=FILE              data to be verified, if --data is not set the data will be read from stdin\n");
        printf("  --seal=FILE              authentication seal to be verified\n");
        break;
    case personality_enroll:
        printf("Usage: gta-cli personality_enroll --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME                   personality for which an enrollment request should be "
               "created\n");
        printf("  --prof=PROFILE_NAME                       profile defining which kind of enrollment request should "
               "be created\n");
        printf("  [(--ctx_attr ATTR_TYPE=ATTR_VAL)...]      extra attributes required to create the enrollment as "
               "described in the enrollment profile\n");
        printf("                                            ATTR_VAL is the attribute value as a string\n");
        printf("  [(--ctx_attr_file=FILE)...]               extra attributes provided in a file with "
               "ATTR_TYPE=ATTR_VAL pairs\n");
        printf("                                            ATTR_VAL is the attribute value as a string\n");
        printf("  [(--ctx_attr_bin ATTR_TYPE=FILE)...]      extra attributes required to create the enrollment as "
               "described in the enrollment profile\n");
        printf("                                            FILE is the path to a file with the attribute value as "
               "binary\n");
        break;
    case personality_remove:
        printf("Usage: gta-cli personality_remove --options\n");
        printf("Options:\n");
        printf("  --pers=PERSONALITY_NAME   personality which should be deleted\n");
        printf("  --prof=PROFILE_NAME       profile that should be used deleting the personality\n");
        break;
    case devicestate_transition:
        printf("Usage: gta-cli devicestate_transition --options\n");
        printf("Options:\n");
        printf("  --acc_pol_recede=HANDLE               access policy defining authentication required to run "
               "devicestate_recede\n");
        printf(
            "  --owner_lock_count=OWNER_LOCK_COUNT   counter to restrict the assignment of recede access policies\n");
        printf("                                        with authentication by physical access for future device "
               "states\n");
        break;
    case devicestate_recede:
        printf("Usage: gta-cli devicestate_recede\n");
        printf("No options\n");
        break;
    case access_policy_simple:
        printf("Usage: gta-cli access_policy_simple\n");
        printf("Options:\n");
        printf(" [--descr_type={INITIAL|BASIC|PHYSICAL_PRESENCE}]   type of single access descriptor that is used to "
               "setup the simple access policy [default: INITIAL]\n");
        break;

    default:
        fprintf(stderr, "Unknown function.\n");
        show_help();
        break;
    }
}

void free_ctx_attributes(t_ctx_attributes * p_ctx_attributes)
{
    if (p_ctx_attributes) {
        for (size_t i = 0; i < p_ctx_attributes->num; i++) {
            free(p_ctx_attributes->p_attr[i].p_type);
            free(p_ctx_attributes->p_attr[i].p_val);
        }
        p_ctx_attributes->num = 0;
        free(p_ctx_attributes->p_attr);
        p_ctx_attributes->p_attr = NULL;
    }

    return;
}

/* Parse string p_attr with ATTR_TYPE=ATTR_VAL and write ATTR_TYPE and ATTR_VAL to members of p_attribute structure */
/* the memory of p_attribute->p_type and p_attribute->p_val is allocated dynamically and should be freed by the caller
 */
int parse_attributes(const char * p_attr, t_attribute * p_attribute)
{
    const char * p_attr_type = NULL;
    const char * p_attr_val = NULL;
    size_t attr_type_len = 0;
    size_t attr_val_len = 0;

    if (NULL == p_attr || NULL == p_attribute) {
        return EXIT_FAILURE;
    }

    /* parse for equals sign, extract attr_type and attr_val, allocate memory for members of attribute and copy values
     */
    /* as ATTR_VAL can contain equals itself search only for the first one in the string */
    /* example string for ATTR_TYPE=ATTR_VAL*/
    /* com.github.generic-trust-anchor-api.enroll.subject_rdn="CN=Dummy Product Name,O=Dummy Organization,OU=Dummy
     * Organizational Unit" */
    const char separator = '=';
    char * const sep_at = strchr(p_attr, separator);

    if (NULL == sep_at) {
        return EXIT_FAILURE;
    } else {
        *sep_at = '\0'; /* overwrite first separator, creating two strings. */
        p_attr_type = p_attr;
        p_attr_val = sep_at + 1;
    }

    attr_type_len = strnlen(p_attr_type, MAXLEN_ATTRIBUTE) + 1;
    attr_val_len = strnlen(p_attr_val, MAXLEN_ATTRIBUTE) + 1;
    p_attribute->p_type = calloc(attr_type_len, sizeof(char));
    p_attribute->p_val = calloc(attr_val_len, sizeof(char));
    if ((NULL == p_attribute->p_type) || (NULL == p_attribute->p_val)) {
        return EXIT_FAILURE;
    }
    memcpy(p_attribute->p_type, p_attr_type, attr_type_len);
    memcpy(p_attribute->p_val, p_attr_val, attr_val_len);

    return EXIT_SUCCESS;
}

static bool create_folder(const char * folder_path)
{
    bool ret = false;
    DIR * dir = opendir(folder_path);

    if (NULL == dir) {
        if (0 != mkdir(folder_path, 0770)) {
            fprintf(stderr, "Error: creating folder\n");
        } else {
            ret = true;
        }
    } else {
        closedir(dir);
        ret = true;
    }
    return ret;
}

/*
 * Helper function to initialize an ifilestream. In casa data is not NULL,
 * it should contain a filepath which we use as input, otherwise we read
 * from stdin.
 */
int init_ifilestream(const char * data, myio_ifilestream_t * ifilestream)
{
    gta_errinfo_t errinfo = GTA_ERROR_INTERNAL_ERROR;

    if (NULL != data) {
        if (!myio_open_ifilestream(ifilestream, data, &errinfo)) {
            fprintf(stderr, "Cannot open file %s\n", data);
            return EXIT_FAILURE;
        }
    } else {
        ifilestream->file = stdin;
        ifilestream->read = (gtaio_stream_read_t)myio_ifilestream_read;
        ifilestream->eof = (gtaio_stream_eof_t)myio_ifilestream_eof;
    }

    return EXIT_SUCCESS;
}

/* Initializes ofilestream to stdout. */
void init_ofilestream(myio_ofilestream_t * ofilestream)
{
    ofilestream->write = (gtaio_stream_write_t)myio_ofilestream_write;
    ofilestream->finish = (gtaio_stream_finish_t)myio_ofilestream_finish;
    ofilestream->file = stdout;
}

int pers_add_attribute(
    gta_instance_handle_t h_inst,
    gta_context_handle_t h_ctx,
    struct arguments * arguments,
    bool trusted)
{
    int ret = EXIT_FAILURE;
    gta_errinfo_t errinfo = 0;
    myio_ifilestream_t istream_attr_val = {0};

    if (NULL == arguments->pers || NULL == arguments->prof || NULL == arguments->attr_type ||
        NULL == arguments->attr_name) {
        fprintf(stderr, "Invalid or missing function arguments\n");
        show_function_help(arguments->func);
        goto cleanup;
    }

    if (EXIT_SUCCESS != init_ifilestream(arguments->attr_val, &istream_attr_val)) {
        goto cleanup;
    }

    h_ctx = gta_context_open(h_inst, arguments->pers, arguments->prof, &errinfo);
    if (NULL == h_ctx) {
        fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
        goto cleanup;
    }

    if (trusted) {
        if (!gta_personality_add_trusted_attribute(
                h_ctx, arguments->attr_type, arguments->attr_name, (gtaio_istream_t *)&istream_attr_val, &errinfo)) {
            fprintf(stderr, "gta_personality_add_attribute failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
    } else {
        if (!gta_personality_add_attribute(
                h_ctx, arguments->attr_type, arguments->attr_name, (gtaio_istream_t *)&istream_attr_val, &errinfo)) {
            fprintf(stderr, "gta_personality_add_attribute failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
    }
    if (!gta_context_close(h_ctx, &errinfo)) {
        fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
        goto cleanup;
    }
    ret = EXIT_SUCCESS;

cleanup:
    myio_close_ifilestream(&istream_attr_val, &errinfo);
    return ret;
}

int parse_handle(const char * p_handle_string, enum functions func, gta_access_policy_handle_t * p_handle)
{
    int ret = EXIT_SUCCESS;
    if (NULL != p_handle_string) {
        uintptr_t int_val = (uintptr_t)strtoull(p_handle_string, NULL, 10);
        *p_handle = (void *)int_val;
    }
    if (NULL == p_handle_string || NULL == *p_handle) {
        fprintf(stderr, "Invalid policy handle %s\n", p_handle_string);
        show_function_help(func);
        ret = EXIT_FAILURE;
    }
    return ret;
}

int parse_pers_flag(const struct arguments * arguments, gta_personality_enum_flags_t * pers_flag)
{
    int ret = EXIT_SUCCESS;
    if (NULL != arguments->pers_flag) {
        if (!strcmp(arguments->pers_flag, "ALL")) {
            *pers_flag = GTA_PERSONALITY_ENUM_ALL;
        } else if (!strcmp(arguments->pers_flag, "ACTIVE")) {
            *pers_flag = GTA_PERSONALITY_ENUM_ACTIVE;
        } else if (!strcmp(arguments->pers_flag, "INACTIVE")) {
            *pers_flag = GTA_PERSONALITY_ENUM_INACTIVE;
        } else {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments->func);
            ret = EXIT_FAILURE;
        }
    }
    return ret;
}

int parse_descr_type(const struct arguments * arguments, gta_access_descriptor_type_t * descr_type)
{
    int ret = EXIT_SUCCESS;
    if (NULL != arguments->descr_type) {
        if (!strcmp(arguments->descr_type, "INITIAL")) {
            *descr_type = GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL;
        } else if (!strcmp(arguments->descr_type, "BASIC")) {
            *descr_type = GTA_ACCESS_DESCRIPTOR_TYPE_BASIC_TOKEN;
        } else if (!strcmp(arguments->descr_type, "PHYSICAL_PRESENCE")) {
            *descr_type = GTA_ACCESS_DESCRIPTOR_TYPE_PHYSICAL_PRESENCE_TOKEN;
        } else {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments->func);
            ret = EXIT_FAILURE;
        }
    }
    return ret;
}

int encode_b64(const unsigned char * p_token, size_t in_len, unsigned char ** pp_b64)
{
    if (NULL == pp_b64) {
        return EXIT_FAILURE;
    }

    /* calculate length for base64 string*/
    size_t out_len = 4 * ((in_len + 2) / 3);

    *pp_b64 = malloc(out_len + 1);
    if (NULL == *pp_b64) {
        return EXIT_FAILURE;
    }

    int written = EVP_EncodeBlock(*pp_b64, p_token, (int)in_len);
    if (written <= 0) {
        free(*pp_b64);
        return EXIT_FAILURE;
    }
    (*pp_b64)[written] = '\0';

    return EXIT_SUCCESS;
}

int decode_b64(const unsigned char * p_b64, size_t in_len, unsigned char ** pp_bytes, size_t * p_out_len)
{
    if (p_b64 == NULL || pp_bytes == NULL || p_out_len == NULL) {
        return EXIT_FAILURE;
    }

    /* no input: nothing to decode */
    if (in_len == 0) {
        *pp_bytes = NULL;
        *p_out_len = 0;
        return EXIT_SUCCESS;
    }

    /* length of base64 is always a multiple of 4 */
    if (in_len % 4 != 0) {
        return EXIT_FAILURE;
    }

    /* calculate max output len, 3 bytes per base64 character */
    size_t alloc_len = 3 * (in_len / 4);
    unsigned char * buf = (unsigned char *)malloc(alloc_len);
    if (buf == NULL) {
        return EXIT_FAILURE;
    }

    /* EVP_DecodeBlock writes max alloc_len bytes and returns the number of written bytes or -1 if an error occurs */
    int written = EVP_DecodeBlock(buf, p_b64, (int)in_len);
    if (written < 0) {
        free(buf);
        return EXIT_FAILURE;
    }

    /* correct length based on padding ('=' at the end) */
    size_t pad = 0;
    if (in_len >= 1 && p_b64[in_len - 1] == '=')
        pad++;
    if (in_len >= 2 && p_b64[in_len - 2] == '=')
        pad++;

    size_t out_len = (size_t)written - pad;

    *pp_bytes = buf;
    *p_out_len = out_len;
    return EXIT_SUCCESS;
}

int main(int argc, char * argv[])
{
    struct arguments arguments = {0};
    int ret = EXIT_FAILURE;
    /* the environment variable GTA_STATE_DIRECTORY takes a path to a dir
       this dir should be already present on the filesystem */
    const char * p_state_dir_env = getenv("GTA_STATE_DIRECTORY");
    const char * p_state_dir = NULL;
    if (NULL == p_state_dir_env) {
        p_state_dir = "gta_state";  /* default directory name to store gta states */
        create_folder(p_state_dir); /* create the default one if not existing */
    } else {
        p_state_dir = p_state_dir_env;
    }

    /* Parse the arguments */
    if (EXIT_SUCCESS != parse_args(argc, argv, &arguments)) {
        return EXIT_FAILURE;
    }

    gta_instance_handle_t h_inst = GTA_HANDLE_INVALID;
    gta_context_handle_t h_ctx = GTA_HANDLE_INVALID;
    myio_ifilestream_t istream = {0};
    myio_ifilestream_t istream_seal = {0};
    gta_errinfo_t errinfo = 0;

    /* GTA instance used by the tests */
    struct gta_instance_params_t inst_params = {
        NULL,
        {
            .calloc = &calloc,
            .free = &free,
            .mutex_create = NULL,
            .mutex_destroy = NULL,
            .mutex_lock = NULL,
            .mutex_unlock = NULL,
        },
        NULL};

    istream_from_buf_t init_config = {0};
    istream_from_buf_init(&init_config, p_state_dir, strnlen(p_state_dir, MAXLEN_STATEDIR_PATH));

    /* initialising gta_instance */
    h_inst = gta_instance_init(&inst_params, &errinfo);

    if (NULL == h_inst) {
        fprintf(stderr, "h_inst failed with ERROR_CODE %ld\n", errinfo);
        goto cleanup;
    }

    /* register profiles for provider */
    for (size_t i = 0; i < (sizeof(profiles_to_register) / sizeof(profiles_to_register[0])); ++i) {
        if (!gta_sw_provider_gta_register_provider(
                h_inst, (gtaio_istream_t *)&init_config, profiles_to_register[i], &errinfo)) {
            fprintf(stderr, "gta_sw_provider_gta_register_provider failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
    }

    /* Call the selected function with the parsed arguments */
    switch (arguments.func) {
    case identifier_assign: {

        if (NULL == arguments.id_type || NULL == arguments.id_val) {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        if (!gta_identifier_assign(h_inst, arguments.id_type, arguments.id_val, &errinfo)) {
            fprintf(stderr, "gta_identifier_assign failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }
    case personality_create: {

        if (NULL == arguments.id_val || NULL == arguments.pers || NULL == arguments.prof ||
            NULL == arguments.app_name) {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        gta_access_policy_handle_t h_auth_use = GTA_HANDLE_INVALID;
        gta_access_policy_handle_t h_auth_admin = GTA_HANDLE_INVALID;
        struct gta_protection_properties_t protection_properties = {0};

        gta_access_policy_handle_t h_auth_initial = GTA_HANDLE_INVALID;
        if ((GTA_HANDLE_INVALID == arguments.h_auth_use) || (GTA_HANDLE_INVALID == arguments.h_auth_admin)) {
            h_auth_initial = gta_access_policy_simple(h_inst, GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL, &errinfo);
            if (h_auth_initial == NULL) {
                fprintf(stderr, "gta_access_policy_simple failed with ERROR_CODE %ld\n", errinfo);
                goto cleanup;
            }
        }
        if (GTA_HANDLE_INVALID != arguments.h_auth_use) {
            h_auth_use = arguments.h_auth_use;
        } else {
            h_auth_use = h_auth_initial;
        }

        if (GTA_HANDLE_INVALID != arguments.h_auth_admin) {
            h_auth_admin = arguments.h_auth_admin;
        } else {
            h_auth_admin = h_auth_initial;
        }

        if (!gta_personality_create(
                h_inst,
                arguments.id_val,
                arguments.pers,
                arguments.app_name,
                arguments.prof,
                h_auth_use,
                h_auth_admin,
                protection_properties,
                &errinfo)) {
            fprintf(stderr, "gta_personality_create failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
        break;
    }
    case seal_data: {
        if (NULL == arguments.pers || NULL == arguments.prof) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        myio_ofilestream_t ostream_protected_data = {0};
        init_ofilestream(&ostream_protected_data);

        if (EXIT_SUCCESS != init_ifilestream(arguments.data, &istream)) {
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);
        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_seal_data(h_ctx, (gtaio_istream_t *)&istream, (gtaio_ostream_t *)&ostream_protected_data, &errinfo)) {
            fprintf(stderr, "gta_seal_data failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (NULL != arguments.data) {
            myio_close_ifilestream(&istream, &errinfo);
        }

        break;
    }
    case unseal_data: {
        if (NULL == arguments.pers || NULL == arguments.prof) {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        myio_ofilestream_t ostream_unsealed_data = {0};
        init_ofilestream(&ostream_unsealed_data);

        if (EXIT_SUCCESS != init_ifilestream(arguments.data, &istream)) {
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);

        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_unseal_data(h_ctx, (gtaio_istream_t *)&istream, (gtaio_ostream_t *)&ostream_unsealed_data, &errinfo)) {
            fprintf(stderr, "gta_unseal_data failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (NULL != arguments.data) {
            myio_close_ifilestream(&istream, &errinfo);
        }

        break;
    }
    case identifier_enumerate: {
        int num_of_identifier = 0;
        bool b_loop = true;
        gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;

        char idtypebuf[MAXLEN_IDENTIFIER_TYPE] = {0};
        ostream_to_buf_t o_idtype = {0};
        char idnamebuf[MAXLEN_IDENTIFIER_NAME] = {0};
        ostream_to_buf_t o_idname = {0};

        while (b_loop) {
            ostream_to_buf_init(&o_idtype, idtypebuf, sizeof(idtypebuf));
            ostream_to_buf_init(&o_idname, idnamebuf, sizeof(idnamebuf));

            if (gta_identifier_enumerate(
                    h_inst, &h_enum, (gtaio_ostream_t *)&o_idtype, (gtaio_ostream_t *)&o_idname, &errinfo)) {
                printf("[%d]\n", num_of_identifier);
                printf("Identifier Type:    %s\n", idtypebuf);
                printf("Identifier Value:   %s\n\n", idnamebuf);
                num_of_identifier++;
            } else {
                b_loop = false;
            }
        }

        break;
    }

    case personality_enumerate: {
        if (NULL == arguments.id_val) {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        int num_of_personality = 0;
        bool b_loop = true;
        gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
        char persnamebuf[MAXLEN_PERSONALITY_NAME] = {0};
        ostream_to_buf_t o_persname = {0};
        gta_personality_enum_flags_t pers_flag = GTA_PERSONALITY_ENUM_ALL;

        if (EXIT_SUCCESS != parse_pers_flag(&arguments, &pers_flag)) {
            goto cleanup;
        }

        while (b_loop) {
            ostream_to_buf_init(&o_persname, persnamebuf, sizeof(persnamebuf));

            if (gta_personality_enumerate(
                    h_inst, arguments.id_val, &h_enum, pers_flag, (gtaio_ostream_t *)&o_persname, &errinfo)) {
                printf("[%d]\n", num_of_personality);
                printf("Identifier Value:   %s\n", arguments.id_val);
                printf("Personality Name:   %s\n\n", persnamebuf);
                num_of_personality++;
            } else {
                if (errinfo == GTA_ERROR_INVALID_PARAMETER) {
                    fprintf(stderr, "gta_personality_enumerate failed with ERROR_CODE %ld\n", errinfo);
                    fprintf(stderr, "--pers_flag=%s not supported yet\n", arguments.pers_flag);
                }

                b_loop = false;
            }
        }

        break;
    }
    case personality_enumerate_application: {
        if (NULL == arguments.app_name) {
            fprintf(stderr, "Invalid function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        int num_of_personality = 0;
        bool b_loop = true;
        gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;
        char persnamebuf[MAXLEN_PERSONALITY_NAME] = {0};
        ostream_to_buf_t o_persname = {0};
        gta_personality_enum_flags_t pers_flag = GTA_PERSONALITY_ENUM_ALL;

        if (EXIT_SUCCESS != parse_pers_flag(&arguments, &pers_flag)) {
            goto cleanup;
        }

        while (b_loop) {
            ostream_to_buf_init(&o_persname, persnamebuf, sizeof(persnamebuf));

            if (gta_personality_enumerate_application(
                    h_inst, arguments.app_name, &h_enum, pers_flag, (gtaio_ostream_t *)&o_persname, &errinfo)) {
                printf("[%d]\n", num_of_personality);
                printf("Personality Name:   %s\n\n", persnamebuf);
                num_of_personality++;
            } else {
                if (errinfo == GTA_ERROR_INVALID_PARAMETER) {
                    fprintf(stderr, "gta_personality_enumerate failed with ERROR_CODE %ld\n", errinfo);
                    fprintf(stderr, "--pers_flag=%s not supported yet\n", arguments.pers_flag);
                }

                b_loop = false;
            }
        }

        break;
    }
    case personality_add_attribute: {
        if (EXIT_SUCCESS != pers_add_attribute(h_inst, h_ctx, &arguments, false)) {
            goto cleanup;
        }
        break;
    }
    case personality_add_trusted_attribute: {
        if (EXIT_SUCCESS != pers_add_attribute(h_inst, h_ctx, &arguments, true)) {
            goto cleanup;
        }
        break;
    }
    case personality_get_attribute: {

        if (NULL == arguments.pers || NULL == arguments.prof || NULL == arguments.attr_name) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        myio_ofilestream_t ostream_attr_value = {0};
        init_ofilestream(&ostream_attr_value);

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);
        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_personality_get_attribute(
                h_ctx, arguments.attr_name, (gtaio_ostream_t *)&ostream_attr_value, &errinfo)) {
            fprintf(stderr, "gta_personality_get_attribute failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }
    case personality_remove_attribute: {

        if (NULL == arguments.pers || NULL == arguments.prof || NULL == arguments.attr_name) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);
        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_personality_remove_attribute(h_ctx, arguments.attr_name, &errinfo)) {
            fprintf(stderr, "gta_personality_remove_attribute failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }
    case personality_attributes_enumerate: {

        if (NULL == arguments.pers) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        int num_of_attribute = 0;
        bool b_loop = true;
        gta_enum_handle_t h_enum = GTA_HANDLE_ENUM_FIRST;

        char attrtypebuf[MAXLEN_ATTRIBUTE] = {0};
        ostream_to_buf_t o_attrtype = {0};
        char attrnamebuf[MAXLEN_ATTRIBUTE] = {0};
        ostream_to_buf_t o_attrname = {0};

        while (b_loop) {
            ostream_to_buf_init(&o_attrtype, attrtypebuf, sizeof(attrtypebuf));
            ostream_to_buf_init(&o_attrname, attrnamebuf, sizeof(attrnamebuf));

            if (gta_personality_attributes_enumerate(
                    h_inst,
                    arguments.pers,
                    &h_enum,
                    (gtaio_ostream_t *)&o_attrtype,
                    (gtaio_ostream_t *)&o_attrname,
                    &errinfo)) {
                printf("[%d]\n", num_of_attribute);
                printf("Attribute Type:   %s\n", attrtypebuf);
                printf("Attribute Name:   %s\n\n", attrnamebuf);
                num_of_attribute++;
            } else {
                b_loop = false;
            }
        }

        break;
    }
    case authenticate_data_detached: {
        if (NULL == arguments.pers || NULL == arguments.prof) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        myio_ofilestream_t ostream_seal = {0};
        init_ofilestream(&ostream_seal);

        if (EXIT_SUCCESS != init_ifilestream(arguments.data, &istream)) {
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);

        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_authenticate_data_detached(
                h_ctx, (gtaio_istream_t *)&istream, (gtaio_ostream_t *)&ostream_seal, &errinfo)) {
            fprintf(stderr, "gta_authenticate_data_detached failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (arguments.data != NULL) {
            myio_close_ifilestream(&istream, &errinfo);
        }
        break;
    }
    case verify_data_detached: {
        if (NULL == arguments.pers || NULL == arguments.prof || NULL == arguments.seal) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        if (EXIT_SUCCESS != init_ifilestream(arguments.data, &istream)) {
            goto cleanup;
        }

        if (EXIT_SUCCESS != init_ifilestream(arguments.seal, &istream_seal)) {
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);

        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_verify_data_detached(h_ctx, (gtaio_istream_t *)&istream, (gtaio_istream_t *)&istream_seal, &errinfo)) {
            fprintf(stderr, "gta_verify_data_detached failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (arguments.data != NULL) {
            myio_close_ifilestream(&istream, &errinfo);
        }

        myio_close_ifilestream(&istream_seal, &errinfo);

        break;
    }
    case personality_enroll: {
        if (NULL == arguments.pers || NULL == arguments.prof) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        myio_ofilestream_t ostream_enrollment_request = {0};
        init_ofilestream(&ostream_enrollment_request);

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);

        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        /* if context attributes were given call gta_context_set_attribute()*/
        /* context attributes given as binary files */
        if (0 < arguments.ctx_attributes_bin.num) {
            for (size_t i = 0; i < arguments.ctx_attributes_bin.num; i++) {
                if (!myio_open_ifilestream(&istream, arguments.ctx_attributes_bin.p_attr[i].p_val, &errinfo)) {
                    printf("Cannot open file %s\n", arguments.ctx_attributes_bin.p_attr[i].p_val);
                    goto cleanup;
                }

                if (!gta_context_set_attribute(
                        h_ctx, arguments.ctx_attributes_bin.p_attr[i].p_type, (gtaio_istream_t *)&istream, &errinfo)) {
                    printf("gta_context_set_attribute failed with ERROR_CODE %ld\n", errinfo);
                    goto cleanup;
                }
                myio_close_ifilestream(&istream, &errinfo);
            }
        }

        /* context attributes given as strings */
        if (0 < arguments.ctx_attributes.num) {
            istream_from_buf_t istream_attr_val = {0};

            for (size_t i = 0; i < arguments.ctx_attributes.num; i++) {
                istream_from_buf_init(
                    &istream_attr_val,
                    arguments.ctx_attributes.p_attr[i].p_val,
                    strnlen(arguments.ctx_attributes.p_attr[i].p_val, MAXLEN_ATTRIBUTE) + 1);

                if (!gta_context_set_attribute(
                        h_ctx,
                        arguments.ctx_attributes.p_attr[i].p_type,
                        (gtaio_istream_t *)&istream_attr_val,
                        &errinfo)) {
                    fprintf(stderr, "gta_context_set_attribute failed with ERROR_CODE %ld\n", errinfo);
                    goto cleanup;
                }
            }
        }

        free_ctx_attributes(&arguments.ctx_attributes);
        free_ctx_attributes(&arguments.ctx_attributes_bin);

        if (!gta_personality_enroll(h_ctx, (gtaio_ostream_t *)&ostream_enrollment_request, &errinfo)) {
            fprintf(stderr, "gta_personality_enroll failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }
    case personality_remove: {
        if (NULL == arguments.pers || NULL == arguments.prof) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        h_ctx = gta_context_open(h_inst, arguments.pers, arguments.prof, &errinfo);

        if (NULL == h_ctx) {
            fprintf(stderr, "gta_context_open failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_personality_remove(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_personality_remove failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_context_close(h_ctx, &errinfo)) {
            fprintf(stderr, "gta_context_close failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }
    case devicestate_transition: {

        if (NULL == arguments.owner_lock_count || GTA_HANDLE_INVALID == arguments.h_auth_recede) {
            fprintf(stderr, "Invalid or missing function arguments\n");
            show_function_help(arguments.func);
            goto cleanup;
        }

        if (!gta_devicestate_transition(h_inst, arguments.h_auth_recede, *arguments.owner_lock_count, &errinfo)) {
            fprintf(stderr, "gta_devicestate_transition failed with ERROR_CODE %ld\n", errinfo);
            free(arguments.owner_lock_count);
            goto cleanup;
        }
        free(arguments.owner_lock_count);

        break;
    }

    case devicestate_recede: {

        gta_access_token_t physical_presence_token;
        if (!gta_access_token_get_physical_presence(h_inst, physical_presence_token, &errinfo)) {
            fprintf(stderr, "gta_access_token_get_physical_presence failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        if (!gta_devicestate_recede(h_inst, physical_presence_token, &errinfo)) {
            fprintf(stderr, "gta_devicestate_recede failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }

        break;
    }

    case access_policy_simple: {

        gta_access_descriptor_type_t access_descriptor_type = GTA_ACCESS_DESCRIPTOR_TYPE_INITIAL;
        gta_access_policy_handle_t h_simple = GTA_HANDLE_INVALID;

        if (EXIT_SUCCESS != parse_descr_type(&arguments, &access_descriptor_type)) {
            goto cleanup;
        }

        h_simple = gta_access_policy_simple(h_inst, access_descriptor_type, &errinfo);
        if (GTA_HANDLE_INVALID == h_simple) {
            fprintf(stderr, "gta_access_policy_simple failed with ERROR_CODE %ld\n", errinfo);
            goto cleanup;
        }
        printf("%" PRIuPTR "\n", (uintptr_t)h_simple);

        break;
    }

    default:
        fprintf(stderr, "Unknown function.\n");
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

cleanup:
    if ((NULL != istream.file) && (stdin != istream.file)) {
        myio_close_ifilestream(&istream, &errinfo);
    }
    if (NULL != istream_seal.file) {
        myio_close_ifilestream(&istream_seal, &errinfo);
    }
    free_ctx_attributes(&arguments.ctx_attributes);
    free_ctx_attributes(&arguments.ctx_attributes_bin);
    if (GTA_HANDLE_INVALID != h_ctx) {
        gta_context_close(h_ctx, &errinfo);
    }
    if (GTA_HANDLE_INVALID != h_inst) {
        gta_instance_final(h_inst, &errinfo);
    }
    return ret;
}
