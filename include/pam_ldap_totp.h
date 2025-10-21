/*
 * pam_ldap_totp.h
 *
 * PAM module for LDAP-backed TOTP authentication
 * Retrieves TOTP secrets from LDAP and validates OTP codes
 */

#ifndef PAM_LDAP_TOTP_H
#define PAM_LDAP_TOTP_H

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <ldap.h>
#include <liboath/oath.h>

/* Authentication mode enumeration */
typedef enum {
  TOTP_MODE_APPEND = 0,        /* Traditional: password+TOTP appended (default) */
  TOTP_MODE_CHALLENGE,         /* Challenge-response: separate TOTP prompt */
  TOTP_MODE_WEB                /* Web-based deferred authentication */
} totp_mode_e;

/* Configuration structure */
typedef struct {
  totp_mode_e totp_mode;       /* Authentication mode (default: TOTP_MODE_APPEND) */
  char *challenge_prompt;      /* Prompt text for challenge-response mode */
  char *web_auth_script;       /* Path to deferred auth script for web mode */
  char *totp_attribute;        /* LDAP attribute containing TOTP secret */
  char *totp_prefix;           /* Prefix for TOTP data (e.g., "TOTP-SECRET:") */
  char *scratch_prefix;        /* Prefix for scratch codes */
  int fallback_to_file;        /* Fallback to file-based authenticator */
  int time_step;               /* TOTP time step (default: 30) */
  int window_size;             /* Time window tolerance (default: 3) */
  int grace_period_days;       /* Grace period for MFA setup (default: 7) */
  char *enforcement_mode;      /* Enforcement mode: strict, graceful, warn_only */
  char *setup_service_dn;      /* Service DN allowed during setup */
  char *nslcd_conf_file;       /* Path to nslcd.conf (optional, default: /etc/nslcd.conf) */
  int debug;                   /* Enable debug logging */
} totp_config_t;

/* LDAP configuration from nslcd.conf */
typedef struct {
  char *uri;                   /* LDAP server URI */
  char *base;                  /* Search base DN */
  char *binddn;                /* Bind DN for LDAP connection */
  char *bindpw;                /* Bind password */
  int use_tls;                 /* Use TLS/StartTLS */
  int tls_reqcert;             /* TLS certificate validation */
  char *tls_cacertfile;        /* CA certificate file */
} ldap_config_t;

/* Function prototypes */

/* config.c - Configuration parsing */
int parse_totp_config(const char *config_file, totp_config_t *config);
int parse_ldap_config_from_file(const char *config_file, ldap_config_t *config);
int parse_combined_config(const char *totp_config_file, totp_config_t *totp_config, ldap_config_t *ldap_config);
void free_totp_config(totp_config_t *config);
void free_ldap_config(ldap_config_t *config);

/* ldap_query.c - LDAP operations */
LDAP *totp_ldap_connect(pam_handle_t *pamh, ldap_config_t *config, totp_config_t *totp_cfg);
char *ldap_get_totp_secret(pam_handle_t *pamh, LDAP *ld, const char *username,
                            ldap_config_t *ldap_cfg, totp_config_t *totp_cfg);
char *ldap_get_attribute(pam_handle_t *pamh, LDAP *ld, const char *username,
                          const char *attribute, ldap_config_t *ldap_cfg);
int ldap_check_scratch_code(pam_handle_t *pamh, LDAP *ld, const char *username,
                              const char *code, ldap_config_t *ldap_cfg,
                              totp_config_t *totp_cfg);
void totp_ldap_disconnect(LDAP *ld);

/* totp_validate.c - TOTP validation */
int validate_totp_code(pam_handle_t *pamh, const char *secret, const char *code,
                        totp_config_t *config);
int validate_scratch_code(const char *code);

/* pam_ldap_totp.c - Main PAM module */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                int argc, const char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv);

/* Utility macros */
#define TOTP_CONFIG_FILE "/etc/security/pam_ldap_totp.conf"
#define NSLCD_CONFIG_FILE "/etc/nslcd.conf"
#define FILE_BASED_OTP_DIR "/etc/openvpn/otp"

/* Info logging macro - always outputs to stderr for Docker logs visibility */
#define INFO_LOG(fmt, ...) \
  do { \
    fprintf(stderr, "[PAM_LDAP_TOTP] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
  } while(0)

/* Debug logging macro - outputs to stderr when debug enabled */
#define DEBUG_LOG(cfg, fmt, ...) \
  do { \
    if ((cfg)->debug) { \
      fprintf(stderr, "[PAM_LDAP_TOTP:DEBUG] " fmt "\n", ##__VA_ARGS__); \
      fflush(stderr); \
    } \
  } while(0)

#endif /* PAM_LDAP_TOTP_H */
