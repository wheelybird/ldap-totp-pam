/*
 * ldap_query.c
 *
 * LDAP connection and query functions for retrieving TOTP secrets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ldap.h>
#include "../include/pam_ldap_totp.h"

/* Connect to LDAP server */
LDAP *totp_ldap_connect(pam_handle_t *pamh, ldap_config_t *config, totp_config_t *totp_cfg) {
  LDAP *ld = NULL;
  int rc;
  int version = LDAP_VERSION3;

  /* Initialize LDAP connection */
  rc = ldap_initialize(&ld, config->uri);
  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_initialize failed: %s", ldap_err2string(rc));
    return NULL;
  }

  DEBUG_LOG(totp_cfg, "Connecting to LDAP: uri=%s base=%s binddn=%s",
            config->uri, config->base ? config->base : "(null)",
            config->binddn ? config->binddn : "(anonymous)");

  /* Set LDAP version */
  rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_set_option PROTOCOL_VERSION failed: %s",
                ldap_err2string(rc));
    ldap_unbind_ext_s(ld, NULL, NULL);
    return NULL;
  }

  /* Configure TLS */
  if (config->use_tls == 1) {
    /* StartTLS */
    rc = ldap_start_tls_s(ld, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_start_tls_s failed: %s", ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
  }

  if (config->tls_reqcert == 0) {
    int reqcert = LDAP_OPT_X_TLS_NEVER;
    ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
  }

  if (config->tls_cacertfile) {
    ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, config->tls_cacertfile);
  }

  /* Bind to LDAP */
  if (config->binddn && config->bindpw) {
    struct berval cred;
    cred.bv_val = config->bindpw;
    cred.bv_len = strlen(config->bindpw);

    rc = ldap_sasl_bind_s(ld, config->binddn, LDAP_SASL_SIMPLE, &cred,
                           NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_sasl_bind_s failed: %s", ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
  }
  else {
    /* Anonymous bind */
    rc = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_SIMPLE, NULL, NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "ldap_sasl_bind_s (anonymous) failed: %s",
                  ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return NULL;
    }
  }

  return ld;
}

/* Disconnect from LDAP */
void totp_ldap_disconnect(LDAP *ld) {
  if (ld) {
    ldap_unbind_ext_s(ld, NULL, NULL);
  }
}

/* Get TOTP secret from LDAP */
char *ldap_get_totp_secret(pam_handle_t *pamh, LDAP *ld, const char *username,
                            ldap_config_t *ldap_cfg, totp_config_t *totp_cfg) {
  int rc;
  char filter[256];
  char *attrs[] = { totp_cfg->totp_attribute, NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  char *secret = NULL;
  size_t prefix_len = strlen(totp_cfg->totp_prefix);

  /* Build search filter (uid=username) */
  snprintf(filter, sizeof(filter), "(uid=%s)", username);

  DEBUG_LOG(totp_cfg, "LDAP search: base='%s' filter='%s' attr='%s'",
            ldap_cfg->base, filter, totp_cfg->totp_attribute);

  /* Search for user */
  rc = ldap_search_ext_s(ld, ldap_cfg->base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return NULL;
  }

  int count = ldap_count_entries(ld, result);
  DEBUG_LOG(totp_cfg, "LDAP search returned %d entries", count);

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    pam_syslog(pamh, LOG_NOTICE, "User %s not found in LDAP", username);
    ldap_msgfree(result);
    return NULL;
  }

  char *dn = ldap_get_dn(ld, entry);
  DEBUG_LOG(totp_cfg, "Found user DN: %s", dn ? dn : "(null)");
  if (dn) ldap_memfree(dn);

  /* Get attribute values */
  DEBUG_LOG(totp_cfg, "Requesting attribute '%s' with prefix '%s' (len=%zu)",
            totp_cfg->totp_attribute, totp_cfg->totp_prefix, prefix_len);
  values = ldap_get_values_len(ld, entry, totp_cfg->totp_attribute);
  if (!values) {
    /* Check LDAP error - ldap_get_values_len doesn't set specific errors, just returns NULL */
    DEBUG_LOG(totp_cfg, "ldap_get_values_len returned NULL for '%s' attribute (attribute not found or no values)",
              totp_cfg->totp_attribute);

    /* List all attributes in entry for debugging */
    if (totp_cfg->debug) {
      BerElement *ber = NULL;
      char *attr = ldap_first_attribute(ld, entry, &ber);
      DEBUG_LOG(totp_cfg, "Available attributes in entry:");
      while (attr) {
        DEBUG_LOG(totp_cfg, "  - %s", attr);
        ldap_memfree(attr);
        attr = ldap_next_attribute(ld, entry, ber);
      }
      if (ber) ber_free(ber, 0);
    }
    ldap_msgfree(result);
    return NULL;
  }

  DEBUG_LOG(totp_cfg, "Found %d value(s) for %s attribute",
            ldap_count_values_len(values), totp_cfg->totp_attribute);

  /* Find TOTP secret in values */
  for (int i = 0; values[i] != NULL; i++) {
    DEBUG_LOG(totp_cfg, "Checking value %d: length=%lu prefix_len=%lu",
              i, (unsigned long)values[i]->bv_len, (unsigned long)prefix_len);

    if (strncmp(values[i]->bv_val, totp_cfg->totp_prefix, prefix_len) == 0) {
      DEBUG_LOG(totp_cfg, "Prefix match found");
      /* Found TOTP secret */
      char *secret_start = values[i]->bv_val + prefix_len;
      char *colon = strchr(secret_start, ':');

      if (colon) {
        /* Extract secret up to next colon */
        size_t secret_len = colon - secret_start;
        secret = strndup(secret_start, secret_len);
      }
      else {
        /* No options, use rest of string */
        secret = strdup(secret_start);
      }

      DEBUG_LOG(totp_cfg, "Found TOTP secret for user %s (length: %lu)",
                username, (unsigned long)(secret ? strlen(secret) : 0));
      break;
    }
  }

  if (!secret) {
    DEBUG_LOG(totp_cfg, "No matching TOTP secret found (prefix mismatch?)");
  } else {
    DEBUG_LOG(totp_cfg, "Successfully extracted TOTP secret (len=%zu)", strlen(secret));
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  return secret;
}

/* Check if scratch code exists in LDAP (for future use) */
int ldap_check_scratch_code(pam_handle_t *pamh, LDAP *ld, const char *username,
                              const char *code, ldap_config_t *ldap_cfg,
                              totp_config_t *totp_cfg) {
  int rc;
  char filter[256];
  char *attrs[] = { "totpScratchCode", NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  int found = 0;

  /* Build search filter */
  snprintf(filter, sizeof(filter), "(uid=%s)", username);

  /* Search for user */
  rc = ldap_search_ext_s(ld, ldap_cfg->base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return 0;
  }

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    ldap_msgfree(result);
    return 0;
  }

  /* Get attribute values */
  values = ldap_get_values_len(ld, entry, "totpScratchCode");
  if (!values) {
    DEBUG_LOG(totp_cfg, "No scratch codes found for user %s", username);
    ldap_msgfree(result);
    return 0;
  }

  /* Look for matching scratch code */
  char *user_dn = NULL;
  for (int i = 0; values[i] != NULL; i++) {
    if (strcmp(values[i]->bv_val, code) == 0) {
      found = 1;
      DEBUG_LOG(totp_cfg, "Found matching scratch code for user %s", username);

      /* Get user DN for modification */
      user_dn = ldap_get_dn(ld, entry);
      break;
    }
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  /* Remove the used scratch code from LDAP (single-use enforcement) */
  if (found && user_dn) {
    LDAPMod mod;
    LDAPMod *mods[2];
    struct berval bval;
    struct berval *bvals[2];

    /* Prepare the modification to delete this specific scratch code */
    bval.bv_val = (char *)code;
    bval.bv_len = strlen(code);
    bvals[0] = &bval;
    bvals[1] = NULL;

    mod.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
    mod.mod_type = "totpScratchCode";
    mod.mod_bvalues = bvals;

    mods[0] = &mod;
    mods[1] = NULL;

    rc = ldap_modify_ext_s(ld, user_dn, mods, NULL, NULL);
    if (rc == LDAP_SUCCESS) {
      DEBUG_LOG(totp_cfg, "Successfully removed used scratch code for user %s", username);
      pam_syslog(pamh, LOG_NOTICE, "Removed used scratch code for user %s", username);
    } else {
      pam_syslog(pamh, LOG_WARNING, "Failed to remove scratch code for user %s: %s",
                 username, ldap_err2string(rc));
      /* Don't fail authentication if removal fails - code was still valid */
    }

    ldap_memfree(user_dn);
  }

  return found;
}

/* Generic function to retrieve any LDAP attribute for a user */
char *ldap_get_attribute(pam_handle_t *pamh, LDAP *ld, const char *username,
                          const char *attribute, ldap_config_t *ldap_cfg) {
  int rc;
  char filter[256];
  char *attrs[] = { (char *)attribute, NULL };
  LDAPMessage *result = NULL;
  LDAPMessage *entry;
  struct berval **values;
  char *value = NULL;

  /* Build search filter (uid=username) */
  snprintf(filter, sizeof(filter), "(uid=%s)", username);

  /* Search for user */
  rc = ldap_search_ext_s(ld, ldap_cfg->base, LDAP_SCOPE_SUBTREE,
                          filter, attrs, 0, NULL, NULL, NULL,
                          LDAP_NO_LIMIT, &result);

  if (rc != LDAP_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "ldap_search_ext_s failed: %s", ldap_err2string(rc));
    return NULL;
  }

  /* Get first entry */
  entry = ldap_first_entry(ld, result);
  if (!entry) {
    ldap_msgfree(result);
    return NULL;
  }

  /* Get attribute values */
  values = ldap_get_values_len(ld, entry, attribute);
  if (!values) {
    ldap_msgfree(result);
    return NULL;
  }

  /* Get first value */
  if (values[0] != NULL) {
    value = strndup(values[0]->bv_val, values[0]->bv_len);
  }

  ldap_value_free_len(values);
  ldap_msgfree(result);

  return value;
}
