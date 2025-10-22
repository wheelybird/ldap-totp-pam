/*
 * config.c
 *
 * Configuration file parsing for PAM LDAP TOTP module
 * Parses both nslcd.conf and pam_ldap_totp.conf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include "../include/pam_ldap_totp.h"

/* Trim whitespace from string */
static char *trim_whitespace(char *str) {
  char *end;

  /* Trim leading space */
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0) return str;

  /* Trim trailing space */
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  end[1] = '\0';
  return str;
}

/* Strip surrounding quotes from string (modifies in place) */
static char *strip_quotes(char *str) {
  size_t len = strlen(str);

  /* Check if string is quoted with double quotes */
  if (len >= 2 && str[0] == '"' && str[len-1] == '"') {
    str[len-1] = '\0';  /* Remove trailing quote */
    return str + 1;      /* Skip leading quote */
  }

  /* Check if string is quoted with single quotes */
  if (len >= 2 && str[0] == '\'' && str[len-1] == '\'') {
    str[len-1] = '\0';  /* Remove trailing quote */
    return str + 1;      /* Skip leading quote */
  }

  return str;
}

/* Parse TOTP configuration file */
int parse_totp_config(const char *config_file, totp_config_t *config) {
  FILE *fp;
  char line[256];
  char key[64], value[192];

  /* Set defaults */
  memset(config, 0, sizeof(totp_config_t));
  config->totp_mode = TOTP_MODE_APPEND; /* Default: traditional append mode */
  config->challenge_prompt = strdup("Enter TOTP code: ");
  config->web_auth_script = strdup("/usr/local/bin/pam_ldap_totp_deferred.sh");
  config->totp_attribute = strdup("totpSecret");
  config->scratch_attribute = strdup("totpScratchCode");
  config->status_attribute = strdup("totpStatus");
  config->enrolled_date_attribute = strdup("totpEnrolledDate");
  config->totp_prefix = strdup("");
  config->scratch_prefix = strdup("TOTP-SCRATCH:");
  config->fallback_to_file = 0;
  config->time_step = 30;
  config->window_size = 3;
  config->grace_period_days = 7;
  config->enforcement_mode = strdup("graceful");
  config->setup_service_dn = NULL;
  config->nslcd_conf_file = NULL;  /* NULL means use default /etc/nslcd.conf if needed */
  config->debug = 0;

  fp = fopen(config_file, "r");
  if (!fp) {
    /* Config file not found, use defaults */
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim_whitespace(line);

    /* Skip comments and empty lines */
    if (trimmed[0] == '#' || trimmed[0] == '\0') {
      continue;
    }

    /* Parse key=value */
    if (sscanf(trimmed, "%63s %191[^\n]", key, value) == 2) {
      char *trimmed_value = trim_whitespace(value);
      trimmed_value = strip_quotes(trimmed_value);

      if (strcmp(key, "totp_mode") == 0) {
        if (strcmp(trimmed_value, "append") == 0) {
          config->totp_mode = TOTP_MODE_APPEND;
        }
        else if (strcmp(trimmed_value, "challenge_response") == 0 ||
                 strcmp(trimmed_value, "challenge") == 0) {
          config->totp_mode = TOTP_MODE_CHALLENGE;
        }
        else if (strcmp(trimmed_value, "web_auth") == 0 ||
                 strcmp(trimmed_value, "web") == 0) {
          config->totp_mode = TOTP_MODE_WEB;
        }
      }
      else if (strcmp(key, "challenge_prompt") == 0) {
        free(config->challenge_prompt);
        config->challenge_prompt = strdup(trimmed_value);
      }
      else if (strcmp(key, "web_auth_script") == 0) {
        free(config->web_auth_script);
        config->web_auth_script = strdup(trimmed_value);
      }
      else if (strcmp(key, "totp_attribute") == 0) {
        if (!is_valid_ldap_attribute(trimmed_value)) {
          syslog(LOG_ERR, "Invalid LDAP attribute name: %s", trimmed_value);
          continue;
        }
        free(config->totp_attribute);
        config->totp_attribute = strdup(trimmed_value);
      }
      else if (strcmp(key, "scratch_attribute") == 0) {
        if (!is_valid_ldap_attribute(trimmed_value)) {
          syslog(LOG_ERR, "Invalid LDAP attribute name: %s", trimmed_value);
          continue;
        }
        free(config->scratch_attribute);
        config->scratch_attribute = strdup(trimmed_value);
      }
      else if (strcmp(key, "status_attribute") == 0) {
        if (!is_valid_ldap_attribute(trimmed_value)) {
          syslog(LOG_ERR, "Invalid LDAP attribute name: %s", trimmed_value);
          continue;
        }
        free(config->status_attribute);
        config->status_attribute = strdup(trimmed_value);
      }
      else if (strcmp(key, "enrolled_date_attribute") == 0) {
        if (!is_valid_ldap_attribute(trimmed_value)) {
          syslog(LOG_ERR, "Invalid LDAP attribute name: %s", trimmed_value);
          continue;
        }
        free(config->enrolled_date_attribute);
        config->enrolled_date_attribute = strdup(trimmed_value);
      }
      else if (strcmp(key, "totp_prefix") == 0) {
        free(config->totp_prefix);
        config->totp_prefix = strdup(trimmed_value);
      }
      else if (strcmp(key, "scratch_prefix") == 0) {
        free(config->scratch_prefix);
        config->scratch_prefix = strdup(trimmed_value);
      }
      else if (strcmp(key, "fallback_to_file") == 0) {
        config->fallback_to_file = (strcmp(trimmed_value, "true") == 0 ||
                                     strcmp(trimmed_value, "1") == 0);
      }
      else if (strcmp(key, "time_step") == 0) {
        config->time_step = atoi(trimmed_value);
      }
      else if (strcmp(key, "window_size") == 0) {
        config->window_size = atoi(trimmed_value);
      }
      else if (strcmp(key, "grace_period_days") == 0) {
        config->grace_period_days = atoi(trimmed_value);
      }
      else if (strcmp(key, "enforcement_mode") == 0) {
        free(config->enforcement_mode);
        config->enforcement_mode = strdup(trimmed_value);
      }
      else if (strcmp(key, "setup_service_dn") == 0) {
        if (config->setup_service_dn) free(config->setup_service_dn);
        config->setup_service_dn = strdup(trimmed_value);
      }
      else if (strcmp(key, "nslcd_conf_file") == 0) {
        if (config->nslcd_conf_file) free(config->nslcd_conf_file);
        config->nslcd_conf_file = strdup(trimmed_value);
      }
      else if (strcmp(key, "debug") == 0) {
        config->debug = (strcmp(trimmed_value, "true") == 0 ||
                         strcmp(trimmed_value, "1") == 0);
      }
      /* Note: LDAP settings (uri, base, binddn, etc.) are ignored here */
      /* They should be parsed via parse_ldap_config_from_file() or parse_combined_config() */
    }
  }

  fclose(fp);
  return 0;
}

/* Parse LDAP configuration from any config file (nslcd.conf format or pam_ldap_totp.conf) */
int parse_ldap_config_from_file(const char *config_file, ldap_config_t *config) {
  FILE *fp;
  char line[512];
  char key[64], value[448];

  /* Set defaults */
  memset(config, 0, sizeof(ldap_config_t));
  config->uri = strdup("ldap://localhost");
  config->base = strdup("dc=example,dc=com");
  config->use_tls = 0;
  config->tls_reqcert = 0;

  fp = fopen(config_file, "r");
  if (!fp) {
    /* Config file not found, use defaults */
    return 0;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim_whitespace(line);

    /* Skip comments and empty lines */
    if (trimmed[0] == '#' || trimmed[0] == '\0') {
      continue;
    }

    /* Parse key value */
    if (sscanf(trimmed, "%63s %447[^\n]", key, value) == 2) {
      char *trimmed_value = trim_whitespace(value);
      trimmed_value = strip_quotes(trimmed_value);

      if (strcmp(key, "uri") == 0) {
        free(config->uri);
        config->uri = strdup(trimmed_value);
      }
      else if (strcmp(key, "base") == 0) {
        free(config->base);
        config->base = strdup(trimmed_value);
      }
      else if (strcmp(key, "binddn") == 0) {
        if (config->binddn) free(config->binddn);
        config->binddn = strdup(trimmed_value);
      }
      else if (strcmp(key, "bindpw") == 0) {
        if (config->bindpw) free(config->bindpw);
        config->bindpw = strdup(trimmed_value);
      }
      else if (strcmp(key, "ssl") == 0) {
        if (strcmp(trimmed_value, "start_tls") == 0) {
          config->use_tls = 1;
        }
        else if (strcmp(trimmed_value, "on") == 0) {
          config->use_tls = 2; /* LDAPS */
        }
      }
      else if (strcmp(key, "tls_reqcert") == 0) {
        if (strcmp(trimmed_value, "never") == 0 ||
            strcmp(trimmed_value, "no") == 0) {
          config->tls_reqcert = 0;
        }
        else {
          config->tls_reqcert = 1;
        }
      }
      else if (strcmp(key, "tls_cacertfile") == 0) {
        if (config->tls_cacertfile) free(config->tls_cacertfile);
        config->tls_cacertfile = strdup(trimmed_value);
      }
    }
  }

  fclose(fp);
  return 0;
}

/* Parse combined configuration - reads both TOTP and LDAP settings
 *
 * Priority order:
 * 1. Read LDAP settings from nslcd.conf (if nslcd_conf_file is set or /etc/nslcd.conf exists)
 * 2. Read TOTP settings from pam_ldap_totp.conf
 * 3. Override LDAP settings with any found in pam_ldap_totp.conf
 *
 * This allows users to:
 * - Use nslcd.conf for LDAP settings (set nslcd_conf_file or leave default)
 * - Put everything in pam_ldap_totp.conf (comment out LDAP settings to use nslcd.conf)
 * - Override specific LDAP settings in pam_ldap_totp.conf while using nslcd.conf for others
 */
int parse_combined_config(const char *totp_config_file, totp_config_t *totp_config, ldap_config_t *ldap_config) {
  /* First, parse TOTP config (this sets nslcd_conf_file if specified) */
  parse_totp_config(totp_config_file, totp_config);

  /* Initialize LDAP config with defaults */
  memset(ldap_config, 0, sizeof(ldap_config_t));
  ldap_config->uri = strdup("ldap://localhost");
  ldap_config->base = strdup("dc=example,dc=com");
  ldap_config->use_tls = 0;
  ldap_config->tls_reqcert = 0;

  /* Determine nslcd.conf path */
  const char *nslcd_path = totp_config->nslcd_conf_file ?
                           totp_config->nslcd_conf_file :
                           "/etc/nslcd.conf";

  /* Try to read LDAP settings from nslcd.conf if it exists */
  FILE *fp = fopen(nslcd_path, "r");
  if (fp) {
    fclose(fp);
    parse_ldap_config_from_file(nslcd_path, ldap_config);
  }

  /* Now parse LDAP settings from pam_ldap_totp.conf (these override nslcd.conf) */
  parse_ldap_config_from_file(totp_config_file, ldap_config);

  return 0;
}

/* Free TOTP configuration */
void free_totp_config(totp_config_t *config) {
  if (config->challenge_prompt) free(config->challenge_prompt);
  if (config->web_auth_script) free(config->web_auth_script);
  if (config->totp_attribute) free(config->totp_attribute);
  if (config->scratch_attribute) free(config->scratch_attribute);
  if (config->status_attribute) free(config->status_attribute);
  if (config->enrolled_date_attribute) free(config->enrolled_date_attribute);
  if (config->totp_prefix) free(config->totp_prefix);
  if (config->scratch_prefix) free(config->scratch_prefix);
  if (config->enforcement_mode) free(config->enforcement_mode);
  if (config->setup_service_dn) free(config->setup_service_dn);
  if (config->nslcd_conf_file) free(config->nslcd_conf_file);
}

/* Free LDAP configuration */
void free_ldap_config(ldap_config_t *config) {
  if (config->uri) free(config->uri);
  if (config->base) free(config->base);
  if (config->binddn) free(config->binddn);
  if (config->bindpw) free(config->bindpw);
  if (config->tls_cacertfile) free(config->tls_cacertfile);
}
