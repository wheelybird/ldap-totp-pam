/*
 * pam_ldap_totp.c
 *
 * Main PAM module for LDAP-backed TOTP authentication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "../include/pam_ldap_totp.h"

/* Extract OTP from password (assumes last 6 or 8 digits) */
static int extract_otp_from_password(const char *full_password, char **password, char **otp) {
  /* Input validation */
  if (!full_password || !password || !otp) {
    return 0;
  }

  size_t len = strlen(full_password);

  /* Trim whitespace from both ends - standard practice for authentication input */
  const char *start = full_password;
  const char *end = full_password + len - 1;

  /* Strip leading whitespace */
  while (len > 0 && (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')) {
    start++;
    len--;
  }

  /* Strip trailing whitespace */
  while (len > 0 && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
    end--;
    len--;
  }

  if (len == 0) {
    return 0;
  }

  /* Sanity check: password too long indicates potential attack */
  if (len > 512) {
    return 0;
  }

  /* Create trimmed copy for safer substring operations */
  char *trimmed = strndup(start, len);
  if (!trimmed) {
    return 0;
  }

  /* Try 6-digit OTP first (standard TOTP) - most common case */
  if (len > 6) {
    size_t pass_len = len - 6;
    const char *otp_start = trimmed + pass_len;

    /* Check if last 6 chars are digits */
    int all_digits = 1;
    for (int i = 0; i < 6; i++) {
      if (otp_start[i] < '0' || otp_start[i] > '9') {
        all_digits = 0;
        break;
      }
    }

    if (all_digits) {
      *password = strndup(trimmed, pass_len);
      *otp = strdup(otp_start);
      free(trimmed);

      /* Validate allocations succeeded */
      if (!*password || !*otp) {
        free(*password);
        free(*otp);
        return 0;
      }
      return 1;
    }
  }

  /* Try 8-digit OTP (scratch/backup code) as fallback */
  if (len > 8) {
    size_t pass_len = len - 8;
    const char *otp_start = trimmed + pass_len;

    /* Check if last 8 chars are digits */
    int all_digits = 1;
    for (int i = 0; i < 8; i++) {
      if (otp_start[i] < '0' || otp_start[i] > '9') {
        all_digits = 0;
        break;
      }
    }

    if (all_digits) {
      *password = strndup(trimmed, pass_len);
      *otp = strdup(otp_start);
      free(trimmed);

      /* Validate allocations succeeded */
      if (!*password || !*otp) {
        free(*password);
        free(*otp);
        return 0;
      }
      return 1;
    }
  }

  free(trimmed);
  return 0;
}

/* Try file-based fallback */
static int try_file_fallback(pam_handle_t *pamh, const char *username, const char *otp) {
  char filepath[512];
  FILE *fp;
  char secret[128];
  totp_config_t config;
  int result = 0;

  /* Validate username to prevent path traversal attacks */
  if (!is_safe_username(username)) {
    pam_syslog(pamh, LOG_ERR, "Unsafe username rejected for file-based fallback: %s", username);
    return 0;
  }

  snprintf(filepath, sizeof(filepath), "%s/%s.google_authenticator",
           FILE_BASED_OTP_DIR, username);

  fp = fopen(filepath, "r");
  if (!fp) {
    pam_syslog(pamh, LOG_NOTICE, "No file-based OTP for user %s", username);
    return 0;
  }

  /* Read secret from first line */
  if (fgets(secret, sizeof(secret), fp)) {
    /* Remove newline */
    secret[strcspn(secret, "\n")] = 0;

    /* Set default config */
    config.time_step = 30;
    config.window_size = 3;
    config.debug = 0;

    /* Validate OTP */
    result = validate_totp_code(pamh, secret, otp, &config);

    if (result) {
      pam_syslog(pamh, LOG_NOTICE, "File-based OTP validated for user %s", username);
    }
  }

  fclose(fp);
  return result;
}

/* Challenge-response authentication mode */
static int authenticate_challenge_response(pam_handle_t *pamh,
                                           const char *username,
                                           totp_config_t *totp_cfg,
                                           ldap_config_t *ldap_cfg) {
  char *otp = NULL;
  int retval = PAM_AUTH_ERR;
  LDAP *ld = NULL;
  char *secret = NULL;

  if (totp_cfg->debug) {
    pam_syslog(pamh, LOG_DEBUG, "Using challenge-response mode for user: %s", username);
  }

  /* Prompt for TOTP code */
  retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &otp, "%s", totp_cfg->challenge_prompt);
  if (retval != PAM_SUCCESS || !otp) {
    pam_syslog(pamh, LOG_ERR, "Failed to get TOTP code via prompt");
    return PAM_AUTH_ERR;
  }

  /* Trim whitespace from OTP */
  char *trimmed_otp = otp;
  while (*trimmed_otp == ' ' || *trimmed_otp == '\t') trimmed_otp++;
  size_t otp_len = strlen(trimmed_otp);
  while (otp_len > 0 && (trimmed_otp[otp_len-1] == ' ' || trimmed_otp[otp_len-1] == '\t')) {
    trimmed_otp[--otp_len] = '\0';
  }

  if (totp_cfg->debug) {
    pam_syslog(pamh, LOG_DEBUG, "Received TOTP code of length %zu", otp_len);
  }

  /* Validate OTP length */
  if (otp_len != 6 && otp_len != 8) {
    pam_syslog(pamh, LOG_NOTICE, "Invalid TOTP code length: %zu (expected 6 or 8)", otp_len);
    SECURE_FREE_STRING(otp);
    return PAM_AUTH_ERR;
  }

  /* Connect to LDAP */
  ld = totp_ldap_connect(pamh, ldap_cfg, totp_cfg);
  if (!ld) {
    pam_syslog(pamh, LOG_ERR, "Failed to connect to LDAP in challenge-response mode");

    /* Try file fallback if enabled */
    if (totp_cfg->fallback_to_file) {
      if (try_file_fallback(pamh, username, trimmed_otp)) {
        SECURE_FREE_STRING(otp);
        return PAM_SUCCESS;
      }
    }

    SECURE_FREE_STRING(otp);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Get TOTP secret from LDAP */
  secret = ldap_get_totp_secret(pamh, ld, username, ldap_cfg, totp_cfg);
  if (!secret) {
    pam_syslog(pamh, LOG_NOTICE, "No TOTP secret found for user %s", username);

    /* Try file fallback if enabled */
    if (totp_cfg->fallback_to_file) {
      totp_ldap_disconnect(ld);
      if (try_file_fallback(pamh, username, trimmed_otp)) {
        SECURE_FREE_STRING(otp);
        return PAM_SUCCESS;
      }
    }

    totp_ldap_disconnect(ld);
    SECURE_FREE_STRING(otp);
    return PAM_AUTH_ERR;
  }

  /* Validate TOTP code */
  if (otp_len == 6) {
    /* Standard 6-digit TOTP */
    if (validate_totp_code(pamh, secret, trimmed_otp, totp_cfg)) {
      pam_syslog(pamh, LOG_NOTICE, "Challenge-response TOTP authentication successful for user %s", username);
      retval = PAM_SUCCESS;
    } else {
      pam_syslog(pamh, LOG_NOTICE, "Challenge-response TOTP authentication failed for user %s", username);
      retval = PAM_AUTH_ERR;
    }
  } else if (otp_len == 8) {
    /* 8-digit backup code */
    if (validate_scratch_code(trimmed_otp)) {
      if (ldap_check_scratch_code(pamh, ld, username, trimmed_otp, ldap_cfg, totp_cfg)) {
        pam_syslog(pamh, LOG_NOTICE, "Challenge-response backup code validated for user %s", username);
        retval = PAM_SUCCESS;
      } else {
        pam_syslog(pamh, LOG_NOTICE, "Challenge-response invalid backup code for user %s", username);
        retval = PAM_AUTH_ERR;
      }
    } else {
      retval = PAM_AUTH_ERR;
    }
  }

  /* Cleanup */
  SECURE_FREE_STRING(secret);
  SECURE_FREE_STRING(otp);
  totp_ldap_disconnect(ld);

  return retval;
}

/* Append mode authentication (traditional password+TOTP) */
static int authenticate_append_mode(pam_handle_t *pamh,
                                    const char *username,
                                    const char *full_password,
                                    totp_config_t *totp_cfg,
                                    ldap_config_t *ldap_cfg) {
  char *password = NULL;
  char *otp = NULL;
  int retval = PAM_AUTH_ERR;
  LDAP *ld = NULL;
  char *secret = NULL;
  char *full_password_copy = NULL;

  INFO_LOG("Authenticating user '%s' in append mode", username);
  DEBUG_LOG(totp_cfg, "Using append mode for user: %s", username);

  /* Save a copy of full_password before any PAM operations that might modify it */
  full_password_copy = strdup(full_password);
  if (!full_password_copy) {
    pam_syslog(pamh, LOG_ERR, "Failed to allocate memory for password copy");
    return PAM_AUTH_ERR;
  }

  /* Extract OTP from password */
  DEBUG_LOG(totp_cfg, "Extracting OTP from password (len=%zu)", strlen(full_password_copy));
  if (!extract_otp_from_password(full_password_copy, &password, &otp)) {
    INFO_LOG("Failed to extract OTP from password for user '%s'", username);
    pam_syslog(pamh, LOG_ERR, "Failed to extract OTP from password");
    SECURE_FREE_STRING(full_password_copy);
    return PAM_AUTH_ERR;
  }
  DEBUG_LOG(totp_cfg, "Extracted password (len=%zu) and OTP (len=%zu)", strlen(password), strlen(otp));

  /* Update PAM with password (without OTP) for next module */
  pam_set_item(pamh, PAM_AUTHTOK, password);

  /* Connect to LDAP */
  DEBUG_LOG(totp_cfg, "Attempting LDAP connection...");
  ld = totp_ldap_connect(pamh, ldap_cfg, totp_cfg);
  if (!ld) {
    INFO_LOG("LDAP connection failed for user '%s'", username);
    pam_syslog(pamh, LOG_ERR, "Failed to connect to LDAP");

    /* Try file fallback if enabled */
    if (totp_cfg->fallback_to_file) {
      if (try_file_fallback(pamh, username, otp)) {
        INFO_LOG("File-based OTP fallback succeeded for user '%s'", username);
        SECURE_FREE_STRING(password);
        SECURE_FREE_STRING(otp);
        SECURE_FREE_STRING(full_password_copy);
        return PAM_SUCCESS;
      }
    }

    SECURE_FREE_STRING(password);
    SECURE_FREE_STRING(otp);
    SECURE_FREE_STRING(full_password_copy);
    return PAM_AUTHINFO_UNAVAIL;
  }
  DEBUG_LOG(totp_cfg, "LDAP connection successful");

  /* Get TOTP secret from LDAP */
  INFO_LOG("Looking up TOTP secret for user '%s'", username);
  DEBUG_LOG(totp_cfg, "Fetching TOTP secret for user: %s", username);
  secret = ldap_get_totp_secret(pamh, ld, username, ldap_cfg, totp_cfg);
  if (!secret) {
    INFO_LOG("No TOTP secret found for user '%s'", username);
    DEBUG_LOG(totp_cfg, "No TOTP secret in LDAP for user %s", username);

    /* Check MFA status for grace period handling */
    char *totp_status = ldap_get_attribute(pamh, ld, username, totp_cfg->status_attribute, ldap_cfg);
    char *enrolled_date = ldap_get_attribute(pamh, ld, username, totp_cfg->enrolled_date_attribute, ldap_cfg);

    if (totp_status && strcmp(totp_status, "pending") == 0) {
      /* User is in grace period - allow without TOTP */
      if (enrolled_date && totp_cfg->grace_period_days > 0) {
        struct tm tm_enrolled = {0};
        int year, month, day, hour, min, sec;
        if (sscanf(enrolled_date, "%4d%2d%2d%2d%2d%2d",
                   &year, &month, &day, &hour, &min, &sec) == 6) {
          /* Validate date components */
          if (!is_valid_date(year, month, day, hour, min, sec)) {
            pam_syslog(pamh, LOG_WARNING, "Invalid enrollment date for user %s", username);
            if (totp_status) free(totp_status);
            if (enrolled_date) free(enrolled_date);
            SECURE_FREE_STRING(password);
            SECURE_FREE_STRING(otp);
            SECURE_FREE_STRING(full_password_copy);
            totp_ldap_disconnect(ld);
            return PAM_AUTH_ERR;
          }

          tm_enrolled.tm_year = year - 1900;
          tm_enrolled.tm_mon = month - 1;
          tm_enrolled.tm_mday = day;
          tm_enrolled.tm_hour = hour;
          tm_enrolled.tm_min = min;
          tm_enrolled.tm_sec = sec;
          time_t enrolled_time = timegm(&tm_enrolled);
          time_t current_time = time(NULL);
          int days_elapsed = (current_time - enrolled_time) / 86400;

          if (days_elapsed < totp_cfg->grace_period_days) {
            pam_syslog(pamh, LOG_NOTICE, "User %s in grace period (%d days remaining)",
                      username, totp_cfg->grace_period_days - days_elapsed);
            if (totp_status) free(totp_status);
            if (enrolled_date) free(enrolled_date);
            SECURE_FREE_STRING(password);
            SECURE_FREE_STRING(otp);
            SECURE_FREE_STRING(full_password_copy);
            totp_ldap_disconnect(ld);
            return PAM_SUCCESS;
          }
        }
      }
    }

    if (totp_status) free(totp_status);
    if (enrolled_date) free(enrolled_date);

    /* Try file fallback if enabled */
    if (totp_cfg->fallback_to_file) {
      if (try_file_fallback(pamh, username, otp)) {
        SECURE_FREE_STRING(password);
        SECURE_FREE_STRING(otp);
        SECURE_FREE_STRING(full_password_copy);
        totp_ldap_disconnect(ld);
        return PAM_SUCCESS;
      }
    }

    pam_syslog(pamh, LOG_NOTICE, "No TOTP configured for user %s", username);
    SECURE_FREE_STRING(password);
    SECURE_FREE_STRING(otp);
    SECURE_FREE_STRING(full_password_copy);
    totp_ldap_disconnect(ld);
    return PAM_AUTH_ERR;
  }

  /* Validate OTP code
   * Smart fallback logic: extraction always gets last 6 digits, but if the
   * original input had 8+ trailing digits and TOTP validation fails, try
   * validating as an 8-digit scratch code.
   */
  DEBUG_LOG(totp_cfg, "Got TOTP secret, validating OTP code (len=%zu)", strlen(otp));

  /* Step 1: Try 6-digit TOTP validation (most common case) */
  DEBUG_LOG(totp_cfg, "Validating 6-digit TOTP code");
  if (validate_totp_code(pamh, secret, otp, totp_cfg)) {
    INFO_LOG("TOTP authentication SUCCEEDED for user '%s'", username);
    pam_syslog(pamh, LOG_NOTICE, "TOTP authentication successful for user %s", username);
    retval = PAM_SUCCESS;
  }
  else {
    /* Step 2: Check if original input has 8+ trailing digits for scratch code fallback */
    size_t full_len = strlen(full_password_copy);
    int has_8_trailing_digits = 0;

    DEBUG_LOG(totp_cfg, "TOTP failed, checking for scratch code fallback (input_len=%zu)", full_len);

    if (full_len >= 8) {
      has_8_trailing_digits = 1;
      for (size_t i = full_len - 8; i < full_len; i++) {
        if (full_password_copy[i] < '0' || full_password_copy[i] > '9') {
          has_8_trailing_digits = 0;
          DEBUG_LOG(totp_cfg, "Non-digit found at position %zu: '%c'", i, full_password_copy[i]);
          break;
        }
      }
    }

    DEBUG_LOG(totp_cfg, "has_8_trailing_digits=%d", has_8_trailing_digits);

    /* Step 3: If 8+ trailing digits exist, try scratch code validation */
    if (has_8_trailing_digits) {
      char scratch_code[9];
      strncpy(scratch_code, &full_password_copy[full_len - 8], 8);
      scratch_code[8] = '\0';

      DEBUG_LOG(totp_cfg, "TOTP validation failed, trying 8-digit scratch code fallback");
      if (validate_scratch_code(scratch_code)) {
        if (ldap_check_scratch_code(pamh, ld, username, scratch_code, ldap_cfg, totp_cfg)) {
          INFO_LOG("Scratch code authentication SUCCEEDED for user '%s' (fallback)", username);
          pam_syslog(pamh, LOG_NOTICE, "Scratch code validated for user %s", username);
          retval = PAM_SUCCESS;
        }
        else {
          INFO_LOG("Scratch code authentication FAILED for user '%s' (code not found or already used)", username);
          pam_syslog(pamh, LOG_NOTICE, "Invalid scratch code for user %s", username);
          retval = PAM_AUTH_ERR;
        }
      }
      else {
        INFO_LOG("TOTP and scratch code both failed for user '%s'", username);
        pam_syslog(pamh, LOG_NOTICE, "TOTP authentication failed for user %s", username);
        retval = PAM_AUTH_ERR;
      }
    }
    else {
      /* No 8-digit fallback possible, TOTP validation simply failed */
      INFO_LOG("TOTP authentication FAILED for user '%s' (invalid code)", username);
      pam_syslog(pamh, LOG_NOTICE, "TOTP authentication failed for user %s", username);
      retval = PAM_AUTH_ERR;
    }
  }

  /* Cleanup */
  SECURE_FREE_STRING(secret);
  SECURE_FREE_STRING(password);
  SECURE_FREE_STRING(otp);
  SECURE_FREE_STRING(full_password_copy);
  totp_ldap_disconnect(ld);

  return retval;
}

/* Main authentication function - routes to appropriate mode */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                     int argc, const char **argv) {
  const char *username = NULL;
  const char *full_password = NULL;
  int retval = PAM_AUTH_ERR;

  totp_config_t totp_cfg;
  ldap_config_t ldap_cfg;

  /* Suppress unused parameter warnings */
  (void)flags;
  (void)argc;
  (void)argv;

  /* Get username */
  retval = pam_get_user(pamh, &username, NULL);
  if (retval != PAM_SUCCESS || !username) {
    INFO_LOG("Failed to get username from PAM");
    pam_syslog(pamh, LOG_ERR, "Failed to get username");
    return PAM_USER_UNKNOWN;
  }

  /* Parse configuration files (reads TOTP config and LDAP config) */
  parse_combined_config(TOTP_CONFIG_FILE, &totp_cfg, &ldap_cfg);

  INFO_LOG("PAM module loaded for user '%s' (mode: %s, debug: %s)",
           username,
           totp_cfg.totp_mode == TOTP_MODE_APPEND ? "append" :
           totp_cfg.totp_mode == TOTP_MODE_CHALLENGE ? "challenge" : "web",
           totp_cfg.debug ? "enabled" : "disabled");
  DEBUG_LOG(&totp_cfg, "Authenticating user: %s (mode: %d)", username, totp_cfg.totp_mode);

  /* Route to appropriate authentication mode */
  if (totp_cfg.totp_mode == TOTP_MODE_CHALLENGE) {
    /* Challenge-response mode: prompt for TOTP separately */
    retval = authenticate_challenge_response(pamh, username, &totp_cfg, &ldap_cfg);
  }
  else if (totp_cfg.totp_mode == TOTP_MODE_WEB) {
    /* Web authentication mode: not supported by PAM directly */
    /* Use OpenVPN's auth-user-pass-verify with deferred auth script instead */
    pam_syslog(pamh, LOG_ERR, "Web authentication mode should be configured via OpenVPN auth-user-pass-verify, not PAM");
    pam_syslog(pamh, LOG_INFO, "For web authentication, use the standalone deferred auth script with OpenVPN");
    retval = PAM_AUTH_ERR;
  }
  else {
    /* Default: Append mode - password+TOTP concatenated */
    DEBUG_LOG(&totp_cfg, "Using append mode");
    /* Get password */
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &full_password, NULL);
    if (retval != PAM_SUCCESS || !full_password) {
      INFO_LOG("Failed to get password from PAM for user '%s'", username);
      pam_syslog(pamh, LOG_ERR, "Failed to get password");
      retval = PAM_AUTH_ERR;
    } else {
      retval = authenticate_append_mode(pamh, username, full_password, &totp_cfg, &ldap_cfg);
    }
  }

  /* Cleanup configuration */
  free_totp_config(&totp_cfg);
  free_ldap_config(&ldap_cfg);

  return retval;
}

/* Set credentials (no-op for this module) */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                int argc, const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

/* Account management (no-op for this module) */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}
