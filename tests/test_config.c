/*
 * test_config.c
 *
 * Unit tests for configuration parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../include/pam_ldap_totp.h"

/* Test helper: create temporary config file */
static char *create_temp_config(const char *content) {
  static char template[] = "/tmp/pam_ldap_totp_test_XXXXXX";
  char *filename = strdup(template);
  int fd = mkstemp(filename);
  if (fd == -1) {
    free(filename);
    return NULL;
  }

  write(fd, content, strlen(content));
  close(fd);
  return filename;
}

/* Test 1: Parse basic TOTP configuration */
void test_parse_totp_config_basic() {
  const char *config =
    "totp_mode append\n"
    "totp_attribute totpSecret\n"
    "time_step 30\n"
    "window_size 3\n"
    "debug false\n";

  char *config_file = create_temp_config(config);
  assert(config_file != NULL);

  totp_config_t cfg;
  int result = parse_totp_config(config_file, &cfg);

  assert(result == 0);
  assert(cfg.totp_mode == TOTP_MODE_APPEND);
  assert(strcmp(cfg.totp_attribute, "totpSecret") == 0);
  assert(cfg.time_step == 30);
  assert(cfg.window_size == 3);
  assert(cfg.debug == 0);

  free_totp_config(&cfg);
  unlink(config_file);
  free(config_file);

  printf("✓ test_parse_totp_config_basic passed\n");
}

/* Test 2: Parse challenge mode */
void test_parse_totp_config_challenge_mode() {
  const char *config =
    "totp_mode challenge\n"
    "challenge_prompt Enter your TOTP code:\n";

  char *config_file = create_temp_config(config);
  assert(config_file != NULL);

  totp_config_t cfg;
  parse_totp_config(config_file, &cfg);

  assert(cfg.totp_mode == TOTP_MODE_CHALLENGE);
  assert(strcmp(cfg.challenge_prompt, "Enter your TOTP code:") == 0);

  free_totp_config(&cfg);
  unlink(config_file);
  free(config_file);

  printf("✓ test_parse_totp_config_challenge_mode passed\n");
}

/* Test 3: Parse nslcd_conf_file option */
void test_parse_nslcd_conf_file_option() {
  const char *config =
    "totp_mode append\n"
    "nslcd_conf_file /usr/local/etc/nslcd.conf\n";

  char *config_file = create_temp_config(config);
  assert(config_file != NULL);

  totp_config_t cfg;
  parse_totp_config(config_file, &cfg);

  assert(cfg.nslcd_conf_file != NULL);
  assert(strcmp(cfg.nslcd_conf_file, "/usr/local/etc/nslcd.conf") == 0);

  free_totp_config(&cfg);
  unlink(config_file);
  free(config_file);

  printf("✓ test_parse_nslcd_conf_file_option passed\n");
}

/* Test 4: Parse LDAP configuration */
void test_parse_ldap_config() {
  const char *config =
    "uri ldap://ldap.example.com\n"
    "base dc=example,dc=com\n"
    "binddn cn=admin,dc=example,dc=com\n"
    "bindpw secretpassword\n"
    "ssl start_tls\n"
    "tls_reqcert yes\n";

  char *config_file = create_temp_config(config);
  assert(config_file != NULL);

  ldap_config_t cfg;
  parse_ldap_config_from_file(config_file, &cfg);

  assert(strcmp(cfg.uri, "ldap://ldap.example.com") == 0);
  assert(strcmp(cfg.base, "dc=example,dc=com") == 0);
  assert(strcmp(cfg.binddn, "cn=admin,dc=example,dc=com") == 0);
  assert(strcmp(cfg.bindpw, "secretpassword") == 0);
  assert(cfg.use_tls == 1);  /* start_tls */
  assert(cfg.tls_reqcert == 1);

  free_ldap_config(&cfg);
  unlink(config_file);
  free(config_file);

  printf("✓ test_parse_ldap_config passed\n");
}

/* Test 5: Parse combined configuration */
void test_parse_combined_config() {
  /* Create a nslcd.conf file */
  const char *nslcd_content =
    "uri ldap://ldap.example.com\n"
    "base dc=example,dc=com\n";

  char *nslcd_file = create_temp_config(nslcd_content);
  assert(nslcd_file != NULL);

  /* Create pam_ldap_totp.conf with override */
  char totp_content[512];
  snprintf(totp_content, sizeof(totp_content),
    "totp_mode append\n"
    "nslcd_conf_file %s\n"
    "uri ldap://override.example.com\n", /* Override uri */
    nslcd_file);

  char *totp_file = create_temp_config(totp_content);
  assert(totp_file != NULL);

  totp_config_t totp_cfg;
  ldap_config_t ldap_cfg;
  parse_combined_config(totp_file, &totp_cfg, &ldap_cfg);

  /* LDAP uri should be overridden */
  assert(strcmp(ldap_cfg.uri, "ldap://override.example.com") == 0);
  /* Base should come from nslcd.conf */
  assert(strcmp(ldap_cfg.base, "dc=example,dc=com") == 0);
  /* TOTP mode should be set */
  assert(totp_cfg.totp_mode == TOTP_MODE_APPEND);

  free_totp_config(&totp_cfg);
  free_ldap_config(&ldap_cfg);
  unlink(nslcd_file);
  unlink(totp_file);
  free(nslcd_file);
  free(totp_file);

  printf("✓ test_parse_combined_config passed\n");
}

/* Test 6: Quoted values */
void test_parse_quoted_values() {
  const char *config =
    "challenge_prompt \"Enter TOTP code: \"\n"
    "totp_prefix 'TOTP-SECRET:'\n";

  char *config_file = create_temp_config(config);
  assert(config_file != NULL);

  totp_config_t cfg;
  parse_totp_config(config_file, &cfg);

  assert(strcmp(cfg.challenge_prompt, "Enter TOTP code: ") == 0);
  assert(strcmp(cfg.totp_prefix, "TOTP-SECRET:") == 0);

  free_totp_config(&cfg);
  unlink(config_file);
  free(config_file);

  printf("✓ test_parse_quoted_values passed\n");
}

/* Test 7: Default values */
void test_default_values() {
  totp_config_t cfg;
  parse_totp_config("/nonexistent/file", &cfg);

  /* Should have defaults */
  assert(cfg.totp_mode == TOTP_MODE_APPEND);
  assert(cfg.time_step == 30);
  assert(cfg.window_size == 3);
  assert(cfg.grace_period_days == 7);
  assert(cfg.debug == 0);
  assert(strcmp(cfg.totp_attribute, "totpSecret") == 0);

  free_totp_config(&cfg);

  printf("✓ test_default_values passed\n");
}

int main() {
  printf("Running configuration parsing tests...\n\n");

  test_parse_totp_config_basic();
  test_parse_totp_config_challenge_mode();
  test_parse_nslcd_conf_file_option();
  test_parse_ldap_config();
  test_parse_combined_config();
  test_parse_quoted_values();
  test_default_values();

  printf("\n✅ All configuration tests passed!\n");
  return 0;
}
