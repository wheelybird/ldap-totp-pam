/*
 * test_totp.c
 *
 * Unit tests for TOTP validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <liboath/oath.h>
#include "../include/pam_ldap_totp.h"

/* Mock PAM handle for testing */
typedef struct {
  int dummy;
} mock_pam_handle_t;

/* Test 1: Validate known TOTP code */
void test_validate_totp_known_code() {
  /* Known test vector from RFC 6238 */
  const char *secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";  /* Base32 encoded */

  totp_config_t cfg;
  cfg.time_step = 30;
  cfg.window_size = 1;
  cfg.debug = 0;

  /* Decode Base32 secret */
  char *decoded_secret = NULL;
  size_t decoded_len = 0;
  int rc = oath_base32_decode(secret, strlen(secret), &decoded_secret, &decoded_len);
  assert(rc == OATH_OK);

  /* Generate current code */
  char code[7];
  time_t now = time(NULL);

  oath_totp_generate(decoded_secret, decoded_len,
                     now, cfg.time_step, 0, 6, code);

  mock_pam_handle_t pamh;
  int result = validate_totp_code((pam_handle_t*)&pamh, secret, code, &cfg);

  assert(result == 1);  /* Should succeed */

  free(decoded_secret);
  printf("✓ test_validate_totp_known_code passed\n");
}

/* Test 2: Reject invalid code */
void test_validate_totp_invalid_code() {
  const char *secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const char *invalid_code = "000000";

  totp_config_t cfg;
  cfg.time_step = 30;
  cfg.window_size = 1;
  cfg.debug = 0;

  mock_pam_handle_t pamh;
  int result = validate_totp_code((pam_handle_t*)&pamh, secret, invalid_code, &cfg);

  assert(result == 0);  /* Should fail */

  printf("✓ test_validate_totp_invalid_code passed\n");
}

/* Test 3: Test time window tolerance */
void test_validate_totp_window_tolerance() {
  const char *secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  totp_config_t cfg;
  cfg.time_step = 30;
  cfg.window_size = 3;  /* Allow ±3 time steps */
  cfg.debug = 0;

  /* Decode Base32 secret */
  char *decoded_secret = NULL;
  size_t decoded_len = 0;
  int rc = oath_base32_decode(secret, strlen(secret), &decoded_secret, &decoded_len);
  assert(rc == OATH_OK);

  /* Generate code for 90 seconds ago (3 steps back) */
  char code[7];
  time_t past = time(NULL) - 90;

  oath_totp_generate(decoded_secret, decoded_len,
                     past, cfg.time_step, 0, 6, code);

  mock_pam_handle_t pamh;
  int result = validate_totp_code((pam_handle_t*)&pamh, secret, code, &cfg);

  assert(result == 1);  /* Should succeed within window */

  free(decoded_secret);
  printf("✓ test_validate_totp_window_tolerance passed\n");
}

/* Test 4: Validate scratch code format */
void test_validate_scratch_code_format() {
  /* Valid 8-digit scratch code */
  assert(validate_scratch_code("12345678") == 1);

  /* Invalid formats */
  assert(validate_scratch_code("1234567") == 0);   /* Too short */
  assert(validate_scratch_code("123456789") == 0); /* Too long */
  assert(validate_scratch_code("1234567a") == 0);  /* Non-digit */
  assert(validate_scratch_code("") == 0);          /* Empty */
  assert(validate_scratch_code(NULL) == 0);        /* NULL */

  printf("✓ test_validate_scratch_code_format passed\n");
}

/* Test 5: Different time steps */
void test_validate_totp_different_time_steps() {
  const char *secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  /* Test with 60-second time step */
  totp_config_t cfg;
  cfg.time_step = 60;
  cfg.window_size = 1;
  cfg.debug = 0;

  /* Decode Base32 secret */
  char *decoded_secret = NULL;
  size_t decoded_len = 0;
  int rc = oath_base32_decode(secret, strlen(secret), &decoded_secret, &decoded_len);
  assert(rc == OATH_OK);

  char code[7];
  time_t now = time(NULL);

  oath_totp_generate(decoded_secret, decoded_len,
                     now, cfg.time_step, 0, 6, code);

  mock_pam_handle_t pamh;
  int result = validate_totp_code((pam_handle_t*)&pamh, secret, code, &cfg);

  assert(result == 1);

  free(decoded_secret);
  printf("✓ test_validate_totp_different_time_steps passed\n");
}

int main() {
  printf("Running TOTP validation tests...\n\n");

  /* Initialize oath library */
  oath_init();

  test_validate_totp_known_code();
  test_validate_totp_invalid_code();
  test_validate_totp_window_tolerance();
  test_validate_scratch_code_format();
  test_validate_totp_different_time_steps();

  oath_done();

  printf("\n✅ All TOTP validation tests passed!\n");
  return 0;
}
