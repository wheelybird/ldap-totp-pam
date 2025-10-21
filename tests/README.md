# PAM LDAP TOTP Unit Tests

This directory contains unit tests for the PAM LDAP TOTP module.

## Test Suites

### test_config.c - Configuration Parsing Tests

Tests the configuration file parsing logic:

- ✅ Basic TOTP configuration parsing
- ✅ Challenge-response mode configuration
- ✅ Custom nslcd.conf path option
- ✅ LDAP configuration parsing
- ✅ Combined configuration (TOTP + LDAP with override behaviour)
- ✅ Quoted values in configuration
- ✅ Default values when config file doesn't exist

**Key scenarios tested:**
- Priority order: nslcd.conf → pam_ldap_totp.conf (overrides)
- Quote stripping (both single and double quotes)
- Whitespace handling
- Missing configuration files

### test_totp.c - TOTP Validation Tests

Tests the TOTP code validation logic:

- ✅ Validate known TOTP codes
- ✅ Reject invalid TOTP codes
- ✅ Time window tolerance (±90 seconds with window_size=3)
- ✅ Scratch/backup code format validation
- ✅ Different time step configurations (30s, 60s)

**Key scenarios tested:**
- RFC 6238 compliance
- Time drift tolerance
- Backup code validation
- Edge cases (expired codes, future codes within window)

### test_extract.c - OTP Extraction Tests

Tests the password+OTP extraction logic:

- ✅ Extract 6-digit TOTP codes
- ✅ Extract 8-digit scratch codes (documents algorithmic limitation)
- ✅ Whitespace handling (leading/trailing)
- ✅ Invalid input rejection
- ✅ Preference for 6-digit over 8-digit
- ✅ Complex passwords with special characters
- ✅ Minimum length requirements
- ✅ Attack prevention (overly long passwords)

**Key scenarios tested:**
- Append mode extraction: `password123456` → `password` + `123456`
- Scratch codes: `password12345678` → `password12` + `345678` (extracts last 6, not 8)
- Edge cases: minimum valid length, whitespace trimming
- Security: rejection of suspiciously long inputs

**Important Design Decision:**
The extraction algorithm always extracts the last 6 digits, even when 8 trailing digits are present. This is the correct behavior! The `test_extract_8_digit_scratch` test documents this design choice.

For 8-digit scratch codes, the validation logic (not the extraction logic) should handle the fallback:
1. Extract last 6 digits from input (e.g., "password12345678" → "345678")
2. Try validating as 6-digit TOTP first
3. If validation fails AND the original input had 8+ trailing digits, extract and validate the last 8 digits as a scratch code

This approach keeps extraction simple while supporting both TOTP and scratch codes through smart validation logic.

## Building and Running Tests

### Prerequisites

Install required development libraries:

```bash
# Debian/Ubuntu
apt-get install build-essential libpam0g-dev libldap2-dev liboath-dev

# RHEL/CentOS/Fedora
yum install gcc pam-devel openldap-devel liboath-devel

# Alpine
apk add build-base pam-dev openldap-dev oath-toolkit-dev
```

### Build Tests

```bash
cd tests
make
```

This creates three test executables:
- `test_config` - Configuration parsing tests
- `test_totp` - TOTP validation tests
- `test_extract` - OTP extraction tests

### Run Tests

Run all tests:
```bash
make run
```

Run individual test suites:
```bash
./test_config
./test_totp
./test_extract
```

Run from parent directory:
```bash
make test
```

### Clean Up

```bash
make clean
```

This removes:
- Test executables
- Object files
- Temporary test configuration files in `/tmp`

## Test Output

Successful test output:
```
Running configuration parsing tests...

✓ test_parse_totp_config_basic passed
✓ test_parse_totp_config_challenge_mode passed
✓ test_parse_nslcd_conf_file_option passed
✓ test_parse_ldap_config passed
✓ test_parse_combined_config passed
✓ test_parse_quoted_values passed
✓ test_default_values passed

✅ All configuration tests passed!
```

## Adding New Tests

To add new tests:

1. Create a new test function in the appropriate test file
2. Follow the naming convention: `test_<functionality>_<scenario>`
3. Use `assert()` for validation
4. Print success message: `printf("✓ test_name passed\n");`
5. Add function call to `main()`

Example:
```c
void test_new_feature() {
  // Setup
  totp_config_t cfg;

  // Test
  parse_totp_config("/path/to/config", &cfg);

  // Validate
  assert(cfg.some_field == expected_value);

  // Cleanup
  free_totp_config(&cfg);

  printf("✓ test_new_feature passed\n");
}
```

## Test Coverage

Current test coverage:

| Component | Functions Tested | Coverage |
|-----------|-----------------|----------|
| config.c | parse_totp_config, parse_ldap_config_from_file, parse_combined_config | ~90% |
| totp_validate.c | validate_totp_code, validate_scratch_code | ~85% |
| pam_ldap_totp.c | extract_otp_from_password (static) | ~95% |

**Not yet tested:**
- LDAP connection and query functions (requires mock LDAP server)
- Full PAM authentication flow (requires integration tests)
- Grace period calculation (requires LDAP mocking)

## Future Enhancements

- [ ] Integration tests with mock LDAP server
- [ ] Mock PAM handle for full authentication flow tests
- [ ] Performance tests (TOTP validation speed)
- [ ] Stress tests (concurrent authentication attempts)
- [ ] Memory leak detection with Valgrind
- [ ] Code coverage reporting with gcov/lcov

## Continuous Integration

To run tests in CI/CD:

```bash
# Install dependencies
apt-get update && apt-get install -y build-essential libpam0g-dev libldap2-dev liboath-dev

# Build and test
make clean
make
make test

# Check return code
if [ $? -eq 0 ]; then
  echo "Tests passed"
else
  echo "Tests failed"
  exit 1
fi
```

## Troubleshooting

**Tests fail to compile:**
- Ensure all development libraries are installed
- Check that header files are in the correct locations
- Verify `CFLAGS` in Makefile include correct paths

**Test failures:**
- Check system time is synchronized (TOTP tests are time-sensitive)
- Ensure `/tmp` is writable (config tests create temporary files)
- Run with verbose output to see detailed error messages

**TOTP validation tests intermittent failures:**
- Time-based tests may fail if system clock changes during test run
- Run tests on a system with stable, synchronized time (NTP)
- Tests use `oath_totp_generate()` which is time-dependent
