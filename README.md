# LDAP TOTP PAM Module

A PAM (Pluggable Authentication Modules) module that validates TOTP (Time-based One-Time Password) codes stored in LDAP directories. This enables centralised two-factor authentication for any PAM-enabled service including OpenVPN, SSH, sudo, login, and more.

## Features

- **Universal PAM module** - Works with any PAM-enabled service
- **LDAP-backed storage** - TOTP secrets stored centrally in LDAP
- **Multiple authentication modes**:
  - **Append mode**: Password and OTP concatenated (e.g., `password123456`)
  - **Challenge-response mode**: Separate prompts for password and OTP
- **RFC 6238 compliant** - Standard TOTP implementation with SHA1
- **Backup codes support** - Emergency access with scratch codes (deleted after use)
- **Configurable validation** - Time window tolerance for clock drift
- **Grace period enforcement** - Allow users time to set up MFA
- **Secure by design** - Reads LDAP secrets with proper access controls

## Requirements

### LDAP Schema (Recommended)

It is **strongly recommended** that you install the LDAP TOTP schema in your LDAP directory:

**LDAP TOTP Schema**: https://github.com/wheelybird/ldap-totp-schema

This schema adds standardised LDAP attributes (`totpSecret`, `totpStatus`, `totpScratchCode`, etc.) for storing TOTP secrets and managing MFA policies, along with secure ACL examples.

**Alternative Configuration**: The PAM module is configurable and can use any LDAP attribute you specify via the `totp_attribute` setting. However, if you use custom attributes, you are responsible for implementing appropriate LDAP access controls to protect the TOTP secrets. The official schema provides battle-tested ACLs and attribute definitions.

### System Dependencies

**Build dependencies:**
```bash
# Debian/Ubuntu
apt-get install build-essential libpam0g-dev libldap2-dev liboath-dev

# RHEL/CentOS/Fedora
yum install gcc pam-devel openldap-devel liboath-devel

# Alpine
apk add build-base pam-dev openldap-dev oath-toolkit-dev
```

**Runtime dependencies:**
- PAM library (`libpam`)
- OpenLDAP client library (`libldap`)
- OATH Toolkit library (`liboath`)

### LDAP Configuration

The module supports flexible LDAP configuration with three approaches:

**Option 1: Use `/etc/nslcd.conf` (Recommended if you already use nslcd)**
- The module reads LDAP connection settings from `/etc/nslcd.conf` by default
- It uses the nslcd config file format but does **not** require the nslcd service to be running
- This allows reuse of existing LDAP configuration
- If you have nslcd.conf in a custom location, set `nslcd_conf_file` in `/etc/security/pam_ldap_totp.conf`

**Option 2: Configure LDAP settings in `/etc/security/pam_ldap_totp.conf`**
- Uncomment LDAP settings in the config file (see `pam_ldap_totp.conf.example`)
- Useful if you don't use nslcd or want different LDAP settings for TOTP authentication
- Settings in `pam_ldap_totp.conf` override those from `nslcd.conf`

**Option 3: Hybrid approach**
- Use `/etc/nslcd.conf` for most LDAP settings
- Override specific settings in `/etc/security/pam_ldap_totp.conf`
- Example: Use nslcd.conf for uri/base, but set custom binddn/bindpw for TOTP authentication

**LDAP settings supported:**
- `uri` - LDAP server URI (e.g., `ldap://ldap.example.com` or `ldaps://ldap.example.com:636`)
- `base` - LDAP base DN (e.g., `dc=example,dc=com`)
- `binddn` - Bind DN for LDAP authentication (optional, anonymous bind if not set)
- `bindpw` - Bind password (optional)
- `ssl` - TLS/SSL settings (`on`, `start_tls`, or `off`)
- `tls_reqcert` - Certificate validation (`yes`/`no`)
- `tls_cacertfile` - Path to CA certificate file
- `nslcd_conf_file` - Custom path to nslcd.conf (default: `/etc/nslcd.conf`)

## Building

```bash
make
```

This will compile `pam_ldap_totp.so` in the current directory.

## Installation

```bash
sudo make install
```

This installs the module to `/lib/security/pam_ldap_totp.so` (or `/lib64/security/` on 64-bit systems).

## Configuration

### 1. PAM Module Configuration

Create `/etc/security/pam_ldap_totp.conf`:

```bash
sudo cp pam_ldap_totp.conf.example /etc/security/pam_ldap_totp.conf
sudo chmod 600 /etc/security/pam_ldap_totp.conf
```

Edit the configuration file to match your setup. Key settings:

```conf
# Authentication mode: append or challenge
totp_mode append

# LDAP attribute containing TOTP secret
totp_attribute totpSecret

# TOTP validation settings
time_step 30
window_size 3

# MFA enforcement
grace_period_days 7
enforcement_mode graceful

# Debug (disable in production)
debug false
```

See `pam_ldap_totp.conf.example` for all available options.

### 2. Service PAM Configuration

Choose the appropriate example for your service and install it to `/etc/pam.d/`:

**OpenVPN:**
```bash
sudo cp examples/openvpn/openvpn /etc/pam.d/openvpn
```

**SSH:**
```bash
sudo cp examples/ssh/sshd /etc/pam.d/sshd
```

**sudo:**
```bash
sudo cp examples/sudo/sudo /etc/pam.d/sudo
```

### 3. Service-Specific Configuration

**For SSH (challenge-response mode):**

Edit `/etc/ssh/sshd_config`:
```
ChallengeResponseAuthentication yes
UsePAM yes
PasswordAuthentication no
```

Then restart SSH:
```bash
sudo systemctl restart sshd
```

**For OpenVPN:**

Configure OpenVPN server to use PAM authentication. See the [OpenVPN documentation](https://github.com/wheelybird/openvpn-server-ldap-otp) for details.

## Authentication Modes

### Append Mode (Default)

User enters password and TOTP code concatenated together.

**Example:** If password is `mypassword` and TOTP code is `123456`, user enters: `mypassword123456`

**Configuration:**
```conf
totp_mode append
```

**Use cases:**
- OpenVPN (all clients support this)
- Services without challenge-response support
- Simple, predictable UX

**Scratch Code Support:**
8-digit scratch/backup codes are supported.  In append mode it works as follows:

1. User enters password + 8-digit scratch code: `mypassword12345678`
2. Module extracts last 6 digits as OTP: `345678`
3. Module attempts TOTP validation with `345678`
4. If validation fails AND the original input had 8+ trailing digits, module extracts last 8 digits (`12345678`) and validates as scratch code
5. Authentication succeeds if scratch code is valid
6. The scratch code is removed from LDAP

### Challenge-Response Mode

System prompts separately for password and TOTP code.

**User experience:**
```
Password: [user enters password]
TOTP code: [user enters 6-digit code or 8-digit scratch code]
```

**Configuration:**
```conf
totp_mode challenge
challenge_prompt Enter TOTP code:
```

**Use cases:**
- SSH (best UX with separate prompts)
- sudo (clear two-step authentication)
- login (terminal prompts)

**Note:** OpenVPN does NOT support challenge-response mode. Use append mode for OpenVPN.

## Usage Examples

### Enable MFA for LDAP User

```bash
# 1. Generate TOTP secret (Base32, 160-bit)
SECRET=$(openssl rand -base64 20 | base32 | tr -d '=' | head -c 32)

# 2. Add to LDAP user entry
ldapmodify -x -D "cn=admin,dc=example,dc=com" -w password <<EOF
dn: uid=jdoe,ou=people,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: totpUser
-
add: totpSecret
totpSecret: $SECRET
-
add: totpStatus
totpStatus: active
-
add: totpEnrolledDate
totpEnrolledDate: $(date -u +"%Y%m%d%H%M%SZ")
EOF

# 3. Generate QR code for user
echo "otpauth://totp/Example:jdoe?secret=$SECRET&issuer=Example" | qrencode -t UTF8
```

### Test Authentication

**Append mode (OpenVPN, general use):**
```bash
# Generate current TOTP code
CODE=$(oathtool --totp --base32 "JBSWY3DPEHPK3PXP")

# Test with pamtester
pamtester openvpn jdoe authenticate
# Enter: password$CODE (e.g., mypassword123456)
```

**Challenge-response mode (SSH, sudo):**
```bash
# SSH will prompt separately
ssh jdoe@server
# Password: mypassword
# TOTP code: 123456
```

## Troubleshooting

### Check Module Installation

```bash
ls -l /lib/security/pam_ldap_totp.so
# Should show the module file
```

### Enable Debug Logging

Edit `/etc/security/pam_ldap_totp.conf`:
```conf
debug true
```

Check logs:
```bash
# Debian/Ubuntu
tail -f /var/log/auth.log

# RHEL/CentOS
tail -f /var/log/secure

# systemd
journalctl -f -u sshd
```

### Common Issues

**"LDAP connection failed"**
- Check `/etc/nslcd.conf` configuration
- Verify LDAP server is reachable
- Test with: `ldapsearch -x -b "dc=example,dc=com"`

**"TOTP secret not found"**
- Verify user has `totpUser` objectClass
- Check `totpSecret` attribute exists
- Verify PAM module can read the attribute (check LDAP ACLs)

**"TOTP validation failed" (code is correct)**
- Check system time synchronization: `timedatectl status`
- Install NTP: `apt-get install ntp` or `yum install chrony`
- Increase `window_size` in config (temporarily for testing)

**"Permission denied" when accessing `/etc/security/pam_ldap_totp.conf`**
```bash
sudo chmod 600 /etc/security/pam_ldap_totp.conf
sudo chown root:root /etc/security/pam_ldap_totp.conf
```

### Test TOTP Code Generation

```bash
# Install oathtool
apt-get install oathtool  # Debian/Ubuntu
yum install oathtool      # RHEL/CentOS

# Generate code from secret
oathtool --totp --base32 "JBSWY3DPEHPK3PXP"
```

## Security Considerations

### LDAP ACLs

See the [LDAP TOTP schema](https://github.com/wheelybird/ldap-totp-schema) for complete ACL examples.  The module needs read access to all the TOTP attributes except for the attribute storing the scratch codes - it needs write access to this in order to remove scratch codes that have been used.

### Time Synchronization

TOTP relies on accurate system time:
- Install and enable NTP/chrony
- Ensure all servers are time-synchronized
- Monitor for clock drift

### Backup Codes

Always generate backup codes for emergency access:
```bash
for i in {1..10}; do
  printf "TOTP-SCRATCH:%08d\n" $((RANDOM * RANDOM % 100000000))
done
```

Store with `totpScratchCode` attribute in LDAP.

### Configuration File Permissions

```bash
# PAM module config should only be readable by root
chmod 600 /etc/security/pam_ldap_totp.conf
chown root:root /etc/security/pam_ldap_totp.conf
```

## Integration Examples

### OpenVPN

See [openvpn-server-ldap-otp](https://github.com/wheelybird/openvpn-server-ldap-otp) for a complete OpenVPN container with LDAP TOTP support.

### SSH Two-Factor Authentication

Complete SSH MFA setup:

1. Install PAM module (see above)
2. Configure `/etc/pam.d/sshd` (use example)
3. Configure `/etc/ssh/sshd_config`:
   ```
   ChallengeResponseAuthentication yes
   UsePAM yes
   PasswordAuthentication no
   ```
4. Restart SSH: `systemctl restart sshd`
5. Enroll users in LDAP (add `totpSecret`)
6. Test: `ssh username@server`

### Self-Service MFA Enrollment

Use [LDAP User Manager](https://github.com/wheelybird/ldap-user-manager) to provide a web interface where users can:
- Enroll in MFA themselves
- Scan QR codes with authenticator apps
- View and save backup codes
- Manage their MFA status

## Technical Details

### TOTP Parameters

- **Algorithm**: SHA1 (RFC 6238 standard)
- **Digits**: 6
- **Time Step**: 30 seconds (configurable)
- **Window Size**: 3 steps (±90 seconds tolerance, configurable)

### Validation Window

With `window_size=3`, the module accepts codes from:
- 3 steps before current time (-90 seconds)
- Current time window
- 3 steps after current time (+90 seconds)

This provides a total window of 210 seconds (7 time steps).

### Grace Period

The `grace_period_days` setting allows users time to set up MFA:
- Check if user is in group with `mfaRequired=TRUE`
- If `totpStatus=pending`, allow grace period
- Calculate: `days_elapsed = (current_date - totpEnrolledDate) / 86400`
- If `days_elapsed > grace_period_days`, enforce MFA

## Development

### Building from Source

```bash
git clone https://github.com/wheelybird/ldap-totp-pam.git
cd ldap-totp-pam
make
```

### Running Unit Tests

The project includes comprehensive unit tests for configuration parsing, TOTP validation, and OTP extraction logic.

```bash
# Run all tests
make test

# Or run tests directly
cd tests
make run

# Run individual test suites
./tests/test_config   # Configuration parsing tests
./tests/test_totp     # TOTP validation tests
./tests/test_extract  # OTP extraction tests
```

See [tests/README.md](tests/README.md) for detailed test documentation.

### Integration Testing with pamtester

```bash
# Install pamtester
sudo apt-get install pamtester

# Test authentication
pamtester <service> <username> authenticate
```

### Debugging

Enable debug logging in `/etc/security/pam_ldap_totp.conf`:
```conf
debug true
```

Then check logs:
```bash
# Debian/Ubuntu
tail -f /var/log/auth.log

# RHEL/CentOS
tail -f /var/log/secure

# systemd
journalctl -f -u sshd
```

## Related Projects

- **LDAP TOTP Schema**: https://github.com/wheelybird/ldap-totp-schema - LDAP schema definitions
- **LDAP User Manager**: https://github.com/wheelybird/ldap-user-manager - Web UI for MFA enrolment
- **OpenVPN LDAP OTP**: https://github.com/wheelybird/openvpn-server-ldap-otp - OpenVPN with LDAP TOTP

## Standards & References

- **RFC 6238** - TOTP: Time-Based One-Time Password Algorithm
- **RFC 4226** - HOTP: HMAC-Based One-Time Password Algorithm
- **Linux-PAM Documentation**: http://www.linux-pam.org/
- **OATH Toolkit**: https://www.nongnu.org/oath-toolkit/

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please open an issue or pull request on GitHub.

## Support

- **Issues**: https://github.com/wheelybird/ldap-totp-pam/issues
- **Discussions**: https://github.com/wheelybird/ldap-totp-pam/discussions
