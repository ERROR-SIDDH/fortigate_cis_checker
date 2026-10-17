# Creating the Read-Only User on FortiGate

The script assumes the FortiGate side, not just the script, enforces
read-only access. Do this configuration directly on the FortiGate
(GUI or CLI) as a full admin, once, before running the checker.

## 1. Create a read-only access profile

CLI:

```
config system accprofile
    edit "cis_readonly"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
```

Every permission group is set to `read`, not `read-write`. This profile
cannot create, modify, or delete configuration regardless of what any
client (including this script) sends it.

## 2a. REST API backend — create an API admin + token

CLI:

```
config system api-user
    edit "cis_checker_api"
        set accprofile "cis_readonly"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <your-scanning-host-ip>/32
            next
        end
    next
end
execute api-user generate-key cis_checker_api
```

The device prints a one-time API token. Save it somewhere safe (e.g. an
environment variable `FGT_API_TOKEN`), it cannot be retrieved again.

Restricting `trusthost` to the machine that will run this script means
the token is useless even if leaked, unless the attacker is also on
that source IP.

## 2b. SSH backend — create a read-only admin

CLI:

```
config system admin
    edit "cis_checker_ssh"
        set accprofile "cis_readonly"
        set password <strong-password-or-use-key-auth>
        set ssh-public-key1 "<paste public key here>"
        config trusthost1
            set trusthost1 <your-scanning-host-ip> 255.255.255.255
        next
    next
end
```

Prefer SSH key auth over password auth where possible.

## 3. Verify the restriction actually holds

Before trusting the script's results, confirm the profile really is
read-only, e.g. try (and expect to be refused):

```
ssh cis_checker_ssh@<fortigate-ip>
> config system global
   set hostname test
```

This should be rejected by the FortiGate itself. If it is not, the
accprofile was not applied correctly, fix that before running any
scanner against production.

## 4. Least privilege reminder

- Never reuse the default `admin` account for scanning.
- Scope `trusthost` as tightly as possible.
- Rotate the API token / SSH key after the assessment period ends,
  especially for a coursework/lab environment that may be shared.
