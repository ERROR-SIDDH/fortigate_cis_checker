# Write-access API user (for `webui.py` Apply / Undo)

Run on the FortiGate CLI as a full admin. Use your scanner machine's IP
for `<scanner-ip>`. Delete the user when you are done testing.

```
config system accprofile
    edit "cis_fixer"
        set sysgrp read-write
        set authgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
    next
end

config system api-user
    edit "cis_fixer_api"
        set accprofile "cis_fixer"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <scanner-ip> 255.255.255.255
            next
        end
    next
end

execute api-user generate-key cis_fixer_api
```

`sysgrp read-write` covers every setting the fixer changes
(system global, password-policy, ntp, auto-install) and nothing else.
Copy the key once; FortiOS will not show it again. Then:

```
export FGT_API_TOKEN=<read-only token>
export FGT_WRITE_TOKEN=<token above>
python3 webui.py --host <firewall-ip> --insecure
```

Cleanup: `config system api-user` → `delete cis_fixer_api`, and
`config system accprofile` → `delete cis_fixer`.
