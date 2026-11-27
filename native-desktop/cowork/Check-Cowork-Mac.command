#!/bin/bash
set -euo pipefail
# Read-only collection. No sudo, feature enablement, launch or network changes.
mode="${1:-Unknown}"
case "$mode" in Unknown|Cloud|LocalVM) ;; *) printf '%s\n' 'Mode must be Unknown, Cloud or LocalVM' >&2; exit 64;; esac
os=$(/usr/bin/sw_vers -productVersion)
architecture=$(/usr/bin/uname -m)
memory=$(/usr/sbin/sysctl -n hw.memsize)
virtualization=null
if value=$(/usr/sbin/sysctl -n kern.hv_support 2>/dev/null); then
  if [ "$value" = 1 ]; then virtualization=true; else virtualization=false; fi
fi
official=false
signature=NOT_INSTALLED
for app in /Applications/Claude.app "$HOME/Applications/Claude.app"; do
  if [ -d "$app" ]; then
    official=true
    if /usr/bin/codesign --verify --deep --strict -R='anchor apple generic and identifier "com.anthropic.claudefordesktop" and certificate leaf[subject.OU] = "Q6L2SF6YDW"' "$app" >/dev/null 2>&1; then signature=VALID; else signature=INVALID; fi
    if [ "$signature" = VALID ]; then break; fi
  fi
done
assessment=MODE_CONFIRMATION_REQUIRED
cloud_egress=null
case "$mode" in
  Cloud) assessment=CLOUD_FEATURE_AND_ACCOUNT_VERIFICATION_REQUIRED;cloud_egress=false;;
  LocalVM) assessment=OFFICIAL_LOCAL_VM_CHECK_REQUIRED;;
esac
printf '{"schema":"hongai.cowork-readiness.v1","mode":"%s","assessment":"%s","machineFacts":{"osVersion":"%s","architecture":"%s","memoryBytes":%s,"hardwareVirtualizationAvailable":%s,"officialDesktopPresent":%s,"officialSignature":"%s"},"accountEntitlement":"NOT_INSPECTED_CUSTOMER_CONFIRMS","officialReadinessCheckRequired":true,"cageCoworkBoundaryAccepted":false,"coworkEnabledByThisCheck":false,"automaticInstallationAllowed":false,"automaticRebootAllowed":false,"hostNetworkSettingsChanged":false,"cloudTaskOutboundUsesLocalProxy":%s}\n' "$mode" "$assessment" "$os" "$architecture" "$memory" "$virtualization" "$official" "$signature" "$cloud_egress"
