import { englishText } from "../../../../shared/localization/runtime";
import { ApplicationContext } from "../../../../server/core/applicationContext";
import { saveConfig } from "../../../settings/server/service";
import { applyDnsProtectionProfile, getDnsProtectionStatus } from "../service";
export function registerPostApiDnsProtectionApply(app: any, context: Pick<ApplicationContext, "settings">) {
    app.post("/api/dns-protection/apply", async (req, res) => {
        try {
            const profile = await applyDnsProtectionProfile(context.settings, req.body?.profileId);
            context.settings = {
                ...context.settings,
                dnsProtectionEnabled: true,
                dnsProtectionProfile: profile.id,
                dnsProtectionAppliedAt: new Date().toISOString()
            };
            await saveConfig(context.settings);
            const status = await getDnsProtectionStatus(context.settings);
            const warning = status.partiallyApplied
                ? "DNS protection is active on at least one internet adapter. Some adapters still report different DNS settings, which can happen with VPNs, virtual adapters, IPv6 policy, or router-managed DNS."
                : undefined;
            res.status(status.applied ? 200 : 409).json({
                success: status.applied,
                warning,
                error: status.applied ? undefined : englishText("backend.dns_protection.windows_accepted_the_dns_change_but_windows_did_not_report_this_d"),
                status
            });
        }
        catch (e: any) {
            res.status(500).json({ success: false, error: e?.message || String(e) });
        }
    });
}
