import { englishText } from "../../../shared/localization/runtime";
export const dnsProtectionProfiles = [
    {
        id: "cloudflare-malware",
        provider: "Cloudflare",
        name: englishText("backend.dns_protection.malware_blocking"),
        description: englishText("backend.dns_protection.blocks_domains_associated_with_malware_and_phishing"),
        ipv4: ["1.1.1.2", "1.0.0.2"],
        ipv6: ["2606:4700:4700::1112", "2606:4700:4700::1002"],
        websiteUrl: "https://developers.cloudflare.com/1.1.1.1/setup/",
        category: "security"
    },
    {
        id: "cloudflare-family",
        provider: "Cloudflare",
        name: englishText("backend.dns_protection.malware_adult_content"),
        description: englishText("backend.dns_protection.blocks_malware_phishing_and_adult_content"),
        ipv4: ["1.1.1.3", "1.0.0.3"],
        ipv6: ["2606:4700:4700::1113", "2606:4700:4700::1003"],
        websiteUrl: "https://developers.cloudflare.com/1.1.1.1/setup/",
        category: "family"
    },
    {
        id: "quad9-threat-blocking",
        provider: "Quad9",
        name: englishText("backend.dns_protection.threat_blocking"),
        description: englishText("backend.dns_protection.blocks_malicious_domains_with_quad9_s_public_security_filtering_r"),
        ipv4: ["9.9.9.9", "149.112.112.112"],
        ipv6: ["2620:fe::fe", "2620:fe::9"],
        websiteUrl: "https://docs.quad9.net/services/",
        category: "security"
    },
    {
        id: "quad9-threat-blocking-ecs",
        provider: "Quad9",
        name: englishText("backend.dns_protection.threat_blocking_ecs"),
        description: englishText("backend.dns_protection.blocks_malicious_domains_with_quad9_and_uses_edns_client_subnet_f"),
        ipv4: ["9.9.9.11", "149.112.112.11"],
        ipv6: ["2620:fe::11", "2620:fe::fe:11"],
        websiteUrl: "https://docs.quad9.net/services/#99911-secure--ecs",
        category: "security"
    },
    {
        id: "adguard-default",
        provider: "AdGuard",
        name: englishText("backend.dns_protection.default_protection"),
        description: englishText("backend.dns_protection.blocks_ads_trackers_malware_phishing_and_fraudulent_domains"),
        ipv4: ["94.140.14.14", "94.140.15.15"],
        ipv6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        websiteUrl: "https://adguard-dns.io/en/public-dns.html",
        category: "privacy"
    },
    {
        id: "adguard-family",
        provider: "AdGuard",
        name: englishText("backend.dns_protection.family_protection"),
        description: englishText("backend.dns_protection.adds_adult_content_blocking_and_safe_search_to_adguard_s_default"),
        ipv4: ["94.140.14.15", "94.140.15.16"],
        ipv6: ["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
        websiteUrl: "https://adguard-dns.io/en/public-dns.html",
        category: "family"
    },
    {
        id: "cleanbrowsing-security",
        provider: "CleanBrowsing",
        name: englishText("backend.dns_protection.security_filter"),
        description: englishText("backend.dns_protection.blocks_phishing_spam_malware_and_other_malicious_domains"),
        ipv4: ["185.228.168.9", "185.228.169.9"],
        ipv6: ["2a0d:2a00:1::2", "2a0d:2a00:2::2"],
        websiteUrl: "https://cleanbrowsing.org/filters",
        category: "security"
    },
    {
        id: "cleanbrowsing-family",
        provider: "CleanBrowsing",
        name: englishText("backend.dns_protection.family_filter"),
        description: englishText("backend.dns_protection.blocks_malicious_and_adult_domains_mixed_content_sites_proxy_vpn"),
        ipv4: ["185.228.168.168", "185.228.169.168"],
        ipv6: ["2a0d:2a00:1::", "2a0d:2a00:2::"],
        websiteUrl: "https://cleanbrowsing.org/filters",
        category: "family"
    },
    {
        id: "controld-malware",
        provider: "Control D",
        name: englishText("backend.dns_protection.malware_blocking"),
        description: englishText("backend.dns_protection.uses_control_d_s_free_public_malware_filtering_resolver"),
        ipv4: ["76.76.2.1", "76.76.10.1"],
        ipv6: ["2606:1a40::1", "2606:1a40:1::1"],
        websiteUrl: "https://docs.controld.com/docs/free-dns",
        category: "security"
    },
    {
        id: "controld-ads",
        provider: "Control D",
        name: englishText("backend.dns_protection.ads_tracking"),
        description: englishText("backend.dns_protection.uses_control_d_s_free_public_ads_and_tracking_resolver"),
        ipv4: ["76.76.2.2", "76.76.10.2"],
        ipv6: ["2606:1a40::2", "2606:1a40:1::2"],
        websiteUrl: "https://docs.controld.com/docs/free-dns",
        category: "privacy"
    },
    {
        id: "controld-family",
        provider: "Control D",
        name: englishText("backend.dns_protection.family_friendly"),
        description: englishText("backend.dns_protection.uses_control_d_s_free_public_family_friendly_resolver"),
        ipv4: ["76.76.2.4", "76.76.10.4"],
        ipv6: ["2606:1a40::4", "2606:1a40:1::4"],
        websiteUrl: "https://docs.controld.com/docs/free-dns",
        category: "family"
    }
];
