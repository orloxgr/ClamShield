// Trusted catalog: provider configuration accepts only these exact filenames.
// Descriptions are localized as plain text; downloaded databases are never code modules.
export const securiteInfoDatabaseCatalog = [
    ["securiteinfo.ign2", "False-positive corrections: ignores signatures withdrawn by SecuriteInfo."],
    ["securiteinfoold.hdb", "Malware older than one year; increases memory use."],
    ["securiteinfo.hdb", "Recent malware, mainly Windows executable files."],
    ["javascript.ndb", "HTML and JavaScript malware patterns, including phishing pages."],
    ["securiteinfohtml.hdb", "Malicious HTML content."],
    ["securiteinfoascii.hdb", "Malicious text and scripts, including BAT, shell and Perl."],
    ["securiteinfoandroid.hdb", "Android malware."],
    ["securiteinfopdf.hdb", "Malicious PDF files and PDF spam."],
    ["securiteinfo0hour.hdb", "Malware collected within the last hour."],
    ["securiteinfo.mdb", "Generic malware detection using sections of executable files."],
    ["securiteinfo.yara", "Generic YARA rules for malware, phishing and potentially unwanted content; scanned by ClamAV."],
    ["securiteinfo.pdb", "Anti-phishing checks for impersonated domains."],
    ["securiteinfo.wdb", "Anti-phishing allowlist that reduces false positives."],
    ["spam_marketing.ndb", "Marketing spam patterns, mainly intended for mail servers."],
    ["securiteinfo-pua-app-and-vulnerabilities.ndb", "Potentially unwanted applications and vulnerable components; may increase false positives."]
] as const;

export const saneSecurityDatabaseCatalog = [
    ["sanesecurity.ftm", "Recognizes message file types to improve scanning."],
    ["sigwhitelist.ign2", "False-positive corrections: ignores problematic SaneSecurity signatures."],
    ["phish.ndb", "Phishing and malware patterns."],
    ["badmacro.ndb", "Dangerous macros and scripts in documents."],
    ["rogue.hdb", "Malware, fake antivirus programs and fake codecs."],
    ["foxhole_filename.cdb", "Suspicious filenames inside archives."],
    ["foxhole_generic.cdb", "Suspicious archive contents and structures."],
    ["malwarehash.hsb", "Known malware file hashes."],
    ["shelter.ldb", "Logical rules for phishing and malware."],
    ["blurl.ndb", "Recently blocked malware, spam and phishing URLs."],
    ["junk.ndb", "General junk mail, phishing, lottery and scam patterns."],
    ["jurlbl.ndb", "URLs associated with junk mail."],
    ["scam.ndb", "Spam and scam patterns."],
    ["spamattach.hdb", "Known spam attachments, including documents and archives."],
    ["spamimg.hdb", "Images used in spam."],
    ["jurlbla.ndb", "Junk-mail URLs collected automatically from feeds."],
    ["lott.ndb", "Lottery scam patterns."],
    ["spam.ldb", "Logical rules for spam."],
    ["spear.ndb", "Email addresses associated with spear phishing."],
    ["spearl.ndb", "URLs associated with spear phishing."]
] as const;

export type SignatureDatabaseCatalog = ReadonlyArray<readonly [string, string]>;

export function normalizeDatabaseSelection(value: unknown, catalog: SignatureDatabaseCatalog): string[] {
    const allowed = new Set(catalog.map(([name]) => name));
    if (!Array.isArray(value) || value.length > catalog.length || value.some(name => typeof name !== "string" || !allowed.has(name)))
        throw new Error("Invalid signature database selection.");
    const selected = new Set(value);
    return catalog.map(([name]) => name).filter(name => selected.has(name));
}

export function availableSecuriteInfoDatabases(plan: unknown): string[] {
    return securiteInfoDatabaseCatalog.map(([name]) => name).filter((_, index) => plan === "paid" || index < 2);
}
