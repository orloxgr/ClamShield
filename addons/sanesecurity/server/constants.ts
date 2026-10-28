import { programDataDir } from "../../../server/core/paths";
import path from "path";

export const saneSecurityWebsiteUrl = "https://sanesecurity.com/";

export const saneSecurityUsageUrl = "https://sanesecurity.com/usage/signatures/";

export const saneSecurityDonateUrl = "https://sanesecurity.com/donate/";

export const saneSecurityPublicKeyUrl = "https://www.sanesecurity.com/publickey.gpg";

export const saneSecurityMirrorHost = "rsync.sanesecurity.net";

export const saneSecurityCygwinSetupUrl = "https://cygwin.com/setup-x86_64.exe";

export const saneSecurityCygwinMirrorUrls = [
    "https://mirrors.kernel.org/sourceware/cygwin/",
    "https://cygwin.mirror.constant.com/"
];

export const saneSecuritySigningKeyFingerprint = "4E025A1CBA90A0653F38D2D8D691DED931EA4D9E";

export const saneSecurityToolsDir = path.join(programDataDir, "tools", "sanesecurity-cygwin");

export const saneSecurityToolsCacheDir = path.join(programDataDir, "tools", "sanesecurity-cygwin-cache");

export const saneSecuritySetupPath = path.join(programDataDir, "tools", "cygwin-setup-x86_64.exe");

export const saneSecurityWorkingDir = path.join(programDataDir, "sanesecurity");

export const saneSecurityGpgHomeDir = path.join(saneSecurityWorkingDir, "gnupg");

export const saneSecurityRsyncPath = path.join(saneSecurityToolsDir, "bin", "rsync.exe");

export const saneSecurityGpgPath = path.join(saneSecurityToolsDir, "bin", "gpg.exe");

export const saneSecurityCygpathPath = path.join(saneSecurityToolsDir, "bin", "cygpath.exe");

export const saneSecurityRequiredDatabases = [
    "sanesecurity.ftm",
    "sigwhitelist.ign2"
];

export const saneSecurityMalwareDatabases = [
    ...saneSecurityRequiredDatabases,
    "phish.ndb",
    "badmacro.ndb",
    "rogue.hdb",
    "foxhole_filename.cdb",
    "foxhole_generic.cdb",
    "malwarehash.hsb",
    "shelter.ldb"
];

export const saneSecurityCompleteDatabases = [
    ...saneSecurityMalwareDatabases,
    "blurl.ndb",
    "junk.ndb",
    "jurlbl.ndb",
    "scam.ndb",
    "spamattach.hdb",
    "spamimg.hdb",
    "jurlbla.ndb",
    "lott.ndb",
    "spam.ldb",
    "spear.ndb",
    "spearl.ndb"
];

export const saneSecurityAllDatabases = Array.from(new Set(saneSecurityCompleteDatabases));
