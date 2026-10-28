

export const securiteInfoSignupUrl = "https://www.securiteinfo.com/clients/customers/signup";

export const securiteInfoAccountUrl = "https://www.securiteinfo.com/clients/customers/";

export const securiteInfoBaseUrl = "https://www.securiteinfo.com/get/signatures";

export const securiteInfoBasicDatabases = [
    "securiteinfo.ign2",
    "securiteinfoold.hdb"
];

export const securiteInfoSpamMarketingDatabase = "spam_marketing.ndb";

export const securiteInfoPuaDatabase = "securiteinfo-pua-app-and-vulnerabilities.ndb";

export const securiteInfoPaidDatabases = [
    ...securiteInfoBasicDatabases,
    "securiteinfo.hdb",
    "javascript.ndb",
    "securiteinfohtml.hdb",
    "securiteinfoascii.hdb",
    "securiteinfoandroid.hdb",
    "securiteinfopdf.hdb",
    "securiteinfo0hour.hdb",
    "securiteinfo.mdb",
    "securiteinfo.yara",
    "securiteinfo.pdb",
    "securiteinfo.wdb"
];

export const securiteInfoAllDatabases = [
    ...securiteInfoPaidDatabases,
    securiteInfoSpamMarketingDatabase,
    securiteInfoPuaDatabase
];
