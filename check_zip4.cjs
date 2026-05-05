const https = require('https');

https.get('https://www.clamav.net/downloads/production/clamav-1.4.1-win-x64-portable.zip', (res) => {
    console.log(res.statusCode);
    console.log(res.headers);
});
