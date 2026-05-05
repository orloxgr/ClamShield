const https = require('https');
const fs = require('fs');
const unzipper = require('unzipper');

https.get('https://www.clamav.net/downloads/production/clamav-1.4.1-win-x64-portable.zip', (res) => {
    res.pipe(unzipper.Parse())
    .on('entry', function (entry) {
        console.log(entry.path);
        entry.autodrain();
    });
});
