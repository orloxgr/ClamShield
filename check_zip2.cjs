const https = require('https');
const unzipper = require('unzipper');

https.get('https://www.clamav.net/downloads/production/clamav-1.4.1-win-x64-portable.zip', (res) => {
    res.pipe(unzipper.Parse())
    .on('entry', function (entry) {
        if(entry.path.includes('clamd')) {
           console.log("FOUND:", entry.path);
        }
        entry.autodrain();
    });
});
