const https = require('http');

https.get('http://localhost:3000/api/testzip', (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => console.log(data));
});
