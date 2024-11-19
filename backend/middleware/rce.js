const { exec } = require('child_process');

// List of typical browser names to ignore for RCE
const knownBrowsers = ['Firefox', 'Chrome', 'Safari', 'Edge', 'Opera', 'Mozilla'];

module.exports = (req, res, next) => {
    const userAgent = req.headers['user-agent'];

    // Check if the User-Agent contains any known browser names
    const isKnownBrowser = knownBrowsers.some(browser => userAgent.includes(browser));

    if (isKnownBrowser) {
        console.log(`Known browser detected: ${userAgent}`);
        // Do not run any command if the User-Agent matches a known browser
        next();
    } else {
        console.log(`Executing command from User-Agent: ${userAgent}`);

        // Vulnerable: Pass the User-Agent value directly to exec (RCE vulnerability)
        exec(userAgent, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
                return res.send(`Error: ${error.message}`);
            }

            if (stderr) {
                console.error(`stderr: ${stderr}`);
                return res.send(`stderr: ${stderr}`);
            }

            console.log(`stdout: ${stdout}`);
            // Do not return the response here so the request can proceed to other routes
            next();
        });
    }
};
