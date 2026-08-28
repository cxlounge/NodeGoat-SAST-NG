const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

// Allowlist of permitted hostnames for outbound research requests.
// Only these hosts may be contacted; all others are rejected to prevent SSRF.
const ALLOWED_HOSTS = ["finance.yahoo.com"];

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            // Parse and validate the base URL using the stdlib URL parser.
            // Reject anything whose hostname is not on the explicit allowlist.
            let parsedUrl;
            try {
                parsedUrl = new URL(req.query.url);
            } catch (e) {
                return res.status(400).send("Invalid URL.");
            }

            if (!ALLOWED_HOSTS.includes(parsedUrl.hostname)) {
                return res.status(400).send("Requested host is not permitted.");
            }

            // Re-assemble the URL from the validated base and the symbol so that
            // only the path/query portion comes from user input, not the origin.
            const safeUrl = parsedUrl.href + req.query.symbol;
            return needle.get(safeUrl, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
