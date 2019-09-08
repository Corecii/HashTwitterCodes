const fastSha256 = require("fast-sha256");
const commandLineArgs = require("command-line-args");
const commandLineUsage = require("command-line-usage");
const dotenv = require("dotenv");
const fs = require("fs-extra");
const base32 = require("base32-crockford");
const util = require("util");

const dotenvResult = dotenv.config();

function validateInteger(number) {
    if (String(number).match(/\D/)) {
        return null;
    }
    return number;
}

const optionDefs = [
    { name: "help", alias: "h", type: Boolean, description: "View this help text" },
    { name: "file", alias: "f", type: String, description: "File name to check for config. If not provided, will try to read the default, 'twitterCodesConfig.json'. If not provided, will not warn when the config file is missing." },
    { name: "nofile", type: Boolean, description: "Don't check config file for parameters" },
    { name: "noenv", type: Boolean, description: "Don't check environment for parameters" },
    { name: "key", alias: "k", type: String, description: "Authentication hash key" },
    { name: "public", alias: "p", type: Boolean, description: "This is a public code that anyone can use" },
    { name: "username", alias: "n", type: String, description: "This is a personal code that only the given user name can use" },
    { name: "userid", alias: "i", type: String, description: "This is a personal code that only the given user id can use" },
    { name: "label", alias: "l", type: String, description: "User-visible label for this code; this must *not* be a number" },
    { name: "max", alias: "m", type: validateInteger, typeLabel: "{underline integer}", description: "Limit the maximum number of uses of this code (for public codes only); this requires marking uses in the DataStore" },
    { name: "currency", alias: "c", type: validateInteger, typeLabel: "{underline integer}", description: "The amount of currency to give" },
    { name: "bytes", alias: "b", type: validateInteger, typeLabel: "{underline currency} {underline bytes}", multiple: true, description: "Specifies how many bytes are required for an amount of currency" },
];

const helpDefs = [
    {
        header: "Twitter Code Generator",
        content: "Generates hash-based twitter codes. Supports user-specific codes, public codes, and use-limited codes."
        + "\nSupports unicode characters in the body and key. The body and key are converted to bytes from utf-8 before hashing."
        + "\n\nChecks the following locations for parameters:"
        + "\n* Command line arguments"
        + "\n* JSON-formatted input file. Either the given --file argument or the default file name, 'twitterCodesConfig.json'"
        + "\n* Environment variables matching 'twitter_codes_X' e.g. 'twitter_codes_key'"
    },
    {
        header: "Options",
        optionList: optionDefs
    }
];

function help() {
    console.log(commandLineUsage(helpDefs));
}

const options = commandLineArgs(optionDefs);

if (options.help) {
    return help();
}

function getOption(location, optionName) {
    for (let key in location) {
        if (key.toLowerCase() === optionName.toLowerCase()) {
            return location[key];
        }
    }
}

function merge(location, prefix) {
    for (let info of optionDefs) {
        if (options[info.name] === undefined) {
            let envValue = location[prefix+info.name];
            if (envValue !== undefined) {
                options[info.name] = info.type(envValue);
            }
        }
    }
}

(async function() {
    if (!options.noenv) {
        merge(process.env, "twitter_codes_");
    }

    const fileName = options.file !== undefined ? options.file : "twitterCodesConfig.json";
    if (fileName && !options.nofile) {
        try {
            let file = await fs.readJson(fileName);
            merge(file, "");
        } catch (err) {
            if (!err.message.match(/^ENOENT/) || options.file) {
                console.warn(`Failed to load ${fileName} as config because: ${err}`);
                console.warn(`Skipping config file ${fileName} because it could not be loaded`);
            }
        }
    }

    if (!options.key) {
        console.warn("Missing required parameter: key");
        return help();
    }
    if (!options.public && !options.username && !options.userid) {
        console.warn("Missing required parameters: one of public, username, or userid");
        return help();
    }
    if (options.username && options.userid) {
        console.warn("Only one of username or userid is allowed");
        return help();
    }
    if (options.public && (options.username || options.userid)) {
        console.warn("Code must be public or personal, not both");
        return help();
    }
    if (!options.currency) {
        console.warn("Missing required parameter: currency");
        return help();
    }
    if (options.bytes && options.bytes.length%2 == 1 && bytes != 1) {
        console.warn("Bytes should be specified in pairs of two (currency, bytes)");
        return help();
    }
    if (options.label && validateInteger(options.label) !== null) {
        console.warn("Label must not be an integer");
        return help();
    }
    if (!options.public && options.max) {
        console.warn("Limits cannot be used with personal codes")
        return help();
    }

    /*
        Code types:
            Public:
                With label and limits:
                    label-coins-limit-pHash
                With label:
                    label-coins-pHash
                With limit:
                    coins-limit-pHash
                Just coins:
                    coins-pHash
            Personal: usernames are nHash, userids are iHash. For iHash, user is absent.
                With label:
                    label-user-coins-nHash
                Just coins:
                    user-coins-nHash
    */

    let codeParts = [];
    let codePartsHash = [];

    function pushCodePart(part, hidden) {
        part = String(part);
        if (!hidden) {
            codeParts.push(part);
        }
        codePartsHash.push(part.toLowerCase());
    }

    let codeTag = "";

    if (options.label) {
        pushCodePart(options.label);
    }
    if (options.public) {
        codeTag = "p";
    } else {
        if (options.username) {
            codeTag = "n";
            pushCodePart(options.username);
        } else if (options.userid) {
            codeTag = "i";
            pushCodePart(options.userid, true);
        }
    }
    pushCodePart(options.currency);
    if (options.max) {
        pushCodePart(options.max);
    }
    pushCodePart(codeTag, true);

    let authStr = codePartsHash.join("-");

    let keyBytes = new util.TextEncoder("utf-8").encode(options.key);
    let bodyBytes = new util.TextEncoder("utf-8").encode(authStr);
    
    let rawHash = new fastSha256.hmac(keyBytes, bodyBytes);

    if (options.bytes) {
        for (let i = 0; i < options.bytes.length; i += 2) {
            let currency = options.bytes[i];
            let bytes = options.bytes[i + 1];
            if (Number(options.currency) <= Number(currency)) {
                rawHash = rawHash.slice(0, bytes);
                break;
            }
        }
    }

    let friendlyHash = base32.encode(rawHash).toUpperCase();

    codeParts.push(codeTag.toUpperCase()+friendlyHash)

    console.log(codeParts.join("-"));
})();