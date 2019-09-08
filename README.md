This module has not been fully tested. Please perform your own tests before using it. I will be revisiting it sometime in the future to ensure that it is safe to use and to fix any bugs.

# HashTwitterCodes

This provides a utility for generating, reading, and validating hash-based reward codes. Using this utility, you can generate codes to reward players in-game currency on the fly without saving a special code in the DataStore, a database, or your game code.

Generator utlity example:
```plain
> codegen -k t -b 10000 6 -n Corecii -c 100 -l "Thanks"
Thanks-Corecii-100-NYGHA84FH18
```

Lua module example:
```lua

-- {<= currencyMax, byteLength} pairs:
local securityByteLength = {
    {500, 4},
    {2000, 6},
    {5000, 8},
    {10000, 12},
}

-- retrieve hmac key from datastore or other safe storage space, then...
local key = keyFromDataStore

--- in a RemoteFunction...

if playerData.FailedTwitterCodes >= 100 then
    return false, "Invalid code" -- ban brute-forcers from using codes
end

local result = HashTwitterCodes.decode(input)
if not result.Success then
    return false, "Invalid code"
end

local validationString = result:GetValidationString(player)
if #validationString > 100 then
    return false, "Invalid code" -- prevent fake, resource-consuming codes from being used
else if playerData.UsedCodes[validationString] then
    return false, "Already used"
elseif result.Currency > 10000 then
    return false, "Invalid code"
end

if not result:CheckHash(key, securityByteLength, player) then
    playerData.FailedTwitterCodes = playerData.FailedTwitterCodes + 1
    return false, "Invalid code"
end

if result.Limit then
    local limitResult = result:CheckAndMarkLimit(30, false)
    if not limitResult.Success then
        return false, "Roblox API failure, try again later!"
    elseif not limitResult:Unwrap() then
        return false, "Code already reached its limit!"
    end
end

if result.CodeTag == "n" then
    local identityResult = result:CheckIdentity(30, player)
    if not limitResult.Success then
        return false, "Roblox API failure, try again later!"
    elseif not identityResult:Unwrap() then
        return false, "Code is not meant for you!"
    end
end

playerData.Coins = playerData.Coins + result.Currency

return true, result.Currency

```

---

The mechanism for this is HMAC hashing. This allows us to authenticate that a message is official on the game server. By giving players authentic, official messages that include what to reward them, players can use those messages as reward codes without us marking those codes in a database or in game code.

Players provide reward details, validation details, and a HMAC hash to the server. The server hashes the validation details and compares it to the given HMAC hash. If the two are a match then the reward details are official, and the player can be rewarded.

These are the types of codes that can be generated:

| Type | Format | Example | Command |
| :--- | -----: | ------: | :------ |
| Public |||||
| plain | `coins-PHASH` | `100-PX5E0462ZD0` | `codegen -p -k t -b 10000 6 -c 100` ||
| labelled | `label-coins-PHASH` | `FreeCoins!-100-PK3FBDG68NG` | `codegen -p -k t -b 10000 6 -c 100 -l "FreeCoins!"` |  |
| limited | `coins-limit-PHASH` | `100-10-P9E484TG970` | `codegen -p -k t -b 10000 6 -c 100 -m 10` |  |
| labelled limited | `label-coins-limit-PHASH` | `FreeCoins!-100-10-PH56RTXH0V8` | `codegen -p -k t -b 10000 6 -c 100 -l "FreeCoins!" -m 10` ||
| Personal (name) |||||
| plain | `user-coins-NHASH` | `Corecii-100-NQVDR9CJQ00` | `codegen -k t -b 10000 6 -n Corecii -c 100` ||
| labelled | `label-user-coins-NHASH` | `Thanks-Corecii-100-NYGHA84FH18` | `codegen -k t -b 10000 6 -n Corecii -c 100 -l "Thanks"` ||
| Personal (user id) |||||
| plain | `coins-IHASH` | `100-I775JMS98NG` | `codegen -k t -b 10000 6 -i 9546145 -c 100` |  |
| labelled | `label-coins-IHASH` | `Thanks-100-IP0BH366EFR` | `codegen -k t -b 10000 6 -i 9546145 -c 100 -l "Thanks"` ||

Comments:
* Limited codes require datastores on validation to check how many times the code has been used. Limited codes are good for giving a code to a small group of players or giving codes in a first-come-first-serve limited manner.
* Personal (name) codes require a web api call on validation to convert the username to a userid. This is done so that the code stays valid even if the player changes their username.
* Personal (id) codes use the submitting user's id as a validation detail. All previous codes' validation details are stored in the message, but in the case of Personal (id) codes, one of the details (the user id) is stored outside of the message.
* This is secure as long as your key stays private. Your key should be *long* and needs to be present in both your code generation environment (to generate codes) and your code validation environment (to validate codes). Best practice is to store keys *outside* of your code e.g. in a file and in the datastore.
* All of these codes use the *extremely short and bad* key `t`. Ideally, your key should be much longer e.g. 50 characters.
* All of these codes use the byte count `6`. You should vary this with the number of currency that you are giving out: more currency = more bytes = more security. Put a cap on how much currency you will award a player.
* [The chance of guessing a code correctly with a random guess at a given required byte count is `1 in 2^(bytes*8)`](https://security.stackexchange.com/questions/93445/determining-strength-of-truncated-hmac). The chance of guessing one of the above codes correctly is `1 in 2^(6*8)` i.e. `1 in 281,474,976,710,656`.
* You need to store what codes a player has used in their player data to prevent code re-use. You should also prevent players from trying many invalid codes in succession, as they might be attempting a brute-force attack.

The name comes from the convention of calling in-game reward codes "twitter codes".

---

## Command-line options


```plain
Twitter Code Generator

  Generates hash-based twitter codes. Supports user-specific codes, public
  codes, and use-limited codes.
  Supports unicode characters in the body and key. The body and key are
  converted to bytes from utf-8 before hashing.

  Checks the following locations for parameters:
  * Command line arguments
  * JSON-formatted input file. Either the given --file argument or the default
  file name, 'twitterCodesConfig.json'
  * Environment variables matching 'twitter_codes_X' e.g. 'twitter_codes_key'

Options

  -h, --help                   View this help text
  -f, --file string            File name to check for config. If not provided, will try to read the default,
                               'twitterCodesConfig.json'. If not provided, will not warn when the config
                               file is missing.
  --nofile                     Don't check config file for parameters
  --noenv                      Don't check environment for parameters
  -k, --key string             Authentication hash key
  -p, --public                 This is a public code that anyone can use
  -n, --username string        This is a personal code that only the given user name can use
  -i, --userid string          This is a personal code that only the given user id can use
  -l, --label string           User-visible label for this code; this must *not* be a number
  -m, --limit integer          Limit the maximum number of uses of this code (for public codes only); this
                               requires marking uses in the DataStore
  -c, --currency integer       The amount of currency to give
  -b, --bytes currency bytes   Specifies how many bytes are required for an amount of currency
```

---

## Lua API:

```plain
HashTwitterCodes API:
    CodeSuccess|Result .decode(string code)
        Decodes a hash twitter code.
        If the code is formatted incorrectly, returns a Result.failure with the reason.
        If the code is formatted correctly, returns a CodeSuccess with the code details.
        The returned CodeSuccess has not been validated for authenticity.
    string .generate(Dict<string, Variant> options)
        Generates a code from the given options.
        This mirrors the commandline tool. The options are the same as the full-name commandline keys and json keys.
        See the commandline tool's docs for more information.
    string.getRequiredLength(integer currency, Array<[integer currency, integer byteCount]> requirements)
        Returns the number of bytes needed to validate the given currency.

Result API:
    Result .success(...)
    Result .failure(string reason)
    bool .Success
        True on success, false on failure
    ... :Unwrap()
        If failure, errors with the failure message.
        If successful, returns the success data (...)

CodeSuccess API:
    CodeSuccess .new(table data)
    bool .Success = true
    CodeSuccess :Unwrap()
        Returns self
    string .CodeTag
        One of "p", "n", or "i" (public, personal user name, or personal user id)
    bool .IsPublic
        True if this is a public code ("p")
    string? Label
        Optional code label. Preserves the casing that the user passed in.
    integer Currency
        A positive integer currency.
    integer? Limit
        Optional code limit. Only present on public codes. A positive integer.
    string? Username
        Optional username.
    string Hash
        Lowercase user-provided hash.
    integer Bytes
        Number of bytes in the user-provided hash.
    string :GetValidationString(string|integer|Player player)
        Gets the string to be used for validation. Validation strings are always lowercase.
        In the case of a personal (id) code, the player argument is required or the method will error.
        The returned string has one matching hash and can be HMAC hashed and compared to the user-provided hash
        to verify authenticity.
        If you need a unique string to represent a hash then use this.
    bool :CheckHashLength(Array<[integer currency, integer bytesRequirement]> requirements)
        Checks if this code has a secure enough amount of bytes for the given currency count.
    bool :CheckHash(string key, integer bytes, string|integer|Player player)
        Gets the validation string using `player`, hashes it using `key`, then compares it
        to the user-provided hash. Return true if they match, false otherwise.
        If this is a personal (id) code and player is not provided or is the wrong type, this method will error.
    Result<bool success> :CheckAndMarkLimit(number timeout, bool retryOnAmbiguous = false)
        Checks the global limit for this hash (using datastores) and marks increse the use-count by 1.
        This method will not error if data stores fail:
        * If the provided parameters to the datastore are incorrect, it will return `Result.failure(errorMessage)`
        * If the datastore queue is full, it will retry until timeout, then return `Result.failure(errorMessage)`
        * If the datastore fails in a non-conventional manner where the update may have or may not have completed...
            * ...if retryOnAmbiguous is true, then it will retry until timeout, then return `Result.failure(errorMessage)`
            * ...if retryOnAmbiguous is false or nil, then it will return `Result.failure(errorMessage)`
        * Retries happen every 10 seconds. If successful within the timeout, returns `Result.success(withinLimit)`,
            where withinLimit is true if the player is allowed to use the code.
        * Because this code increments the total use counter, `retryOnAmbiguous` can result in the counter increasing
            on every failure despite only being used once or not at all. It is up to you whether to risk increasing the
            counter or to return failure and have the user try again later.
        If timeout is not provided or is the wrong type, this method will error.
        If this is not a limit code, `Result.success(true)` is returned.
    Result<bool success> :CheckIdentity(timeout, integer|Player player)
        Checks if this code's username matches the player's identity.
        This method checks the code's username's userid agains the player's userid. This is done to account for
        changing usernames. This method must make web API calls to check this.
        This method will not error if web API calls fail:
        * If the username does not exist, the result is cached and `Result.success(false)` is returned.
        * If the timeout is reached without success, `Result.failure(errorMessage)` is returned.
        * If the userid is retrieved before timemout, `Result.success(userid == player's userid)` is returned.
        * The result of the web API call is cached.
        If timeout is not provided or is the wrong type, this method will error.
        If player is not provided or is the wrong type, this method will error.
        If this is not a personal (username) code, this will return `Result.success(true)`
    Note: You also need to check:
        * Has the player used this code before?
        * Is the player trying invalid codes too often?
        These should be checked *before* calling the Check methods.
```