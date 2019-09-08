--[[
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
		string .getRequiredLength(integer currency, Array<[integer currency, integer byteCount]> requirements)
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
			Checks if this code has a secure enough amount of bytes for the given currency count.
		bool :CheckHash(string key, integer|Array<[integer currency, integer bytesRequirement]> bytes, string|integer|Player player)
			Gets the validation string using `player`, hashes it using `key`, then compares it
			to the user-provided hash. Return true if they match, false otherwise.
			If this is a personal (id) code and player is not provided or is the wrong type, this method will error.
			For the `bytes` argument, either an absolute integer of required bytes can be provided or a requirements array can be provided.
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
			* Is the currency count too high? You should have a max cap on how much currency *any* code can give.
			These should be checked *before* calling the Check methods.
--]]

local lockbox = require(script.lockbox)
lockbox.bit = bit32

local array = require(lockbox.util.array)
local stream = require(lockbox.util.stream)
local basexx = require(lockbox.util.basexx)
local hmac = require(lockbox.mac.hmac)
local sha256 = require(lockbox.digest.sha2_256)

local function hmacAuthHash(body, key, truncate)
	local hmacBuilder = hmac()
		.setBlockSize(64)
		.setDigest(sha256)
		.setKey(array.fromString(key))
		.init()
		.update(stream.fromString(body))
		.finish()
	local bytes = hmacBuilder.asBytes()
	for i, byte in ipairs(bytes) do
		if not truncate or i <= truncate then
			bytes[i] = string.char(byte)
		else
			bytes[i] = nil
		end
	end
	local str = table.concat(bytes)
	local value = basexx.to_crockford(str)
	return value
end

local module = {}

local Result = {}
Result.__index = Result
module.Result = Result
Result.Success = false
function Result.new(message)
	return setmetatable({Message = message}, Result)
end
function Result.failure(message)
	return setmetatable({Success = false, Message = message}, Result)
end
function Result.success(...)
	return setmetatable({Success = true, ...}, Result)
end
function Result.is(obj)
	return type(obj) == 'table' and getmetatable(obj) == Result
end
function Result:__tostring()
	if self.Success then
		return "Success"
	else
		return tostring(self.Message or "Unknown failure")
	end
end
function Result:Unwrap()
	if self.Success then
		return unpack(self)
	else
		error(self.Message)
	end
end

local CodeSuccess = {}
CodeSuccess.__index = CodeSuccess
module.CodeSuccess = CodeSuccess
CodeSuccess.Success = true
function CodeSuccess.new(tbl)
	return setmetatable(tbl, CodeSuccess)
end
function CodeSuccess.is(obj)
	return type(obj) == 'table' and getmetatable(obj) == CodeSuccess
end
function Result:__tostring()
	return "Success"
end
function CodeSuccess:Unwrap()
	return self
end

local function validateInteger(number)
	if not tonumber(number) or ("%d"):format(tonumber(number)):match("%D") then
		return false
	end
	return number
end

function CodeSuccess:GetValidationString(player)
	local user = self.User
	if self.CodeTag == "i" then
		local userId
		if type(player) == "string" then
			userId = player
		elseif type(player) == "number" then
			userId = player
		elseif type(player) == "Instance" then
			if player:IsA("Player") then
				userId = player.UserId
			else
				error("Bad argument #1 to GetValidationString: expected String, Integer or Player, got Instance::"..player.ClassName.." ("..tostring(player)..")")
			end
		else
			error("Bad argument #1 to GetValidationString: expected String, Integer or Player, got "..typeof(player).." ("..tostring(player)..")")
		end
		if type(userId) == "number" then
			userId = ("%d"):format(userId)
			if not userId or userId:match("%D") then
				error("Bad argument #1 to GetValidationString: expected String, Integer or Player, but the Integer given evaluated to "..tostring(userId).." from "..typeof(player).." ("..tostring(player)..")")
			end
		end
		user = userId
	end
	local codeParts = {}
	local function pushCodePart(part)
		if type(part) == "number" then
			part = ("%d"):format(part)
		else
			part = tostring(part)
		end
		codeParts[#codeParts + 1] = part:lower()
	end

	if self.Label then
		pushCodePart(self.Label)
	end
	if self.CodeTag ~= "p" then
		pushCodePart(user)
	end
	pushCodePart(self.Currency)
	if self.Limit then
		pushCodePart(self.Limit)
	end
	pushCodePart(self.CodeTag)
	return table.concat(codeParts, "-")
end

function CodeSuccess:CheckHash(key, bytes, ...)
	local authString = self:GetValidationString(...)
	if typeof(bytes) == 'table' then
		bytes = module.getRequiredLength(self.Currency, bytes)
	end
	local hash = hmacAuthHash(authString:lower(), key, bytes)
	local success = hash:upper() == self.Hash:sub(1, #hash):upper()
	return success
end

function CodeSuccess:CheckAndMarkLimit(timeout, retryOnAmbiguous)
	assert(type(timeout) == "number", "Expected number for argument 1, got "..typeof(timeout).." ("..tostring(timeout)..")")
	if self.CodeTag ~= "p" or not self.Limit then
		return Result.success(true)
	end
	local start = tick()
	local datastore
	local success, reason = pcall(function()
		datastore = game:GetService("DataStoreService"):GetOrderedDataStore("HashTwitterCodeUses")
	end)
	if not datastore then
		return Result.failure(tostring(reason))
	end
	local key = self:GetValidationString("limit")..self.Hash:lower()
	while true do
		local withinLimit
		success, reason = pcall(function()
			datastore:UpdateAsync(key, function(value)
				if not value then
					withinLimit = true
					return 1
				elseif value > self.Limit then
					withinLimit = false
					return
				else
					withinLimit = true
					return value + 1
				end
			end)
		end)
		if not success then
			if reason:match("^3%d%d") or (retryOnAmbiguous and reason:match("^%%d%d")) then
				if tick() + 10 < start + timeout then
					wait(10)
				else
					return Result.failure(reason)
				end
			else
				return Result.failure(reason)
			end
		else
			return Result.success(withinLimit)
		end
	end
end

function CodeSuccess:CheckIdentity(timeout, player)
	assert(type(timeout) == "number", "Expected number for argument 1, got "..typeof(timeout).." ("..tostring(timeout)..")")
	local userId
	if type(player) == "number" then
		userId = player
	elseif type(player) == "Instance" then
		if player:IsA("Player") then
			userId = player.UserId
		else
			error("Bad argument #1 to GetValidationString: expected Integer or Player, got Instance::"..player.ClassName.." ("..tostring(player)..")")
		end
	else
		error("Bad argument #1 to GetValidationString: expected Integer or Player, got "..typeof(player).." ("..tostring(player)..")")
	end
	if self.CodeTag ~= "n" then
		-- note: user id identity is checked in CheckHash
		return Result.success(true)
	end
	if self.CachedUserId == nil then
		local start = tick()
		local myUserId
		while true do
			local success, reason = pcall(function()
				myUserId = game:GetService("Players"):GetUserIdFromNameAsync(self.User)
			end)
			if not success then
				if reason:match("user does not exist") then
					self.CachedUserId = false
					return Result.success(false)
				else
					if tick() + 10 < start + timeout then
						wait(10)
					else
						return Result.failure(reason)
					end
				end
			else
				self.CachedUserId = myUserId
				break
			end
		end
	end
	if self.CachedUserId == false then
		return Result.success(false)
	end
	return Result.success(userId == self.CachedUserId)
end

function module.getRequiredLength(currency, requirements)
	for _, req in ipairs(requirements) do
		if currency <= req[1] then
			return req[2]
		end
	end
end

function module.decode(twitterCode)
	local parts = twitterCode:split("-")
	if #parts < 2 then
		return Result.failure("Code too small")
	end
	if #parts > 4 then
		return Result.failure("Code too large")
	end
	local technical = parts[#parts]:lower()
	local codeTag = technical:sub(1, 1)
	if codeTag ~= "p" and codeTag ~= "n" and codeTag ~= "i" then
		return Result.failure("Invalid codeTag")
	end
	local hash = technical:sub(2)
	if #hash == 0 then
		return Result.failure("Hash too small")
	end
	local bytes
	pcall(function()
		bytes = #basexx.from_crockford(hash)
	end)
	if not bytes or bytes == 0 then
		return Result.failure("Invalid hash")
	end
	local label, currency, limit, user
	if codeTag == "p" then
		if #parts == 4 then
			label, currency, limit = unpack(parts)
		elseif #parts == 3 then
			if tonumber(parts[1]) then
				currency, limit = unpack(parts)
			else
				label, currency = unpack(parts)
			end
		else
			currency = parts[1]
		end
	elseif codeTag == "u" then
		if #parts == 4 then
			label, user, currency = unpack(parts)
		elseif #parts == 3 then
			user, currency = unpack(parts)
		else
			return Result.failure("Code too small")
		end
	elseif codeTag == "i" then
		if #parts > 3 then
			return Result.failure("Code too large")
		elseif #parts == 3 then
			label, currency = unpack(parts)
		else
			currency = unpack(parts)
		end
	end
	if label and validateInteger(label) then
		return Result.failure("Label must not be an integer")
	end
	if currency and not validateInteger(currency) then
		return Result.failure("Currency must be a number")
	end
	if limit and not validateInteger(limit) then
		return Result.failure("Limit must be a number")
	end
	return CodeSuccess.new({
		CodeTag = codeTag,
		IsPublic = codeTag == "p",
		Label = label,
		Currency = currency and tonumber(currency),
		Limit = limit and tonumber(limit),
		Username = user,
		Hash = hash,
		Bytes = bytes,
	})
end

function module.generate(options)

    if not options.key then
        error("Missing required parameter: key");
	end
    if not options.public and not options.username and not options.userid then
        error("Missing required parameters: one of public, username, or userid");
	end
    if options.username and options.userid then
        error("Only one of username or userid is allowed");
	end
    if options.public and (options.username or options.userid) then
        error("Code must be public or personal, not both");
	end
    if not options.currency then
        error("Missing required parameter: currency");
	end
    if options.bytes and options.bytes.length%2 == 1 then
        error("Bytes should be specified in pairs of two (currency, bytes)");
	end
    if options.label and validateInteger(options.label) then
        error("Label must not be an integer");
	end
    if not options.public and options.limit then
        error("Limits cannot be used with personal codes")
	end

    local codeParts = {};
    local codePartsHash = {};

    local function pushCodePart(part, hidden)
		if type(part) == 'number' then
			part = validateInteger(part)
		else
			part = tostring(part)
		end
        if not hidden then
            codeParts.push(part);
        end
        codePartsHash.push(part:lower());
    end

    local codeTag = ""

    if options.label then
        pushCodePart(options.label)
    end
    if options.public then
        codeTag = "p"
	else
        if options.username then
            codeTag = "n"
            pushCodePart(options.username)
		elseif options.userid then
            codeTag = "i"
            pushCodePart(options.userid, true)
        end
    end
    pushCodePart(options.currency)
    if options.limit then
        pushCodePart(options.limit)
    end
    pushCodePart(codeTag, true)

    local authStr = table.concat(codePartsHash, "-")

	local myBytes = nil

    if options.bytes then
        for i = 1, #options.bytes, 2 do
            local currency = options.bytes[i]
            local bytes = options.bytes[i + 1]
            if options.currency <= currency then
               myBytes = bytes
            end
        end
    end

    local friendlyHash = hmacAuthHash(authStr, options.key, myBytes)

    codeParts.push(codeTag..friendlyHash)

    return friendlyHash
end

return module

--[[
Copyright (c) 2019 Corecii Cyr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
--]]