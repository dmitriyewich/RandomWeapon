script_name("RandomWeap")
script_author("dmitriyewich")
script_url("https://vk.com/dmitriyewichmods", 'https://github.com/dmitriyewich/RandomWeapon')
script_properties('work-in-pause', 'forced-reloading-only')
script_version("0.1")

local lffi, ffi = pcall(require, 'ffi')
local lmemory, memory = pcall(require, 'memory')

local lencoding, encoding = pcall(require, 'encoding')
encoding.default = 'CP1251'
u8 = encoding.UTF8

local folder =  getGameDirectory() .."\\modloader\\RandomWeapon\\RandomWeapon.ide"
local folder_txt =  getGameDirectory() .."\\modloader\\RandomWeapon\\RandomWeapon.txt"
local folder_custom =  getGameDirectory() .."\\modloader\\RandomWeapon\\CUSTOM.ide"

changelog = [[
	RandomWeapon v0.1
		- Релиз
]]

-- AUTHOR main hooks lib: RTD/RutreD(https://www.blast.hk/members/126461/)
ffi.cdef[[
    int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
    void* VirtualAlloc(void* lpAddress, unsigned long dwSize, unsigned long  flAllocationType, unsigned long flProtect);
    int VirtualFree(void* lpAddress, unsigned long dwSize, unsigned long dwFreeType);
]]
local function copy(dst, src, len)
    return ffi.copy(ffi.cast('void*', dst), ffi.cast('const void*', src), len)
end
local buff = {free = {}}
local function VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return ffi.C.VirtualProtect(ffi.cast('void*', lpAddress), dwSize, flNewProtect, lpflOldProtect)
end
local function VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect, blFree)
    local alloc = ffi.C.VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
    if blFree then
        table.insert(buff.free, function()
            ffi.C.VirtualFree(alloc, 0, 0x8000)
        end)
    end
    return ffi.cast('intptr_t', alloc)
end
--JMP HOOKS
local jmp_hook = {hooks = {}}
function jmp_hook.new(cast, callback, hook_addr, size, trampoline, org_bytes_tramp)
    jit.off(callback, true) --off jit compilation | thx FYP
    local size = size or 5
    local trampoline = trampoline or false
    local new_hook, mt = {}, {}
    local detour_addr = tonumber(ffi.cast('intptr_t', ffi.cast(cast, callback)))
    local old_prot = ffi.new('unsigned long[1]')
    local org_bytes = ffi.new('uint8_t[?]', size)
    copy(org_bytes, hook_addr, size)
    if trampoline then
        local alloc_addr = VirtualAlloc(nil, size + 5, 0x1000, 0x40, true)
        local trampoline_bytes = ffi.new('uint8_t[?]', size + 5, 0x90)
        if org_bytes_tramp then
            local i = 0
            for byte in org_bytes_tramp:gmatch('(%x%x)') do
                trampoline_bytes[i] = tonumber(byte, 16)
                i = i + 1
            end
        else
            copy(trampoline_bytes, org_bytes, size)
        end
        trampoline_bytes[size] = 0xE9
        ffi.cast('int32_t*', trampoline_bytes + size + 1)[0] = hook_addr - tonumber(alloc_addr) - size + (size - 5)
        copy(alloc_addr, trampoline_bytes, size + 5)
        new_hook.call = ffi.cast(cast, alloc_addr)
        mt = {__call = function(self, ...)
            return self.call(...)
        end}
    else
        new_hook.call = ffi.cast(cast, hook_addr)
        mt = {__call = function(self, ...)
            self.stop()
            local res = self.call(...)
            self.start()
            return res
        end}
    end
    local hook_bytes = ffi.new('uint8_t[?]', size, 0x90)
    hook_bytes[0] = 0xE9
    ffi.cast('int32_t*', hook_bytes + 1)[0] = detour_addr - hook_addr - 5
    new_hook.status = false
    local function set_status(bool)
        new_hook.status = bool
        VirtualProtect(hook_addr, size, 0x40, old_prot)
        copy(hook_addr, bool and hook_bytes or org_bytes, size)
        VirtualProtect(hook_addr, size, old_prot[0], old_prot)
    end
    new_hook.stop = function() set_status(false) end
    new_hook.start = function() set_status(true) end
    new_hook.start()
    if org_bytes[0] == 0xE9 or org_bytes[0] == 0xE8 then
        print('[WARNING] rewrote another hook'.. (trampoline and ' (old hook was disabled, through trampoline)' or ''))
    end
    table.insert(jmp_hook.hooks, new_hook)
    return setmetatable(new_hook, mt)
end
--JMP HOOKS
--DELETE HOOKS
addEventHandler('onScriptTerminate', function(scr)
    if scr == script.this then
        for i, hook in ipairs(jmp_hook.hooks) do
            if hook.status then
                hook.stop()
            end
        end
        for i, free in ipairs(buff.free) do
            free()
        end
    end
end)
--DELETE HOOKS

local function isarray(t, emptyIsObject)
	if type(t)~='table' then return false end
	if not next(t) then return not emptyIsObject end
	local len = #t
	for k,_ in pairs(t) do
		if type(k)~='number' then
			return false
		else
			local _,frac = math.modf(k)
			if frac~=0 or k<1 or k>len then
				return false
			end
		end
	end
	return true
end

local function map(t,f)
	local r={}
	for i,v in ipairs(t) do r[i]=f(v) end
	return r
end

local keywords = {["and"]=1,["break"]=1,["do"]=1,["else"]=1,["elseif"]=1,["end"]=1,["false"]=1,["for"]=1,["function"]=1,["goto"]=1,["if"]=1,["in"]=1,["local"]=1,["nil"]=1,["not"]=1,["or"]=1,["repeat"]=1,["return"]=1,["then"]=1,["true"]=1,["until"]=1,["while"]=1}

local function neatJSON(value, opts) -- https://github.com/Phrogz/NeatJSON
	opts = opts or {}
	if opts.wrap==nil  then opts.wrap = 80 end
	if opts.wrap==true then opts.wrap = -1 end
	opts.indent         = opts.indent         or "  "
	opts.arrayPadding  = opts.arrayPadding  or opts.padding      or 0
	opts.objectPadding = opts.objectPadding or opts.padding      or 0
	opts.afterComma    = opts.afterComma    or opts.aroundComma  or 0
	opts.beforeComma   = opts.beforeComma   or opts.aroundComma  or 0
	opts.beforeColon   = opts.beforeColon   or opts.aroundColon  or 0
	opts.afterColon    = opts.afterColon    or opts.aroundColon  or 0
	opts.beforeColon1  = opts.beforeColon1  or opts.aroundColon1 or opts.beforeColon or 0
	opts.afterColon1   = opts.afterColon1   or opts.aroundColon1 or opts.afterColon  or 0
	opts.beforeColonN  = opts.beforeColonN  or opts.aroundColonN or opts.beforeColon or 0
	opts.afterColonN   = opts.afterColonN   or opts.aroundColonN or opts.afterColon  or 0

	local colon  = opts.lua and '=' or ':'
	local array  = opts.lua and {'{','}'} or {'[',']'}
	local apad   = string.rep(' ', opts.arrayPadding)
	local opad   = string.rep(' ', opts.objectPadding)
	local comma  = string.rep(' ',opts.beforeComma)..','..string.rep(' ',opts.afterComma)
	local colon1 = string.rep(' ',opts.beforeColon1)..colon..string.rep(' ',opts.afterColon1)
	local colonN = string.rep(' ',opts.beforeColonN)..colon..string.rep(' ',opts.afterColonN)

	local build -- set lower
	local function rawBuild(o,indent)
		if o==nil then
			return indent..'null'
		else
			local kind = type(o)
			if kind=='number' then
				local _,frac = math.modf(o)
				return indent .. string.format( frac~=0 and opts.decimals and ('%.'..opts.decimals..'f') or '%g', o)
			elseif kind=='boolean' or kind=='nil' then
				return indent..tostring(o)
			elseif kind=='string' then
				return indent..string.format('%q', o):gsub('\\\n','\\n')
			elseif isarray(o, opts.emptyTablesAreObjects) then
				if #o==0 then return indent..array[1]..array[2] end
				local pieces = map(o, function(v) return build(v,'') end)
				local oneLine = indent..array[1]..apad..table.concat(pieces,comma)..apad..array[2]
				if opts.wrap==false or #oneLine<=opts.wrap then return oneLine end
				if opts.short then
					local indent2 = indent..' '..apad;
					pieces = map(o, function(v) return build(v,indent2) end)
					pieces[1] = pieces[1]:gsub(indent2,indent..array[1]..apad, 1)
					pieces[#pieces] = pieces[#pieces]..apad..array[2]
					return table.concat(pieces, ',\n')
				else
					local indent2 = indent..opts.indent
					return indent..array[1]..'\n'..table.concat(map(o, function(v) return build(v,indent2) end), ',\n')..'\n'..(opts.indentLast and indent2 or indent)..array[2]
				end
			elseif kind=='table' then
				if not next(o) then return indent..'{}' end

				local sortedKV = {}
				local sort = opts.sort or opts.sorted
				for k,v in pairs(o) do
					local kind = type(k)
					if kind=='string' or kind=='number' then
						sortedKV[#sortedKV+1] = {k,v}
						if sort==true then
							sortedKV[#sortedKV][3] = tostring(k)
						elseif type(sort)=='function' then
							sortedKV[#sortedKV][3] = sort(k,v,o)
						end
					end
				end
				if sort then table.sort(sortedKV, function(a,b) return a[3]<b[3] end) end
				local keyvals
				if opts.lua then
					keyvals=map(sortedKV, function(kv)
						if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
							return string.format('%s%s%s',kv[1],colon1,build(kv[2],''))
						else
							return string.format('[%q]%s%s',kv[1],colon1,build(kv[2],''))
						end
					end)
				else
					keyvals=map(sortedKV, function(kv) return string.format('%q%s%s',kv[1],colon1,build(kv[2],'')) end)
				end
				keyvals=table.concat(keyvals, comma)
				local oneLine = indent.."{"..opad..keyvals..opad.."}"
				if opts.wrap==false or #oneLine<opts.wrap then return oneLine end
				if opts.short then
					keyvals = map(sortedKV, function(kv) return {indent..' '..opad..string.format('%q',kv[1]), kv[2]} end)
					keyvals[1][1] = keyvals[1][1]:gsub(indent..' ', indent..'{', 1)
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local indent2 = string.rep(' ',#(k..colonN))
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return table.concat(keyvals, ',\n')..opad..'}'
				else
					local keyvals
					if opts.lua then
						keyvals=map(sortedKV, function(kv)
							if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
								return {table.concat{indent,opts.indent,kv[1]}, kv[2]}
							else
								return {string.format('%s%s[%q]',indent,opts.indent,kv[1]), kv[2]}
							end
						end)
					else
						keyvals = {}
						for i,kv in ipairs(sortedKV) do
							keyvals[i] = {indent..opts.indent..string.format('%q',kv[1]), kv[2]}
						end
					end
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					local indent2 = indent..opts.indent
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return indent..'{\n'..table.concat(keyvals, ',\n')..'\n'..(opts.indentLast and indent2 or indent)..'}'
				end
			end
		end
	end

	-- indexed by object, then by indent level
	local function memoize()
		local memo = setmetatable({},{_mode='k'})
		return function(o,indent)
			if o==nil then
				return indent..(opts.lua and 'nil' or 'null')
			elseif o~=o then --test for NaN
				return indent..(opts.lua and '0/0' or '"NaN"')
			elseif o==math.huge then
				return indent..(opts.lua and '1/0' or '9e9999')
			elseif o==-math.huge then
				return indent..(opts.lua and '-1/0' or '-9e9999')
			end
			local byIndent = memo[o]
			if not byIndent then
				byIndent = setmetatable({},{_mode='k'})
				memo[o] = byIndent
			end
			if not byIndent[indent] then
				byIndent[indent] = rawBuild(o,indent)
			end
			return byIndent[indent]
		end
	end

	build = memoize()
	return build(value,'')
end

function savejson(table, path)
    local f = io.open(path, "w+")
    f:write(table)
    f:close()
end

function convertTableToJsonString(config)
	return (neatJSON(config, { wrap = 174, sort = true, aligned = true, arrayPadding = 1, afterComma = 1 }))
end

local config = {}

if doesFileExist("moonloader/config/RandomWeapon.json") then
    local f = io.open("moonloader/config/RandomWeapon.json")
    config = decodeJson(f:read("*a"))
    f:close()
else
	config = {["weapons"] = {}}

	if not doesDirectoryExist('moonloader/config') then createDirectory('moonloader/config') end

    savejson(convertTableToJsonString(config), "moonloader/config/RandomWeapon.json")
end

math.randomseed( os.clock()^5 )
math.random(); math.random(); math.random()

function random(min, max)
	local rand = math.random(min, max)
    return tonumber(rand)
end

local NameModel = {[321] = "gun_dildo1", [322] = "gun_dildo2", [323] = "gun_vibe1", [324] = "gun_vibe2",
	[325] = "flowera",  [326] = "gun_cane", [327] = "gun_boxwee", [328] = "gun_boxbig",
	[330] = "cellphone", [331] = "brassknuckle", [333] = "golfclub", [334] = "nitestick",
	[335] = "knifecur", [336] = "bat", [337] = "shovel", [338] = "poolcue", [339] = "katana",
	[341] = "chnsaw", [342] = "grenade", [343] = "teargas", [344] = "molotov", [345] = "missile",
	[346] = "colt45", [347] = "silenced", [348] = "desert_eagle", [349] = "chromegun", [350] = "sawnoff",
	[351] = "shotgspa", [352] = "micro_uzi", [353] = "mp5lng", [354] = "flare", [355] = "ak47", [356] = "m4",
	[357] = "cuntgun", [358] = "sniper", [359] = "rocketla", [360] = "heatseek", [361] = "flame", [362] = "minigun",
	[363] = "satchel", [364] = "bomb", [365] = "spraycan",
	[366] = "fire_ex", [367] = "camera", [368] = "nvgoggles", [369] = "irgoggles", [370] = "jetpack",
	[371] = "gun_para", [372] = "tec9", [373] = "armour"}

local standart_weap = [[321, gun_dildo1, gun_dildo1, null, 1, 50, 0
322, gun_dildo2, gun_dildo2, null, 1, 50, 0
323, gun_vibe1, gun_vibe1, null, 1, 50, 0
324, gun_vibe2, gun_vibe2, null, 1, 50, 0
325, flowera, flowera, null, 1, 30, 0
326, gun_cane, gun_cane, null, 1, 50, 0
327, gun_boxwee, gun_boxwee, colt45, 1, 50, 0
328, gun_boxbig, gun_boxbig, null, 1, 50, 0
330, cellphone, cellphone, null, 1, 50, 0
331, brassknuckle, brassknuckle, null, 1, 50, 0
333, golfclub, golfclub, null, 1, 50, 0
334, nitestick, nitestick, null, 1, 50, 0
335, knifecur, knifecur, null, 1, 50, 0
336, bat, bat, null, 1, 50, 0
337, shovel, shovel, null, 1, 50, 0
338, poolcue, poolcue, null, 1, 50, 0
339, katana, katana, null, 1, 50, 0
341, chnsaw, chnsaw, chainsaw, 1, 50, 0
342, grenade, grenade, grenade, 1, 100, 0
343, teargas, teargas, grenade, 1, 50, 0
344, molotov, molotov, grenade, 1, 100, 0
345, missile, missile, null, 1, 100, 0
346, colt45, colt45, colt45, 1, 30, 0
347, silenced, silenced, silenced, 1, 30, 0
348, desert_eagle, desert_eagle, python, 1, 30, 0
349, chromegun, chromegun, shotgun, 1, 50, 0
350, sawnoff, sawnoff, colt45, 1, 30, 0
351, shotgspa, shotgspa, buddy, 1, 50, 0
352, micro_uzi, micro_uzi, colt45, 1, 30, 0
353, mp5lng, mp5lng, uzi, 1, 50, 0
354, flare, flare, null, 1, 100, 0
355, ak47, ak47, rifle, 1, 50, 0
356, m4, m4, rifle, 1, 30, 0
357, cuntgun, cuntgun, rifle, 1, 50, 0
358, sniper, sniper, rifle, 1, 50, 0
359, rocketla, rocketla, rocket, 1, 50, 0
360, heatseek, heatseek, rocket, 1, 50, 0
361, flame, flame, flame, 1, 50, 0
362, minigun, minigun, flame, 1, 50, 0
363, satchel, satchel, grenade, 1, 50, 0
364, bomb, bomb, null, 1, 50, 0
365, spraycan, spraycan, spraycan, 1, 50, 0
366, fire_ex, fire_ex, flame, 1, 50, 0
367, camera, camera, rifle, 1, 50, 0
368, nvgoggles, nvgoggles, goggles, 1, 50, 0
369, irgoggles, irgoggles, goggles, 1, 50, 0
370, jetpack, jetpack, null, 1, 100, 0
371, gun_para, gun_para, null, 1, 100, 0
372, tec9, tec9, colt45, 1, 30, 0
373, armour, armour, null, 1, 30, 0]]

local tbl_this = {}

function AddWeaponModel(this, modelIndex)
	if config.weapons[tostring(modelIndex)] ~= nil then
		local need_id = config.weapons[tostring(modelIndex)][random(1, #config.weapons[tostring(modelIndex)])]
		if not hasModelLoaded(need_id) then
			requestModel(need_id)
			loadAllModelsNow()
		end
		tbl_this[this] = need_id
		modelIndex = need_id
	end
	AddWeaponModel(this, modelIndex)
end

function RemoveWeaponModel(this, modelIndex)
	if config.weapons[tostring(modelIndex)] ~= nil then
		modelIndex = tbl_this[this]
		tbl_this[this] = nil
	end
	RemoveWeaponModel(this, modelIndex)
end

function main()
	
	if script.find("RandomChar") and not doesFileExist(getGameDirectory() .."\\modloader\\RandomChar\\RandomChar.ide") then thisScript():unload() end
	if not doesFileExist(folder) then GeneratedIDE() end

	repeat wait(0) until memory.read(0xC8D4C0, 4, false) == 9
	repeat wait(0) until fixed_camera_to_skin()

	AddWeaponModel = jmp_hook.new("void (__thiscall *)(uintptr_t this, unsigned int modelIndex)", AddWeaponModel, 0x5E5ED0)
	RemoveWeaponModel = jmp_hook.new("void (__thiscall *)(uintptr_t this, unsigned int modelIndex)", RemoveWeaponModel, 0x5E3990)

	wait(-1)
end

function fixed_camera_to_skin() -- проверка на приклепление камеры к скину
	return (memory.read(getModuleHandle('gta_sa.exe') + 0x76F053, 1, false) >= 1 and true or false)
end

function GeneratedIDE()
	local freeID = {}
	os.remove(folder_custom)
	os.remove(folder_txt)
	for i = 1, 20000 do
		if not isModelAvailable(i) and not isModelInCdimage(i) then
			freeID[#freeID+1] = i
		end
	end

	local t={}
	for str in string.gmatch(standart_weap, "([^\n]+)") do
		
		local v_1, v_2, v_3 = tostring(str):match('^(.+),(.+,.+),(.+,.+,.+,.+)$')
		-- print(v_3)
		t[tonumber(v_1)] = v_3
	end

	config.weapons = {}

	local list = 'weap\n'
-- print(file)
	for k, v in pairs(NameModel) do
		local folder_dff = getGameDirectory() .."\\modloader\\RandomWeapon\\models\\" ..v.. "\\*.dff"
		local search, file = findFirstFile(folder_dff)
		if file ~= nil then config.weapons[tostring(k)] = {k} end
		while file do
			if file ~= (v..".dff") then
				local no_dff = file:gsub("%.dff", "")
				local char_new = freeID[1] .. ", " .. no_dff .. ", " .. no_dff .. ", " .. t[k] .. "\n"
				config.weapons[tostring(k)][#config.weapons[tostring(k)]+1] = tonumber(freeID[1])
				table.remove(freeID, 1)
				list = list .. char_new
			end
			file = findNextFile(search)
		end
	end
	
	list = list .. 'end'

	local file = io.open(folder, 'w+')
	file:write(list)
	file:close()

	local file = io.open(folder_custom, 'w+')
	file:write(list)
	file:close()

	local file = io.open(folder_txt, 'w+')
	file:write("IDE DATA\\MAPS\\RandomWeapon.ide")
	file:close()

	savejson(convertTableToJsonString(config), "moonloader/config/RandomWeapon.json")
	callFunction(0x81E5E6, 4, 0, 0, u8:decode"[RU] Сформированы:\n	RandomWeapon.ide\\CUSTOM.ide\\RandomWeapon.txt\n	Необходимо перезапустить игру\n[EN] Generated:\n	RandomWeapon.ide\\CUSTOM.ide\\RandomWeapon.txt\n	Need restart game", "RandomWeapon.lua", 0x00040000)
	os.execute('taskkill /IM gta_sa.exe /F /T')
end

-- Licensed under the GPL-3.0 License
-- Copyright (c) 2022, dmitriyewich <https://github.com/dmitriyewich/RandomWeapon>