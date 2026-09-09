-- /*
--  * Copyright (c) 2026
--  *
--  * Hochschule Offenburg, University of Applied Sciences
--  * Institute for reliable Embedded Systems
--  * and Communications Electronic (ivESK)
--  *
--  * This file is licensed as described in the "LICENSE" file
--  * included within the root folder of this work.
--  */

-- SPsec Protocol Dissector for Wireshark

-- Plugin info
local spsec_info = {
    version = "1.0",
    author = "SPsec Protocol",
    description = "SPsec Protocol Dissector"
}
set_plugin_info(spsec_info)

-- Protocol constants
local CPMT_SESS_HELLO = 0
local CPMT_SESS_FINISH = 1
local CPMT_SESS_RDINIT = 2
local CPMT_SESS_RDSEG = 3
local CPMT_SESS_WRINIT = 4
local CPMT_SESS_WRSEG = 5
local CPMT_SESS_TERMINATE = 6
local CPMT_AUTH_TIME = 8
local CPMT_SYNC = 9
local CPMT_HB = 10
local CPMT_EVT = 11
local CPMT_INTERN_EVT = 12
local CPMT_INTERN_RD = 13

local AUTH_TAG_SIZE = 8
local RANDOM_SIZE = 16
local KEY_SELECTOR_SIZE = 4
local TIMESTAMP_SIZE = 8

-- Get the CAN and CANFD dissectors
local can_dissector = Dissector.get("can")
local canfd_dissector = Dissector.get("canfd")

-- CAN and CANFD fields accessed by the dissector
-- These are created at top level and will be nil if fields don't exist
local can_id_field = nil
local canfd_id_field = nil
local can_len_field = nil
local canfd_len_field = nil

-- Try to create field extractors safely
pcall(function()
    can_id_field = Field.new("can.id")
end)
pcall(function()
    canfd_id_field = Field.new("canfd.id")
end)
pcall(function()
    can_len_field = Field.new("can.len")
end)
pcall(function()
    canfd_len_field = Field.new("canfd.len")
end)

-- Load bit32 library or fallback to native bitwise operators for Lua 5.3+
local bit32 = rawget(_G, "bit32")
if not bit32 then
    local ok, m = pcall(require, "bit32")
    if ok then
        bit32 = m
    else
        local loader = rawget(_G, "load") or rawget(_G, "loadstring")
        if loader then
            bit32 = loader([[
                return {
                    band   = function(a, b) return a & b end,
                    bor    = function(a, b) return a | b end,
                    bxor   = function(a, b) return a ~ b end,
                    bnot   = function(a)    return ~a end,
                    lshift = function(a, n) return a << n end,
                    rshift = function(a, n) return a >> n end,
                }
            ]])()
        end
    end
end

-- Protocol name
local spsec_proto = Proto("spsec", "SPsec Protocol")

-- Field definitions
local f_can_id = ProtoField.uint32("spsec.id", "CAN ID", base.HEX)
local f_can_id_prefix = ProtoField.uint8("spsec.id_prefix", "CAN ID Prefix", base.HEX)
local f_can_id_counter = ProtoField.uint8("spsec.id_counter", "Message Counter", base.DEC)
local f_can_id_cpmt = ProtoField.uint8("spsec.id_cpmt", "CPMT Type", base.DEC, {
    [CPMT_SESS_HELLO] = "SESS_HELLO (0)",
    [CPMT_SESS_FINISH] = "SESS_FINISH (1)",
    [CPMT_SESS_RDINIT] = "SESS_RDINIT (2)",
    [CPMT_SESS_RDSEG] = "SESS_RDSEG (3)",
    [CPMT_SESS_WRINIT] = "SESS_WRINIT (4)",
    [CPMT_SESS_WRSEG] = "SESS_WRSEG (5)",
    [CPMT_SESS_TERMINATE] = "SESS_TERMINATE (6)",
    [CPMT_AUTH_TIME] = "AUTH_TIME (8)",
    [CPMT_SYNC] = "SYNC (9)",
    [CPMT_HB] = "HB (10)",
    [CPMT_EVT] = "EVT (11)",
    [CPMT_INTERN_EVT] = "INTERN_EVT (12)",
    [CPMT_INTERN_RD] = "INTERN_RD (13)",
})
local f_can_id_pid = ProtoField.uint8("spsec.id_pid", "Participant ID", base.DEC)
local f_can_id_direction = ProtoField.string("spsec.id_direction", "Direction")
local f_msg_type = ProtoField.string("spsec.msg_type", "Message Type")

-- Session establishment fields
local f_key_selector = ProtoField.bytes("spsec.key_selector", "Key Selector")
local f_random = ProtoField.bytes("spsec.random", "Random")
local f_auth_tag = ProtoField.bytes("spsec.auth_tag", "Auth Tag")

-- Read/Write operation fields
local f_ciphertext = ProtoField.bytes("spsec.ciphertext", "Ciphertext")
local f_data_len = ProtoField.uint16("spsec.data_len", "Data Length", base.DEC)

-- Time sync fields
local f_timestamp = ProtoField.bytes("spsec.timestamp", "Timestamp")
local f_csalt = ProtoField.bytes("spsec.csalt", "CSalt")

-- AppData fields
local f_secure_data = ProtoField.bytes("spsec.secure_data", "Secure Data")
local f_padding_size = ProtoField.uint8("spsec.padding_size", "Padding Size", base.DEC)
local f_padding_timestamp = ProtoField.bytes("spsec.padding_timestamp", "Padding+Timestamp")
local f_timestamp_lsbs = ProtoField.uint16("spsec.timestamp_lsbs", "Timestamp LSBs", base.HEX)

-- Heartbeat fields
local f_status = ProtoField.uint8("spsec.status", "Status", base.HEX)

spsec_proto.fields = {
    f_can_id, f_can_id_prefix, f_can_id_counter, f_can_id_cpmt, f_can_id_pid,
    f_can_id_direction, f_msg_type,
    f_key_selector, f_random, f_auth_tag,
    f_ciphertext, f_data_len,
    f_timestamp, f_csalt,
    f_secure_data, f_padding_size, f_padding_timestamp, f_timestamp_lsbs,
    f_status
}

-- Helper function to check if bit 7 is set (client message)
local function is_client_message(byte0)
    return bit32.band(byte0, 0x80) ~= 0
end

-- Helper function to extract padding and timestamp from combined bytes
local function extract_padding_timestamp(data, offset)
    local combined = data(offset, 2):uint()
    local padding = bit32.band(bit32.rshift(combined, 12), 0x0F)
    local timestamp_lsbs = bit32.band(combined, 0x0FFF)
    return padding, timestamp_lsbs
end

-- Helper function to parse CAN ID bytes
local function parse_can_id(can_id)
    local byte0 = bit32.band(can_id, 0xFF)
    local byte1 = bit32.band(bit32.rshift(can_id, 8), 0xFF)
    local byte2 = bit32.band(bit32.rshift(can_id, 16), 0xFF)
    local byte3 = bit32.band(bit32.rshift(can_id, 24), 0xFF)
    
    local is_client = is_client_message(byte0)
    local pid = bit32.band(byte0, 0x7F)
    local cpmt = byte1
    local counter = byte2
    local prefix = byte3
    
    return {
        byte0 = byte0,
        byte1 = byte1,
        byte2 = byte2,
        byte3 = byte3,
        is_client = is_client,
        pid = pid,
        cpmt = cpmt,
        counter = counter,
        prefix = prefix
    }
end

-- Session establishment dissectors
local function dissect_client_hello(subtree, payload, id_info)
    subtree:add(f_msg_type, "ClientHello")
    if payload:len() >= 20 then
        subtree:add(f_key_selector, payload(0, KEY_SELECTOR_SIZE))
        subtree:add(f_random, payload(KEY_SELECTOR_SIZE, RANDOM_SIZE))
    end
end

local function dissect_server_hello(subtree, payload, id_info)
    subtree:add(f_msg_type, "ServerHello")
    if payload:len() >= RANDOM_SIZE then
        subtree:add(f_random, payload(0, RANDOM_SIZE))
    end
end

local function dissect_client_finished(subtree, payload, id_info)
    subtree:add(f_msg_type, "ClientFinished")
    if payload:len() >= AUTH_TAG_SIZE then
        subtree:add(f_auth_tag, payload(0, AUTH_TAG_SIZE))
    end
end

local function dissect_server_finished(subtree, payload, id_info)
    subtree:add(f_msg_type, "ServerFinished")
    if payload:len() >= AUTH_TAG_SIZE then
        subtree:add(f_auth_tag, payload(0, AUTH_TAG_SIZE))
    end
end

-- Read operation dissectors
local function dissect_read_initiate_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "ReadInitiate Request")
    if payload:len() >= 8 + AUTH_TAG_SIZE then
        subtree:add(f_ciphertext, payload(0, 8))
        subtree:add(f_auth_tag, payload(8, AUTH_TAG_SIZE))
    end
end

local function dissect_read_initiate_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "ReadInitiate Response")
    if payload:len() >= 8 + AUTH_TAG_SIZE then
        subtree:add(f_ciphertext, payload(0, 8))
        subtree:add(f_auth_tag, payload(8, AUTH_TAG_SIZE))
    end
end

local function dissect_read_segment_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "ReadSegment Request")
    if payload:len() >= AUTH_TAG_SIZE then
        subtree:add(f_auth_tag, payload(0, AUTH_TAG_SIZE))
    end
end

local function dissect_read_segment_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "ReadSegment Response")
    if payload:len() >= AUTH_TAG_SIZE then
        local data_len = payload:len() - AUTH_TAG_SIZE
        if data_len > 0 then
            subtree:add(f_ciphertext, payload(0, data_len))
            subtree:add(f_data_len, data_len)
        end
        subtree:add(f_auth_tag, payload(data_len, AUTH_TAG_SIZE))
    end
end

-- Write operation dissectors
local function dissect_write_initiate_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "WriteInitiate Request")
    if payload:len() >= 8 + AUTH_TAG_SIZE then
        subtree:add(f_ciphertext, payload(0, 8))
        subtree:add(f_auth_tag, payload(8, AUTH_TAG_SIZE))
    end
end

local function dissect_write_initiate_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "WriteInitiate Response")
    if payload:len() >= 8 + AUTH_TAG_SIZE then
        subtree:add(f_ciphertext, payload(0, 8))
        subtree:add(f_auth_tag, payload(8, AUTH_TAG_SIZE))
    end
end

local function dissect_write_segment_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "WriteSegment Request")
    if payload:len() >= AUTH_TAG_SIZE then
        local data_len = payload:len() - AUTH_TAG_SIZE
        if data_len > 0 then
            subtree:add(f_ciphertext, payload(0, data_len))
            subtree:add(f_data_len, data_len)
        end
        subtree:add(f_auth_tag, payload(data_len, AUTH_TAG_SIZE))
    end
end

local function dissect_write_segment_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "WriteSegment Response")
    if payload:len() >= 4 + AUTH_TAG_SIZE then
        subtree:add(f_ciphertext, payload(0, 4))
        subtree:add(f_auth_tag, payload(4, AUTH_TAG_SIZE))
    end
end

-- Session management dissectors
local function dissect_session_terminate_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "SessionTerminate Request")
    if payload:len() >= AUTH_TAG_SIZE then
        subtree:add(f_auth_tag, payload(0, AUTH_TAG_SIZE))
    end
end

local function dissect_session_terminate_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "SessionTerminate Response")
    if payload:len() >= AUTH_TAG_SIZE then
        subtree:add(f_auth_tag, payload(0, AUTH_TAG_SIZE))
    end
end

-- Time sync dissectors
local function dissect_timesync_request(subtree, payload, id_info)
    subtree:add(f_msg_type, "TimeSync Request")
    if payload:len() >= RANDOM_SIZE then
        subtree:add(f_random, payload(0, RANDOM_SIZE))
    end
end

local function dissect_timesync_response(subtree, payload, id_info)
    subtree:add(f_msg_type, "TimeSync Response")
    if payload:len() >= TIMESTAMP_SIZE + 4 + AUTH_TAG_SIZE then
        subtree:add(f_timestamp, payload(0, TIMESTAMP_SIZE))
        subtree:add(f_csalt, payload(TIMESTAMP_SIZE, 4))
        subtree:add(f_auth_tag, payload(TIMESTAMP_SIZE + 4, AUTH_TAG_SIZE))
    end
end

-- Broadcast message dissectors
local function dissect_sync_broadcast(subtree, payload, id_info)
    subtree:add(f_msg_type, "SyncTime Broadcast")
    if payload:len() >= 10 then
        local secure_data_len = payload:len() - 10
        if secure_data_len > 0 then
            subtree:add(f_secure_data, payload(0, secure_data_len))
        end
        local padding, timestamp_lsbs = extract_padding_timestamp(payload, secure_data_len)
        subtree:add(f_padding_timestamp, payload(secure_data_len, 2))
        subtree:add(f_padding_size, padding)
        subtree:add(f_timestamp_lsbs, timestamp_lsbs)
        subtree:add(f_auth_tag, payload(secure_data_len + 2, AUTH_TAG_SIZE))
    end
end

local function dissect_heartbeat(subtree, payload, id_info)
    subtree:add(f_msg_type, "Heartbeat")
    subtree:add(f_status, id_info.counter)
    if payload:len() >= 10 then
        local secure_data_len = payload:len() - 10
        if secure_data_len > 0 then
            subtree:add(f_secure_data, payload(0, secure_data_len))
        end
        local padding, timestamp_lsbs = extract_padding_timestamp(payload, secure_data_len)
        subtree:add(f_padding_timestamp, payload(secure_data_len, 2))
        subtree:add(f_padding_size, padding)
        subtree:add(f_timestamp_lsbs, timestamp_lsbs)
        subtree:add(f_auth_tag, payload(secure_data_len + 2, AUTH_TAG_SIZE))
    end
end

-- Generic AppData dissector
local function dissect_app_data(subtree, payload, id_info)
    subtree:add(f_msg_type, "AppData")
    if payload:len() >= 10 then
        local secure_data_len = payload:len() - 10
        if secure_data_len > 0 then
            subtree:add(f_secure_data, payload(0, secure_data_len))
            subtree:add(f_data_len, secure_data_len)
        end
        local padding, timestamp_lsbs = extract_padding_timestamp(payload, secure_data_len)
        subtree:add(f_padding_timestamp, payload(secure_data_len, 2))
        subtree:add(f_padding_size, padding)
        subtree:add(f_timestamp_lsbs, timestamp_lsbs)
        subtree:add(f_auth_tag, payload(secure_data_len + 2, AUTH_TAG_SIZE))
    end
end

-- Main dissector function
function spsec_proto.dissector(buffer, pinfo, tree)
    -- Extract the CAN ID from the field extractor (similar to cyphal_can.lua)
    local can_id = nil
    
    -- Try CANFD first (most likely)
    if canfd_id_field then
        local can_id_fieldinfo = canfd_id_field()
        if can_id_fieldinfo then
            can_id = can_id_fieldinfo()
        end
    end
    
    -- Fallback to CAN
    if not can_id and can_id_field then
        local can_id_fieldinfo = can_id_field()
        if can_id_fieldinfo then
            can_id = can_id_fieldinfo()
        end
    end
    
    if not can_id then
        return
    end
    
    -- Mask to 29 bits (remove EFF flag if present)
    can_id = bit32.band(can_id, 0x1FFFFFFF)
    
    -- Parse CAN ID
    local id_info = parse_can_id(can_id)
    
    -- Check if this is an SPsec message by checking prefix byte
    local byte3 = id_info.prefix
    if byte3 ~= 0x1E and byte3 ~= 0x0A and byte3 ~= 0x06 and byte3 ~= 0x02 and byte3 ~= 0x12 then
        return
    end
    
    -- The buffer contains the payload (CAN dissector already extracted it)
    local payload = buffer
    
    -- Create SPsec subtree
    local subtree = tree:add(spsec_proto, payload(), "SPsec Protocol")
    
    -- Add CAN ID fields
    local id_tree = subtree:add(f_can_id, can_id)
    id_tree:add(f_can_id_prefix, id_info.prefix)
    id_tree:add(f_can_id_counter, id_info.counter)
    id_tree:add(f_can_id_cpmt, id_info.cpmt)
    id_tree:add(f_can_id_pid, id_info.pid)
    id_tree:add(f_can_id_direction, id_info.is_client and "Client" or "Server")
    
    -- Route to appropriate dissector based on CAN ID pattern
    if id_info.prefix == 0x1E then
        -- Session messages
        if id_info.cpmt == CPMT_SESS_HELLO and id_info.counter == 0xFF then
            if id_info.is_client then
                dissect_client_hello(subtree, payload, id_info)
            else
                dissect_server_hello(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_FINISH then
            if id_info.is_client then
                dissect_client_finished(subtree, payload, id_info)
            else
                dissect_server_finished(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_RDINIT then
            if id_info.is_client then
                dissect_read_initiate_request(subtree, payload, id_info)
            else
                dissect_read_initiate_response(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_RDSEG then
            if id_info.is_client then
                dissect_read_segment_request(subtree, payload, id_info)
            else
                dissect_read_segment_response(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_WRINIT then
            if id_info.is_client then
                dissect_write_initiate_request(subtree, payload, id_info)
            else
                dissect_write_initiate_response(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_WRSEG then
            if id_info.is_client then
                dissect_write_segment_request(subtree, payload, id_info)
            else
                dissect_write_segment_response(subtree, payload, id_info)
            end
        elseif id_info.cpmt == CPMT_SESS_TERMINATE then
            if id_info.is_client then
                dissect_session_terminate_request(subtree, payload, id_info)
            else
                dissect_session_terminate_response(subtree, payload, id_info)
            end
        end
    elseif id_info.prefix == 0x0A and id_info.counter == 0xFF and id_info.cpmt == CPMT_AUTH_TIME and not id_info.is_client then
        dissect_timesync_request(subtree, payload, id_info)
    elseif id_info.prefix == 0x06 and id_info.counter == 0x23 and id_info.cpmt == CPMT_AUTH_TIME and id_info.is_client then
        dissect_timesync_response(subtree, payload, id_info)
    elseif id_info.prefix == 0x02 and id_info.counter == 0x21 and id_info.cpmt == CPMT_SYNC and id_info.pid == 0x00 then
        dissect_sync_broadcast(subtree, payload, id_info)
    elseif id_info.prefix == 0x12 and id_info.cpmt == CPMT_HB and not id_info.is_client then
        dissect_heartbeat(subtree, payload, id_info)
    else
        -- Generic AppData
        dissect_app_data(subtree, payload, id_info)
    end
    
    -- Update protocol column
    pinfo.cols.protocol = spsec_proto.name
end

-- Register as a subdissector for CAN and CANFD protocols
-- This allows it to be used via "Decode As" or automatically for matching CAN IDs
local can_table = DissectorTable.get("can.subdissector")
if can_table then
    can_table:add_for_decode_as(spsec_proto)
end

local canfd_table = DissectorTable.get("canfd.subdissector")
if canfd_table then
    canfd_table:add_for_decode_as(spsec_proto)
end

pcall(function()
    spsec_proto:register_heuristic("can", spsec_proto.dissector)
end)
