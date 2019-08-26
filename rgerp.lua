rgerp = Proto("RGERP", "RGERP", "Redundant Gigabit Ethernet Ring Protocol")

local f = rgerp.fields
local vs_ringState = {[0]="normal",[1]="abnormal"}
-- no idea why portstate 6 is up, but this works. I expected 0 down 1 up or 1 down 2 up.
local vs_portState = {[1]="rx below",[0]="down",[6]="up"}

f.packetType = ProtoField.string("rgerp.packetType","LLC Type")
f.ringId = ProtoField.uint16("rgerp.ringId", "Ring ID")
f.ringState = ProtoField.uint16("rgerp.ringState", "Ring State",base.DEC,vs_ringState)
f.ringMaster = ProtoField.ether("rgerp.ringMaster","Ring Master")

f.portState = ProtoField.uint16("rgerp.portState", "Port State",base.DEC,vs_portState)
f.portId = ProtoField.uint16("rgerp.portId", "Port ID")
f.packetSender = ProtoField.ether("rgerp.packetSender","Packet Sender")


local packet_counter
function rgerp.init()
    packet_counter = 0
end

function rgerp.dissector(buffer, pinfo, tree)
    local subtree = tree:add(rgerp, buffer())
    
    --tree additions
    local packetType
    if string.sub(tostring(pinfo.dst),-1)=='2' then
        packetType="LINK_CHANGE_DOWN"
    elseif string.sub(tostring(pinfo.dst),-1)=='3' then
        packetType="LINK_CHANGE_UP"
    else
        packetType="WATCHDOG"
    end
    subtree:add(f.packetType, packetType)
    
    local offset=0
    if packetType=="WATCHDOG" then
        local ringId = buffer(offset,1)
        subtree:add (f.ringId, ringId)
        offset=offset+1
        
        local ringState = buffer(offset,1)
        subtree:add(f.ringState, ringState)
        offset=offset+1
        
        local ringMaster = buffer(offset,6)
        subtree:add(f.ringMaster, ringMaster)
        offset=offset+6
        
        -- modify columns; replace LLC with custom
        pinfo.cols['protocol'] = "RGERP"
        pinfo.cols.info = "Ring ID: "
        --pinfo.cols.info:append('test'..tostring(pinfo.dst).."/test")
        pinfo.cols.info:append(ringId:uint())
        pinfo.cols.info:append(", ring status: ")
        pinfo.cols.info:append(vs_ringState[ringState:uint()])
        pinfo.cols.info:append(", RM: "..tostring(ringMaster))
        pinfo.cols.info:append(", packet type: "..packetType)
    else
        --linkchange
        local portState = buffer(offset,1)
        subtree:add (f.portState, portState)
        offset = offset+1
        
        local portId = buffer(offset,1)
        subtree:add (f.portId, portId)
        offset = offset+1
        
        local packetSender = buffer(offset,6)
        subtree:add (f.packetSender, packetSender)
        offset = offset+6
        
        local ringId = buffer(offset+1,1)
        subtree:add (f.ringId, ringId)
        offset=offset+1
        
        pinfo.cols['protocol'] = "RGERP"
        pinfo.cols.info = "Ring ID: "
        pinfo.cols.info:append(ringId:uint())
        pinfo.cols.info:append(", node "..tostring(packetSender))        
        pinfo.cols.info:append(" port "..portId:uint().." is ")
        pinfo.cols.info:append(vs_portState[portState:uint()])
        pinfo.cols.info:append(", packet type: "..packetType)        
    end
end

local llc_table = DissectorTable.get("llc.dsap")
llc_table:add(0x6b, rgerp)