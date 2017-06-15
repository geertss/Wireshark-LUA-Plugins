jetview = Proto("JETVIEW", "JETVIEW", "JetView Protocol")

local f = jetview.fields
local tlv_type = {
[1]="TLV_COMPANY_NAME",
[2]="TLV_MODEL_NAME",
[3]="TLV_MAC_ADD",
[4]="TLV_IP_ADD",
[5]="TLV_IP_MASK",
[6]="TLV_IP_GW",
[7]="TLV_DISCOVERY",
[8]="TLV_DISCOVERY_RESP",
[9]="TLV_MULTICAST_SUPPORT",
[11]="TLV_IP_CFG_SET",
[12]="TLV_IP_CFG_OK",
[13]="TLV_IP_CFG_FAILED",
[14]="TLV_IP_CFG_DHCP",
[21]="TLV_CFG_FILE_BACKUP",
[22]="TLV_CFG_FILE_BACKUP",
[23]="TLV_CFG_FILE_BACKUP_OK",
[24]="TLV_CFG_FILE_BACKUP_FAILED",
[25]="TLV_CFG_FILE_RESTORE_OK",
[26]="TLV_CFG_FILE_RESTORE_FAILED",
[27]="TLV_CFG_LOAD_DEFAULT",
[31]="TLV_FW_UPGRADE",
[32]="TLV_FW_UPGRADE_OK",
[33]="TLV_FW_UPGRADE_FAILED",
[34]="TLV_FW_VERSION",
[35]="TLV_BLOADER_UPGRADE",
[36]="TLV_BLOADER_UPGRADE_OK",
[37]="TLV_BLOADER_UPGRADE_FAILED",
[41]="TLV_REBOOT",
[42]="TLV_REBOOT_ACK",
[43]="TLV_TFTP_CLEAR_FILE",
[44]="TLV_REBOOT_B",
[45]="TLV_LOAD_FACTORY_DEFAULT",
[46]="TLV_REBOOT_FAILED",
[91]="TLV_LED_SIGNAL_ON",
[92]="TLV_LED_SIGNAL_OFF",
[93]="TLV_SYS_STATUS",
[94]="TLV_SFP_CHK",
[95]="TLV_SFP_CHK_OK",
[96]="TLV_SFP_CHK_FAILED",
[97]="TLV_SFP_CHK_OK",
[110]="TLV_SYS_ERROR_JFFS2FS",
[111]="TLV_SELF_TEST",
[112]="TLV_SELF_TEST_DONE",
[113]="TLV_SELF_TEST_FAILED",
[114]="TLV_SELF_TEST_NOT_SUPPORT",
[222]="TLV_AUTH_CHECK",
[223]="TLV_AHTH_CHECK_OK",
[224]="TLV_AUTH_CHECK_FAILED",
}

f.packetType = ProtoField.string("jetview.packetType","UDP")
f.tlvtype = ProtoField.uint16("jetview.tlvType", "Type",base.DEC,tlv_type)
f.tlvlength = ProtoField.uint16("jetview.tlvLength", "Length",base.DEC)
f.tlvvalue = ProtoField.string("jetview.tlvValue", "Value",base.DEC,tlv_value)
f.tlvmac = ProtoField.ether("jetview.tlvMac", "MACAddress",base.DEC,tlv_value)

local packet_counter
function jetview.init()
    packet_counter = 0
end

function jetview.dissector(buffer, pinfo, tree)
    --tree additions
    local packetType
    local subtree = tree:add(jetview, buffer(),"JETVIEW")
    local offset=0 
    while offset < buffer:len() do
        
        local tlvtype = buffer(offset,4)
        local subtree1 = subtree:add(tlv_type[tlvtype:uint()])
        subtree1:add(f.tlvtype, tlvtype)
        pinfo.cols['protocol'] = tlv_type[tlvtype:uint()]
        pinfo.cols.info:append(" " .. tostring(tlv_type[tlvtype:uint()]))
        offset=offset+4

        local tlvlength = buffer(offset,4)
        subtree1:add(f.tlvlength,tlvlength)
        offset=offset+4
        pinfo.cols.info:append(" : ")
        if tlvlength:uint() > 0 then 
            local tlvvalue = buffer(offset,tlvlength:uint())
            if tlvtype:uint() == 3 then 
                subtree1:add(f.tlvmac,tlvvalue)
                pinfo.cols.info:append(tostring(tlvvalue:ether()))
            else
                subtree1:add(f.tlvvalue,tlvvalue)
                pinfo.cols.info:append(tostring(tlvvalue:string()))
            end
        else
            pinfo.cols.info:append("")
        end
        pinfo.cols.info:append(", ")
        offset = offset + tlvlength:uint()
    end
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(5010, jetview)