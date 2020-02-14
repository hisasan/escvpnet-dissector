-- ESC/VP.net protocol dissector for Wireshark
-- Version 0.1.0
-- Author H.Doi

escvpnet = Proto("ESCVPNET","ESC/VP.net")

typeid = {
	[0] = "NULL (reserved)",
	[1] = "HELLO",
	[2] = "PASSWORD",
	[3] = "CONNECT"
}

statuscode = {
	[0x00] = "Always set 0x00 since it is a request",
	[0x20] = "OK",
	[0x40] = "Bad Request",
	[0x41] = "Unauthorized",
	[0x43] = "Forbidden",
	[0x45] = "Request not allowed",
	[0x53] = "Service Unavailable",
	[0x55] = "Protocol Version Not Supported"
}

header_id = {
	[0] = "NULL (reserved)",
	[1] = "Password",
	[2] = "New-Password",
	[3] = "Projector-Name",
	[4] = "IM-Type",
	[5] = "Projector-Command-Type",
}

header_attr_password = {
	[0] = "no password",
	[1] = "Plain (no encoding)"
}

header_attr_projectorname = {
	[0] = "no projector name",
	[1] = "US-ASCII",
	[2] = "Shift-JIS (Reserved)",
	[3] = "EUC-JP (Reserved)"
}

header_attr_imtype = {
	[10] = "(Reserved)",
	[11] = "(Reserved)",
	[12] = "Type D",
	[13] = "(Reserved)",
	[14] = "(Reserved)",
	[15] = "(Reserved)",
	[16] = "Type A",
	[17] = "(Reserved)",
	[18] = "(Reserved)",
	[19] = "(Reserved)",
	[20] = "Initial model of EMP/PL-735",
	[21] = "Type C, Type E",
	[22] = "Type F",
	[23] = "Type G",
	[24] = "(Reserved)",
	[25] = "(Reserved)",
	[26] = "(Reserved)",
	[27] = "(Reserved)",
	[28] = "(Reserved)",
	[29] = "(Reserved)",
	[30] = "Type B",
	[31] = "(Reserved)",
	[32] = "(Reserved)",
	[33] = "(Reserved)",
	[34] = "(Reserved)",
	[35] = "(Reserved)",
	[36] = "(Reserved)",
	[37] = "(Reserved)",
	[38] = "(Reserved)",
	[39] = "(Reserved)",
	[40] = "Type H",
	[41] = "Type I",
	[42] = "Type J",
	[43] = "(Reserved)",
	[44] = "(Reserved)",
	[45] = "(Reserved)",
	[46] = "(Reserved)",
	[47] = "(Reserved)",
	[48] = "(Reserved)",
	[49] = "(Reserved)",
	[50] = "Type K",
	[51] = "(Reserved)",
	[52] = "(Reserved)",
	[53] = "(Reserved)",
	[54] = "(Reserved)",
	[55] = "(Reserved)",
	[56] = "(Reserved)",
	[57] = "(Reserved)",
	[58] = "(Reserved)",
	[59] = "(Reserved)"
}

header_attr_projectorcommandtype = {
	[0x22] = "ESC/VP Level6 (Reserved)",
	[0x31] = "ESC/VP21 Ver1.0"
}

clientlist = {}

escvpnet.fields.typeid            = ProtoField.uint8("escvpnet.typeid",            "Type identifier",        base.HEX, typeid)
escvpnet.fields.statuscode        = ProtoField.uint8("escvpnet.statuscode",        "Status code",            base.HEX, statuscode)
escvpnet.fields.numberofheaders   = ProtoField.uint8("escvpnet.numberofheaders",   "Number of headers",      base.HEX)
escvpnet.fields.header_id         = ProtoField.uint8("escvpnet.header.id",         "Header identifier",      base.HEX, header_id)
escvpnet.fields.header_attr_password      = ProtoField.uint8("escvpnet.header.attr.password",      "Header attribute value", base.HEX, header_attr_password)
escvpnet.fields.header_attr_projectorname = ProtoField.uint8("escvpnet.header.attr.projectorname", "Header attribute value", base.HEX, header_attr_projectorname)
escvpnet.fields.header_attr_imtype        = ProtoField.uint8("escvpnet.header.attr.imtype",        "Header attribute value", base.HEX, header_attr_imtype)
escvpnet.fields.header_attr_projectorcommandtype = ProtoField.uint8("escvpnet.header.attr.projectorcommandtype", "Header attribute value", base.HEX, header_attr_projectorcommandtype)
escvpnet.fields.header_information = ProtoField.string("escvpnet.header.information", "Header information")

function escvpnet.dissector(buffer, pinfo, tree)
	local datalen = buffer:len()
	local src = tostring(pinfo.src)
	local seqtype = ""

	pinfo.cols.protocol = escvpnet.description

	if datalen < 16 or buffer(0, 10):string() ~= "ESC/VP.net" then
		if clientlist[src] ~= nil then
			seqtype = "Command"
		else
			seqtype = "Return code"
		end
		pinfo.cols.info = seqtype
		local subtree = tree:add(escvpnet, buffer(), escvpnet.description .. " (" .. seqtype .. ")")
		local offset = 0
		for i = 0, datalen - 1 do
			local code = buffer(i, 1):uint()
			if code == 0x0d or code == 0x3a then
				local val = buffer(offset, i - offset + 1):string()
				pinfo.cols.info:append(" " .. val)
				if code == 0x0d then
					val = val .. "¥r"
				end
				local item = subtree:add(buffer(offset, i - offset + 1), val)
				offset = i + 1
			end
		end
		return
	end

	local status = buffer(14, 1):uint()
	if status == 0 then
		seqtype = "Request"
	else
		seqtype = "Response"
	end

	local subtree = tree:add(escvpnet, buffer(), escvpnet.description .. " (" .. seqtype .. ")")

	subtree:add(buffer(0, 10), "Protocol identifier:", buffer(0, 10):string())
	local ver = buffer(10, 1):uint()
	subtree:add(buffer(10, 1), "Version identifier:", bit32.rshift(ver, 4) .. "." .. bit32.band(ver, 0x0f))
	subtree:add(escvpnet.fields.typeid,          buffer(11, 1))
	subtree:add(escvpnet.fields.statuscode,      buffer(14, 1))
	subtree:add(escvpnet.fields.numberofheaders, buffer(15, 1))

	if (buffer(11, 1):uint() == 3 and buffer(14, 1):uint() == 0) then
		clientlist[src] = pinfo.number
	end

	local typestr   = typeid[buffer(11, 1):uint()] or "Unknown"
	local statusstr = statuscode[buffer(14, 1):uint()] or "Unknown"

	pinfo.cols.info = seqtype .. " " .. typestr .. " " .. statusstr

	local headersize = buffer(15, 1):uint()
	if headersize == 0 then
		return
	end

	local offset = 16
	for i = 1, headersize do
		local htree = subtree:add(buffer(offset, 18), "Header " .. i)
		htree:add(escvpnet.fields.header_id, buffer(offset, 1))
		local htype = buffer(offset, 1):uint()
		if htype == 1 or htype == 2 then
			htree:add(escvpnet.fields.header_attr_password, buffer(offset + 1, 1))
		elseif htype == 3 then
			htree:add(escvpnet.fields.header_attr_projectorname, buffer(offset + 1, 1))
		elseif htype == 4 then
			htree:add(escvpnet.fields.header_attr_imtype, buffer(offset + 1, 1))
		elseif htype == 5 then
			htree:add(escvpnet.fields.header_attr_projectorcommandtype, buffer(offset + 1, 1))
		end
		htree:add(escvpnet.fields.header_information, buffer(offset + 2, 16))
		offset = offset + 18
	end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3629, escvpnet)
tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(3629, escvpnet)
