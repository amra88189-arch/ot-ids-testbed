##! Log the target register/coil address and written value for every Modbus
##! write request — the command semantics the basic modbus.log discards.
##! extract.sh loads this; lab_convert.py reads modbus_detail.log into mb_reg/mb_val.

@load base/protocols/modbus

module ModbusDetail;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts:      time   &log;
        orig:    addr   &log;
        resp:    addr   &log;
        func:    string &log;
        address: count  &log &optional;
        value:   string &log &optional;
    };
}

event zeek_init() {
    Log::create_stream(ModbusDetail::LOG, [$columns=Info, $path="modbus_detail"]);
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                       address: count, value: bool) {
    Log::write(ModbusDetail::LOG, Info($ts=network_time(), $orig=c$id$orig_h, $resp=c$id$resp_h,
        $func="WRITE_SINGLE_COIL", $address=address, $value=cat(value)));
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count) {
    Log::write(ModbusDetail::LOG, Info($ts=network_time(), $orig=c$id$orig_h, $resp=c$id$resp_h,
        $func="WRITE_SINGLE_REGISTER", $address=address, $value=cat(value)));
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders,
                                          start_address: count, coils: ModbusCoils) {
    Log::write(ModbusDetail::LOG, Info($ts=network_time(), $orig=c$id$orig_h, $resp=c$id$resp_h,
        $func="WRITE_MULTIPLE_COILS", $address=start_address, $value=cat(coils)));
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                              start_address: count, registers: ModbusRegisters) {
    Log::write(ModbusDetail::LOG, Info($ts=network_time(), $orig=c$id$orig_h, $resp=c$id$resp_h,
        $func="WRITE_MULTIPLE_REGISTERS", $address=start_address, $value=cat(registers)));
}
