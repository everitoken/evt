from . import evt_exception, libevt
from .evt_data import EvtData


def version():
    return libevt.init_lib()


def json_to_bin(action, json):
    evt = libevt.check_lib_init()
    action_c = bytes(action, encoding='utf-8')
    json_c = bytes(json, encoding='utf-8')
    bin_c = evt.ffi.new('evt_bin_t**')
    ret = evt.lib.evt_abi_json_to_bin(
        evt.abi, action_c, json_c, bin_c)
    evt_exception.evt_exception_raiser(ret)
    return EvtData(bin_c[0])


def bin_to_json(action, bin):
    evt = libevt.check_lib_init()
    action_c = bytes(action, encoding='utf-8')
    bin_c = bin.data
    json_c = evt.ffi.new('char** ')
    ret = evt.lib.evt_abi_bin_to_json(
        evt.abi, action_c, bin_c, json_c)
    evt_exception.evt_exception_raiser(ret)
    json = evt.ffi.string(json_c[0]).decode('utf-8')
    ret = evt.lib.evt_free(json_c[0])
    evt_exception.evt_exception_raiser(ret)
    return json


def trx_json_to_digest(json, chain_id):
    evt = libevt.check_lib_init()
    json_c = bytes(json, encoding='utf-8')
    chain_id_c = chain_id.data
    digest_c = evt.ffi.new('evt_checksum_t**')
    ret = evt.lib.evt_trx_json_to_digest(
        evt.abi, json_c, chain_id_c, digest_c)
    evt_exception.evt_exception_raiser(ret)
    return EvtData(digest_c[0])


class ChainId(EvtData):
    def __init__(self, data):
        super().__init__(data)

    @staticmethod
    def from_string(str):
        evt = libevt.check_lib_init()
        str_c = bytes(str, encoding='utf-8')
        chain_id_c = evt.ffi.new('evt_chain_id_t**')
        ret = evt.lib.evt_chain_id_from_string(str_c, chain_id_c)
        evt_exception.evt_exception_raiser(ret)
        return ChainId(chain_id_c[0])


class BlockId(EvtData):
    def __init__(self, data):
        super().__init__(data)

    @staticmethod
    def from_string(str):
        evt = libevt.check_lib_init()
        str_c = bytes(str, encoding='utf-8')
        block_id_c = evt.ffi.new('evt_block_id_t**')
        ret = evt.lib.evt_block_id_from_string(str_c, block_id_c)
        evt_exception.evt_exception_raiser(ret)
        return BlockId(block_id_c[0])

    def ref_block_num(self):
        uint16_c = self.evt.ffi.new('uint16_t*')
        ret = self.evt.lib.evt_ref_block_num(self.data, uint16_c)
        evt_exception.evt_exception_raiser(ret)
        return int(uint16_c[0])

    def ref_block_prefix(self):
        uint32_c = self.evt.ffi.new('uint32_t*')
        ret = self.evt.lib.evt_ref_block_prefix(self.data, uint32_c)
        evt_exception.evt_exception_raiser(ret)
        return int(uint32_c[0])
