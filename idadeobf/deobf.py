#!/usr/bin/env python

from idc import *


class BaseEmu(object):

    def __init__(self, pc=1):
        self.regs = {
            'R0': 1,
            'R1': 1,
            'R2': 1,
            'R3': 1,
            'R4': 1,
            'R5': 1,
            'R6': 1,
            'R7': 1,
            'R8': 1,
            'R9': 1,
            'R10': 1,
            'R11': 1,
            'R12': 1,
            'SP': 1,
            'LR': 1,
            'PC': pc
        }
        self.opts = {
            'MOV': self.mov,
            'MOVS': self.mov,
            'ADD': self.add,
            'ADDS': self.add,
            'ADR': self.adr,
            'LSL': self.lsl,
            'LSLS': self.lsl,
            'LDR': self.ldr
        }

    def mov_from_value(self, dst_reg, value):
        self.regs[dst_reg] = value

    def mov_from_reg(self, dst_reg, src_reg):
        self.regs[dst_reg] = self.regs[src_reg]

    def mov(self, opt_value):
        if len(opt_value) == 2:
            if self.is_value(opt_value[1]):
                self.mov_from_value(opt_value[0], self.get_value(opt_value[1]))
            else:
                self.mov_from_reg(opt_value[0], opt_value[1])

    def add(self, opt_value):
        if self.is_value(opt_value[2]):
            self.regs[opt_value[0]] = self.regs[opt_value[1]] + self.get_value(opt_value[2])
        else:
            self.regs[opt_value[0]] = self.regs[opt_value[1]] + self.regs[opt_value[2]]

    def adr(self, opt_value):
        self.regs[opt_value[0]] = self.read_value(opt_value)

    def get_adr(self, opt_value):
        print('!base emu')
        return 0

    def is_value(self, value_str):
        return value_str.startwith('#')

    def ldr(self, opt_value):
        if opt_value[0].startwith('='):
            self.regs[opt_value[0]] = self.get_value(opt_value[1])
        else:
            value = opt_value[1][1:-1]
            address = 0
            if value in self.regs:
                address = self.regs[value]
            else:
                address = int(value)
            self.regs[opt_value[0]] = self.read_address(address)

    def read_address(self, address):
        print('!base emu')
        return 0

    def lsl(self, opt_value):
        self.regs[opt_value[0]] = self.regs[opt_value[1]] << self.get_value(opt_value[2])

    def get_value(self, value_str):
        return int(value_str[1:])

    def unsupported(self, ins_str):
        print('unsupported instruction {}'.format(ins_str))

    def interpret(self, ins_str):
        opt, opt_value = self.get_ins(ins_str)
        if opt is None:
            return
        if opt in self.opts:
            self.opts[opt](opt_value)
        else:
            self.unsupported(ins_str)

    def get_ins(self, ins_str):
        print("!base emu")
        return None, None


class IdaDeObf(BaseEmu):

    def get_ins(self, ins_str):
        """
        从字符串中生成规则的指令
        :param ins_str: 指令字符串
        :return: 指令
        """
        first_space_index = ins_str.find(' ')
        opt = ins_str[:first_space_index]
        regs_str = ins_str[first_space_index:].strip()

        opt_value = regs_str.split(',')
        return opt, opt_value

    def get_adr(self, opt_value):
        return int(opt_value[opt_value.find('_')+1:], 16)

    def read_address(self, address):
        return Dword(address)

if __name__ == '__main__':
    func_start_addr = ScreenEA()
    func_end_addr = FindFuncEnd(func_start_addr)
    print("function start address is 0x{:08X}".format(func_start_addr))
    print("function end address is 0x{:08X}".format(func_end_addr))
    crt_addr = func_start_addr
    while crt_addr < func_end_addr:
        asm_str = GetDisasm(crt_addr)
        print("0x{:08X}    {}".format(crt_addr, asm_str))
        if asm_str.startswith('POP'):
            break
        crt_addr = crt_addr + ItemSize(crt_addr)

    print("[+] All Done!")
