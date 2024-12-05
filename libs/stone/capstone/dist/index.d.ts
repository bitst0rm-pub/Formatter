type CallType = 'string' | 'boolean' | 'number' | 'array' | null;

declare const METHODS_TYPES: Record<"cs_open" | "cs_disasm" | "cs_free" | "cs_close" | "cs_option" | "cs_reg_name" | "cs_op_count" | "cs_op_index" | "cs_insn_name" | "cs_group_name" | "cs_insn_group" | "cs_reg_read" | "cs_reg_write" | "cs_errno" | "cs_version" | "cs_support" | "cs_strerror" | "cs_regs_access" | "malloc" | "free", {
    returnType: CallType;
    argTypes: CallType[];
}>;
type MethodName = keyof typeof METHODS_TYPES;
interface Insn {
    id: number;
    address: number | bigint;
    size: number;
    bytes: Uint8Array;
    mnemonic: string;
    opStr: string;
}
declare class Capstone {
    arch: number;
    mode: number;
    handle_ptr: number | null;
    constructor(arch: number, mode: number);
    get handle(): number;
    setOption(opt: number, value: any): number;
    close(): void;
    private static readInsn;
    disasm(data: number[] | Uint8Array, options?: {
        address?: number | bigint;
        count?: number;
    }): Insn[];
    getRegName(id: number): string;
    getInsnName(id: number): string;
    getGroupName(id: number): string;
    errNo(): number;
    static call(name: MethodName, ...args: any[]): any;
    static version(): {
        major: number;
        minor: number;
    };
    static support(query: number): boolean;
    static strError(errNo: number): string;
}
declare function factory(args?: Record<string, unknown>): Promise<void>;

declare const CS_API_MAJOR = 5;
declare const CS_API_MINOR = 0;
declare const CS_ARCH_ARM = 0;
declare const CS_ARCH_ARM64 = 1;
declare const CS_ARCH_MIPS = 2;
declare const CS_ARCH_X86 = 3;
declare const CS_ARCH_PPC = 4;
declare const CS_ARCH_SPARC = 5;
declare const CS_ARCH_SYSZ = 6;
declare const CS_ARCH_XCORE = 7;
declare const CS_ARCH_M68K = 8;
declare const CS_ARCH_TMS320C64X = 9;
declare const CS_ARCH_M680X = 10;
declare const CS_ARCH_MAX = 11;
declare const CS_ARCH_ALL = 65535;
declare const CS_MODE_LITTLE_ENDIAN = 0;
declare const CS_MODE_ARM = 0;
declare const CS_MODE_16: number;
declare const CS_MODE_32: number;
declare const CS_MODE_64: number;
declare const CS_MODE_THUMB: number;
declare const CS_MODE_MCLASS: number;
declare const CS_MODE_V8: number;
declare const CS_MODE_MICRO: number;
declare const CS_MODE_MIPS3: number;
declare const CS_MODE_MIPS32R6: number;
declare const CS_MODE_MIPS2: number;
declare const CS_MODE_BIG_ENDIAN: number;
declare const CS_MODE_V9: number;
declare const CS_MODE_MIPS32: number;
declare const CS_MODE_MIPS64: number;
declare const CS_MODE_QPX: number;
declare const CS_MODE_SPE: number;
declare const CS_MODE_BOOKE: number;
declare const CS_MODE_PS: number;
declare const CS_MODE_M680X_6301: number;
declare const CS_MODE_M680X_6309: number;
declare const CS_MODE_M680X_6800: number;
declare const CS_MODE_M680X_6801: number;
declare const CS_MODE_M680X_6805: number;
declare const CS_MODE_M680X_6808: number;
declare const CS_MODE_M680X_6809: number;
declare const CS_MODE_M680X_6811: number;
declare const CS_MODE_M680X_CPU12: number;
declare const CS_MODE_M680X_HCS08: number;
declare const CS_ERR_OK = 0;
declare const CS_ERR_MEM = 1;
declare const CS_ERR_ARCH = 2;
declare const CS_ERR_HANDLE = 3;
declare const CS_ERR_CSH = 4;
declare const CS_ERR_MODE = 5;
declare const CS_ERR_OPTION = 6;
declare const CS_ERR_DETAIL = 7;
declare const CS_ERR_MEMSETUP = 8;
declare const CS_ERR_VERSION = 9;
declare const CS_ERR_DIET = 10;
declare const CS_ERR_SKIPDATA = 11;
declare const CS_ERR_X86_ATT = 12;
declare const CS_ERR_X86_INTEL = 13;
declare const CS_OPT_SYNTAX = 1;
declare const CS_OPT_DETAIL = 2;
declare const CS_OPT_MODE = 3;
declare const CS_OPT_OFF = 0;
declare const CS_OPT_SYNTAX_INTEL = 1;
declare const CS_OPT_SYNTAX_ATT = 2;
declare const CS_OPT_ON = 3;
declare const CS_OPT_SYNTAX_NOREGNAME = 3;
declare const CS_OP_INVALID = 0;
declare const CS_OP_REG = 1;
declare const CS_OP_IMM = 2;
declare const CS_OP_MEM = 3;
declare const CS_OP_FP = 4;
declare const CS_AC_INVALID = 0;
declare const CS_AC_READ: number;
declare const CS_AC_WRITE: number;
declare const CS_GRP_INVALID = 0;
declare const CS_GRP_JUMP = 1;
declare const CS_GRP_CALL = 2;
declare const CS_GRP_RET = 3;
declare const CS_GRP_INT = 4;
declare const CS_GRP_IRET = 5;
declare const CS_GRP_PRIVILEGE = 6;
declare const CS_SUPPORT_DIET: number;
declare const CS_SUPPORT_X86_REDUCE: number;

declare const _const_CS_AC_INVALID: typeof CS_AC_INVALID;
declare const _const_CS_AC_READ: typeof CS_AC_READ;
declare const _const_CS_AC_WRITE: typeof CS_AC_WRITE;
declare const _const_CS_API_MAJOR: typeof CS_API_MAJOR;
declare const _const_CS_API_MINOR: typeof CS_API_MINOR;
declare const _const_CS_ARCH_ALL: typeof CS_ARCH_ALL;
declare const _const_CS_ARCH_ARM: typeof CS_ARCH_ARM;
declare const _const_CS_ARCH_ARM64: typeof CS_ARCH_ARM64;
declare const _const_CS_ARCH_M680X: typeof CS_ARCH_M680X;
declare const _const_CS_ARCH_M68K: typeof CS_ARCH_M68K;
declare const _const_CS_ARCH_MAX: typeof CS_ARCH_MAX;
declare const _const_CS_ARCH_MIPS: typeof CS_ARCH_MIPS;
declare const _const_CS_ARCH_PPC: typeof CS_ARCH_PPC;
declare const _const_CS_ARCH_SPARC: typeof CS_ARCH_SPARC;
declare const _const_CS_ARCH_SYSZ: typeof CS_ARCH_SYSZ;
declare const _const_CS_ARCH_TMS320C64X: typeof CS_ARCH_TMS320C64X;
declare const _const_CS_ARCH_X86: typeof CS_ARCH_X86;
declare const _const_CS_ARCH_XCORE: typeof CS_ARCH_XCORE;
declare const _const_CS_ERR_ARCH: typeof CS_ERR_ARCH;
declare const _const_CS_ERR_CSH: typeof CS_ERR_CSH;
declare const _const_CS_ERR_DETAIL: typeof CS_ERR_DETAIL;
declare const _const_CS_ERR_DIET: typeof CS_ERR_DIET;
declare const _const_CS_ERR_HANDLE: typeof CS_ERR_HANDLE;
declare const _const_CS_ERR_MEM: typeof CS_ERR_MEM;
declare const _const_CS_ERR_MEMSETUP: typeof CS_ERR_MEMSETUP;
declare const _const_CS_ERR_MODE: typeof CS_ERR_MODE;
declare const _const_CS_ERR_OK: typeof CS_ERR_OK;
declare const _const_CS_ERR_OPTION: typeof CS_ERR_OPTION;
declare const _const_CS_ERR_SKIPDATA: typeof CS_ERR_SKIPDATA;
declare const _const_CS_ERR_VERSION: typeof CS_ERR_VERSION;
declare const _const_CS_ERR_X86_ATT: typeof CS_ERR_X86_ATT;
declare const _const_CS_ERR_X86_INTEL: typeof CS_ERR_X86_INTEL;
declare const _const_CS_GRP_CALL: typeof CS_GRP_CALL;
declare const _const_CS_GRP_INT: typeof CS_GRP_INT;
declare const _const_CS_GRP_INVALID: typeof CS_GRP_INVALID;
declare const _const_CS_GRP_IRET: typeof CS_GRP_IRET;
declare const _const_CS_GRP_JUMP: typeof CS_GRP_JUMP;
declare const _const_CS_GRP_PRIVILEGE: typeof CS_GRP_PRIVILEGE;
declare const _const_CS_GRP_RET: typeof CS_GRP_RET;
declare const _const_CS_MODE_16: typeof CS_MODE_16;
declare const _const_CS_MODE_32: typeof CS_MODE_32;
declare const _const_CS_MODE_64: typeof CS_MODE_64;
declare const _const_CS_MODE_ARM: typeof CS_MODE_ARM;
declare const _const_CS_MODE_BIG_ENDIAN: typeof CS_MODE_BIG_ENDIAN;
declare const _const_CS_MODE_BOOKE: typeof CS_MODE_BOOKE;
declare const _const_CS_MODE_LITTLE_ENDIAN: typeof CS_MODE_LITTLE_ENDIAN;
declare const _const_CS_MODE_M680X_6301: typeof CS_MODE_M680X_6301;
declare const _const_CS_MODE_M680X_6309: typeof CS_MODE_M680X_6309;
declare const _const_CS_MODE_M680X_6800: typeof CS_MODE_M680X_6800;
declare const _const_CS_MODE_M680X_6801: typeof CS_MODE_M680X_6801;
declare const _const_CS_MODE_M680X_6805: typeof CS_MODE_M680X_6805;
declare const _const_CS_MODE_M680X_6808: typeof CS_MODE_M680X_6808;
declare const _const_CS_MODE_M680X_6809: typeof CS_MODE_M680X_6809;
declare const _const_CS_MODE_M680X_6811: typeof CS_MODE_M680X_6811;
declare const _const_CS_MODE_M680X_CPU12: typeof CS_MODE_M680X_CPU12;
declare const _const_CS_MODE_M680X_HCS08: typeof CS_MODE_M680X_HCS08;
declare const _const_CS_MODE_MCLASS: typeof CS_MODE_MCLASS;
declare const _const_CS_MODE_MICRO: typeof CS_MODE_MICRO;
declare const _const_CS_MODE_MIPS2: typeof CS_MODE_MIPS2;
declare const _const_CS_MODE_MIPS3: typeof CS_MODE_MIPS3;
declare const _const_CS_MODE_MIPS32: typeof CS_MODE_MIPS32;
declare const _const_CS_MODE_MIPS32R6: typeof CS_MODE_MIPS32R6;
declare const _const_CS_MODE_MIPS64: typeof CS_MODE_MIPS64;
declare const _const_CS_MODE_PS: typeof CS_MODE_PS;
declare const _const_CS_MODE_QPX: typeof CS_MODE_QPX;
declare const _const_CS_MODE_SPE: typeof CS_MODE_SPE;
declare const _const_CS_MODE_THUMB: typeof CS_MODE_THUMB;
declare const _const_CS_MODE_V8: typeof CS_MODE_V8;
declare const _const_CS_MODE_V9: typeof CS_MODE_V9;
declare const _const_CS_OPT_DETAIL: typeof CS_OPT_DETAIL;
declare const _const_CS_OPT_MODE: typeof CS_OPT_MODE;
declare const _const_CS_OPT_OFF: typeof CS_OPT_OFF;
declare const _const_CS_OPT_ON: typeof CS_OPT_ON;
declare const _const_CS_OPT_SYNTAX: typeof CS_OPT_SYNTAX;
declare const _const_CS_OPT_SYNTAX_ATT: typeof CS_OPT_SYNTAX_ATT;
declare const _const_CS_OPT_SYNTAX_INTEL: typeof CS_OPT_SYNTAX_INTEL;
declare const _const_CS_OPT_SYNTAX_NOREGNAME: typeof CS_OPT_SYNTAX_NOREGNAME;
declare const _const_CS_OP_FP: typeof CS_OP_FP;
declare const _const_CS_OP_IMM: typeof CS_OP_IMM;
declare const _const_CS_OP_INVALID: typeof CS_OP_INVALID;
declare const _const_CS_OP_MEM: typeof CS_OP_MEM;
declare const _const_CS_OP_REG: typeof CS_OP_REG;
declare const _const_CS_SUPPORT_DIET: typeof CS_SUPPORT_DIET;
declare const _const_CS_SUPPORT_X86_REDUCE: typeof CS_SUPPORT_X86_REDUCE;
declare namespace _const {
  export {
    _const_CS_AC_INVALID as CS_AC_INVALID,
    _const_CS_AC_READ as CS_AC_READ,
    _const_CS_AC_WRITE as CS_AC_WRITE,
    _const_CS_API_MAJOR as CS_API_MAJOR,
    _const_CS_API_MINOR as CS_API_MINOR,
    _const_CS_ARCH_ALL as CS_ARCH_ALL,
    _const_CS_ARCH_ARM as CS_ARCH_ARM,
    _const_CS_ARCH_ARM64 as CS_ARCH_ARM64,
    _const_CS_ARCH_M680X as CS_ARCH_M680X,
    _const_CS_ARCH_M68K as CS_ARCH_M68K,
    _const_CS_ARCH_MAX as CS_ARCH_MAX,
    _const_CS_ARCH_MIPS as CS_ARCH_MIPS,
    _const_CS_ARCH_PPC as CS_ARCH_PPC,
    _const_CS_ARCH_SPARC as CS_ARCH_SPARC,
    _const_CS_ARCH_SYSZ as CS_ARCH_SYSZ,
    _const_CS_ARCH_TMS320C64X as CS_ARCH_TMS320C64X,
    _const_CS_ARCH_X86 as CS_ARCH_X86,
    _const_CS_ARCH_XCORE as CS_ARCH_XCORE,
    _const_CS_ERR_ARCH as CS_ERR_ARCH,
    _const_CS_ERR_CSH as CS_ERR_CSH,
    _const_CS_ERR_DETAIL as CS_ERR_DETAIL,
    _const_CS_ERR_DIET as CS_ERR_DIET,
    _const_CS_ERR_HANDLE as CS_ERR_HANDLE,
    _const_CS_ERR_MEM as CS_ERR_MEM,
    _const_CS_ERR_MEMSETUP as CS_ERR_MEMSETUP,
    _const_CS_ERR_MODE as CS_ERR_MODE,
    _const_CS_ERR_OK as CS_ERR_OK,
    _const_CS_ERR_OPTION as CS_ERR_OPTION,
    _const_CS_ERR_SKIPDATA as CS_ERR_SKIPDATA,
    _const_CS_ERR_VERSION as CS_ERR_VERSION,
    _const_CS_ERR_X86_ATT as CS_ERR_X86_ATT,
    _const_CS_ERR_X86_INTEL as CS_ERR_X86_INTEL,
    _const_CS_GRP_CALL as CS_GRP_CALL,
    _const_CS_GRP_INT as CS_GRP_INT,
    _const_CS_GRP_INVALID as CS_GRP_INVALID,
    _const_CS_GRP_IRET as CS_GRP_IRET,
    _const_CS_GRP_JUMP as CS_GRP_JUMP,
    _const_CS_GRP_PRIVILEGE as CS_GRP_PRIVILEGE,
    _const_CS_GRP_RET as CS_GRP_RET,
    _const_CS_MODE_16 as CS_MODE_16,
    _const_CS_MODE_32 as CS_MODE_32,
    _const_CS_MODE_64 as CS_MODE_64,
    _const_CS_MODE_ARM as CS_MODE_ARM,
    _const_CS_MODE_BIG_ENDIAN as CS_MODE_BIG_ENDIAN,
    _const_CS_MODE_BOOKE as CS_MODE_BOOKE,
    _const_CS_MODE_LITTLE_ENDIAN as CS_MODE_LITTLE_ENDIAN,
    _const_CS_MODE_M680X_6301 as CS_MODE_M680X_6301,
    _const_CS_MODE_M680X_6309 as CS_MODE_M680X_6309,
    _const_CS_MODE_M680X_6800 as CS_MODE_M680X_6800,
    _const_CS_MODE_M680X_6801 as CS_MODE_M680X_6801,
    _const_CS_MODE_M680X_6805 as CS_MODE_M680X_6805,
    _const_CS_MODE_M680X_6808 as CS_MODE_M680X_6808,
    _const_CS_MODE_M680X_6809 as CS_MODE_M680X_6809,
    _const_CS_MODE_M680X_6811 as CS_MODE_M680X_6811,
    _const_CS_MODE_M680X_CPU12 as CS_MODE_M680X_CPU12,
    _const_CS_MODE_M680X_HCS08 as CS_MODE_M680X_HCS08,
    _const_CS_MODE_MCLASS as CS_MODE_MCLASS,
    _const_CS_MODE_MICRO as CS_MODE_MICRO,
    _const_CS_MODE_MIPS2 as CS_MODE_MIPS2,
    _const_CS_MODE_MIPS3 as CS_MODE_MIPS3,
    _const_CS_MODE_MIPS32 as CS_MODE_MIPS32,
    _const_CS_MODE_MIPS32R6 as CS_MODE_MIPS32R6,
    _const_CS_MODE_MIPS64 as CS_MODE_MIPS64,
    _const_CS_MODE_PS as CS_MODE_PS,
    _const_CS_MODE_QPX as CS_MODE_QPX,
    _const_CS_MODE_SPE as CS_MODE_SPE,
    _const_CS_MODE_THUMB as CS_MODE_THUMB,
    _const_CS_MODE_V8 as CS_MODE_V8,
    _const_CS_MODE_V9 as CS_MODE_V9,
    _const_CS_OPT_DETAIL as CS_OPT_DETAIL,
    _const_CS_OPT_MODE as CS_OPT_MODE,
    _const_CS_OPT_OFF as CS_OPT_OFF,
    _const_CS_OPT_ON as CS_OPT_ON,
    _const_CS_OPT_SYNTAX as CS_OPT_SYNTAX,
    _const_CS_OPT_SYNTAX_ATT as CS_OPT_SYNTAX_ATT,
    _const_CS_OPT_SYNTAX_INTEL as CS_OPT_SYNTAX_INTEL,
    _const_CS_OPT_SYNTAX_NOREGNAME as CS_OPT_SYNTAX_NOREGNAME,
    _const_CS_OP_FP as CS_OP_FP,
    _const_CS_OP_IMM as CS_OP_IMM,
    _const_CS_OP_INVALID as CS_OP_INVALID,
    _const_CS_OP_MEM as CS_OP_MEM,
    _const_CS_OP_REG as CS_OP_REG,
    _const_CS_SUPPORT_DIET as CS_SUPPORT_DIET,
    _const_CS_SUPPORT_X86_REDUCE as CS_SUPPORT_X86_REDUCE,
  };
}

export { Capstone, _const as Const, Insn, factory as loadCapstone };
