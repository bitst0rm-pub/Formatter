type CallType = 'string' | 'boolean' | 'number' | 'array' | null;

declare const METHODS_TYPES: Record<"ks_open" | "ks_asm" | "ks_free" | "ks_close" | "ks_option" | "ks_errno" | "ks_version" | "ks_arch_supported" | "ks_strerror" | "malloc" | "free", {
    returnType: CallType;
    argTypes: CallType[];
}>;
type MethodName = keyof typeof METHODS_TYPES;
declare class Keystone {
    arch: number;
    mode: number;
    handle_ptr: number | null;
    constructor(arch: number, mode: number);
    get handle(): number;
    setOption(opt: number, value: any): number;
    close(): void;
    asm(data: string, options?: {
        address?: number | bigint;
    }): Uint8Array;
    errNo(): number;
    static call(name: MethodName, ...args: any[]): any;
    static version(): {
        major: number;
        minor: number;
    };
    static archSupported(query: number): boolean;
    static strError(errNo: number): string;
}
declare function factory(args?: Record<string, unknown>): Promise<void>;

declare const KS_API_MAJOR = 0;
declare const KS_API_MINOR = 9;
declare const KS_VERSION_MAJOR = 0;
declare const KS_VERSION_MINOR = 9;
declare const KS_VERSION_EXTRA = 2;
declare const KS_ARCH_ARM = 1;
declare const KS_ARCH_ARM64 = 2;
declare const KS_ARCH_MIPS = 3;
declare const KS_ARCH_X86 = 4;
declare const KS_ARCH_PPC = 5;
declare const KS_ARCH_SPARC = 6;
declare const KS_ARCH_SYSTEMZ = 7;
declare const KS_ARCH_HEXAGON = 8;
declare const KS_ARCH_EVM = 9;
declare const KS_ARCH_RISCV = 10;
declare const KS_ARCH_MAX = 11;
declare const KS_MODE_LITTLE_ENDIAN = 0;
declare const KS_MODE_BIG_ENDIAN = 1073741824;
declare const KS_MODE_ARM = 1;
declare const KS_MODE_THUMB = 16;
declare const KS_MODE_V8 = 64;
declare const KS_MODE_MICRO = 16;
declare const KS_MODE_MIPS3 = 32;
declare const KS_MODE_MIPS32R6 = 64;
declare const KS_MODE_MIPS32 = 4;
declare const KS_MODE_MIPS64 = 8;
declare const KS_MODE_16 = 2;
declare const KS_MODE_32 = 4;
declare const KS_MODE_64 = 8;
declare const KS_MODE_PPC32 = 4;
declare const KS_MODE_PPC64 = 8;
declare const KS_MODE_QPX = 16;
declare const KS_MODE_RISCV32 = 4;
declare const KS_MODE_RISCV64 = 8;
declare const KS_MODE_SPARC32 = 4;
declare const KS_MODE_SPARC64 = 8;
declare const KS_MODE_V9 = 16;
declare const KS_ERR_ASM = 128;
declare const KS_ERR_ASM_ARCH = 512;
declare const KS_ERR_OK = 0;
declare const KS_ERR_NOMEM = 1;
declare const KS_ERR_ARCH = 2;
declare const KS_ERR_HANDLE = 3;
declare const KS_ERR_MODE = 4;
declare const KS_ERR_VERSION = 5;
declare const KS_ERR_OPT_INVALID = 6;
declare const KS_ERR_ASM_EXPR_TOKEN = 128;
declare const KS_ERR_ASM_DIRECTIVE_VALUE_RANGE = 129;
declare const KS_ERR_ASM_DIRECTIVE_ID = 130;
declare const KS_ERR_ASM_DIRECTIVE_TOKEN = 131;
declare const KS_ERR_ASM_DIRECTIVE_STR = 132;
declare const KS_ERR_ASM_DIRECTIVE_COMMA = 133;
declare const KS_ERR_ASM_DIRECTIVE_RELOC_NAME = 134;
declare const KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN = 135;
declare const KS_ERR_ASM_DIRECTIVE_FPOINT = 136;
declare const KS_ERR_ASM_DIRECTIVE_UNKNOWN = 137;
declare const KS_ERR_ASM_DIRECTIVE_EQU = 138;
declare const KS_ERR_ASM_DIRECTIVE_INVALID = 139;
declare const KS_ERR_ASM_VARIANT_INVALID = 140;
declare const KS_ERR_ASM_EXPR_BRACKET = 141;
declare const KS_ERR_ASM_SYMBOL_MODIFIER = 142;
declare const KS_ERR_ASM_SYMBOL_REDEFINED = 143;
declare const KS_ERR_ASM_SYMBOL_MISSING = 144;
declare const KS_ERR_ASM_RPAREN = 145;
declare const KS_ERR_ASM_STAT_TOKEN = 146;
declare const KS_ERR_ASM_UNSUPPORTED = 147;
declare const KS_ERR_ASM_MACRO_TOKEN = 148;
declare const KS_ERR_ASM_MACRO_PAREN = 149;
declare const KS_ERR_ASM_MACRO_EQU = 150;
declare const KS_ERR_ASM_MACRO_ARGS = 151;
declare const KS_ERR_ASM_MACRO_LEVELS_EXCEED = 152;
declare const KS_ERR_ASM_MACRO_STR = 153;
declare const KS_ERR_ASM_MACRO_INVALID = 154;
declare const KS_ERR_ASM_ESC_BACKSLASH = 155;
declare const KS_ERR_ASM_ESC_OCTAL = 156;
declare const KS_ERR_ASM_ESC_SEQUENCE = 157;
declare const KS_ERR_ASM_ESC_STR = 158;
declare const KS_ERR_ASM_TOKEN_INVALID = 159;
declare const KS_ERR_ASM_INSN_UNSUPPORTED = 160;
declare const KS_ERR_ASM_FIXUP_INVALID = 161;
declare const KS_ERR_ASM_LABEL_INVALID = 162;
declare const KS_ERR_ASM_FRAGMENT_INVALID = 163;
declare const KS_ERR_ASM_INVALIDOPERAND = 512;
declare const KS_ERR_ASM_MISSINGFEATURE = 513;
declare const KS_ERR_ASM_MNEMONICFAIL = 514;
declare const KS_OPT_SYNTAX = 1;
declare const KS_OPT_SYM_RESOLVER = 2;
declare const KS_OPT_SYNTAX_INTEL = 1;
declare const KS_OPT_SYNTAX_ATT = 2;
declare const KS_OPT_SYNTAX_NASM = 4;
declare const KS_OPT_SYNTAX_MASM = 8;
declare const KS_OPT_SYNTAX_GAS = 16;
declare const KS_OPT_SYNTAX_RADIX16 = 32;

declare const _const_KS_API_MAJOR: typeof KS_API_MAJOR;
declare const _const_KS_API_MINOR: typeof KS_API_MINOR;
declare const _const_KS_ARCH_ARM: typeof KS_ARCH_ARM;
declare const _const_KS_ARCH_ARM64: typeof KS_ARCH_ARM64;
declare const _const_KS_ARCH_EVM: typeof KS_ARCH_EVM;
declare const _const_KS_ARCH_HEXAGON: typeof KS_ARCH_HEXAGON;
declare const _const_KS_ARCH_MAX: typeof KS_ARCH_MAX;
declare const _const_KS_ARCH_MIPS: typeof KS_ARCH_MIPS;
declare const _const_KS_ARCH_PPC: typeof KS_ARCH_PPC;
declare const _const_KS_ARCH_RISCV: typeof KS_ARCH_RISCV;
declare const _const_KS_ARCH_SPARC: typeof KS_ARCH_SPARC;
declare const _const_KS_ARCH_SYSTEMZ: typeof KS_ARCH_SYSTEMZ;
declare const _const_KS_ARCH_X86: typeof KS_ARCH_X86;
declare const _const_KS_ERR_ARCH: typeof KS_ERR_ARCH;
declare const _const_KS_ERR_ASM: typeof KS_ERR_ASM;
declare const _const_KS_ERR_ASM_ARCH: typeof KS_ERR_ASM_ARCH;
declare const _const_KS_ERR_ASM_DIRECTIVE_COMMA: typeof KS_ERR_ASM_DIRECTIVE_COMMA;
declare const _const_KS_ERR_ASM_DIRECTIVE_EQU: typeof KS_ERR_ASM_DIRECTIVE_EQU;
declare const _const_KS_ERR_ASM_DIRECTIVE_FPOINT: typeof KS_ERR_ASM_DIRECTIVE_FPOINT;
declare const _const_KS_ERR_ASM_DIRECTIVE_ID: typeof KS_ERR_ASM_DIRECTIVE_ID;
declare const _const_KS_ERR_ASM_DIRECTIVE_INVALID: typeof KS_ERR_ASM_DIRECTIVE_INVALID;
declare const _const_KS_ERR_ASM_DIRECTIVE_RELOC_NAME: typeof KS_ERR_ASM_DIRECTIVE_RELOC_NAME;
declare const _const_KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN: typeof KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN;
declare const _const_KS_ERR_ASM_DIRECTIVE_STR: typeof KS_ERR_ASM_DIRECTIVE_STR;
declare const _const_KS_ERR_ASM_DIRECTIVE_TOKEN: typeof KS_ERR_ASM_DIRECTIVE_TOKEN;
declare const _const_KS_ERR_ASM_DIRECTIVE_UNKNOWN: typeof KS_ERR_ASM_DIRECTIVE_UNKNOWN;
declare const _const_KS_ERR_ASM_DIRECTIVE_VALUE_RANGE: typeof KS_ERR_ASM_DIRECTIVE_VALUE_RANGE;
declare const _const_KS_ERR_ASM_ESC_BACKSLASH: typeof KS_ERR_ASM_ESC_BACKSLASH;
declare const _const_KS_ERR_ASM_ESC_OCTAL: typeof KS_ERR_ASM_ESC_OCTAL;
declare const _const_KS_ERR_ASM_ESC_SEQUENCE: typeof KS_ERR_ASM_ESC_SEQUENCE;
declare const _const_KS_ERR_ASM_ESC_STR: typeof KS_ERR_ASM_ESC_STR;
declare const _const_KS_ERR_ASM_EXPR_BRACKET: typeof KS_ERR_ASM_EXPR_BRACKET;
declare const _const_KS_ERR_ASM_EXPR_TOKEN: typeof KS_ERR_ASM_EXPR_TOKEN;
declare const _const_KS_ERR_ASM_FIXUP_INVALID: typeof KS_ERR_ASM_FIXUP_INVALID;
declare const _const_KS_ERR_ASM_FRAGMENT_INVALID: typeof KS_ERR_ASM_FRAGMENT_INVALID;
declare const _const_KS_ERR_ASM_INSN_UNSUPPORTED: typeof KS_ERR_ASM_INSN_UNSUPPORTED;
declare const _const_KS_ERR_ASM_INVALIDOPERAND: typeof KS_ERR_ASM_INVALIDOPERAND;
declare const _const_KS_ERR_ASM_LABEL_INVALID: typeof KS_ERR_ASM_LABEL_INVALID;
declare const _const_KS_ERR_ASM_MACRO_ARGS: typeof KS_ERR_ASM_MACRO_ARGS;
declare const _const_KS_ERR_ASM_MACRO_EQU: typeof KS_ERR_ASM_MACRO_EQU;
declare const _const_KS_ERR_ASM_MACRO_INVALID: typeof KS_ERR_ASM_MACRO_INVALID;
declare const _const_KS_ERR_ASM_MACRO_LEVELS_EXCEED: typeof KS_ERR_ASM_MACRO_LEVELS_EXCEED;
declare const _const_KS_ERR_ASM_MACRO_PAREN: typeof KS_ERR_ASM_MACRO_PAREN;
declare const _const_KS_ERR_ASM_MACRO_STR: typeof KS_ERR_ASM_MACRO_STR;
declare const _const_KS_ERR_ASM_MACRO_TOKEN: typeof KS_ERR_ASM_MACRO_TOKEN;
declare const _const_KS_ERR_ASM_MISSINGFEATURE: typeof KS_ERR_ASM_MISSINGFEATURE;
declare const _const_KS_ERR_ASM_MNEMONICFAIL: typeof KS_ERR_ASM_MNEMONICFAIL;
declare const _const_KS_ERR_ASM_RPAREN: typeof KS_ERR_ASM_RPAREN;
declare const _const_KS_ERR_ASM_STAT_TOKEN: typeof KS_ERR_ASM_STAT_TOKEN;
declare const _const_KS_ERR_ASM_SYMBOL_MISSING: typeof KS_ERR_ASM_SYMBOL_MISSING;
declare const _const_KS_ERR_ASM_SYMBOL_MODIFIER: typeof KS_ERR_ASM_SYMBOL_MODIFIER;
declare const _const_KS_ERR_ASM_SYMBOL_REDEFINED: typeof KS_ERR_ASM_SYMBOL_REDEFINED;
declare const _const_KS_ERR_ASM_TOKEN_INVALID: typeof KS_ERR_ASM_TOKEN_INVALID;
declare const _const_KS_ERR_ASM_UNSUPPORTED: typeof KS_ERR_ASM_UNSUPPORTED;
declare const _const_KS_ERR_ASM_VARIANT_INVALID: typeof KS_ERR_ASM_VARIANT_INVALID;
declare const _const_KS_ERR_HANDLE: typeof KS_ERR_HANDLE;
declare const _const_KS_ERR_MODE: typeof KS_ERR_MODE;
declare const _const_KS_ERR_NOMEM: typeof KS_ERR_NOMEM;
declare const _const_KS_ERR_OK: typeof KS_ERR_OK;
declare const _const_KS_ERR_OPT_INVALID: typeof KS_ERR_OPT_INVALID;
declare const _const_KS_ERR_VERSION: typeof KS_ERR_VERSION;
declare const _const_KS_MODE_16: typeof KS_MODE_16;
declare const _const_KS_MODE_32: typeof KS_MODE_32;
declare const _const_KS_MODE_64: typeof KS_MODE_64;
declare const _const_KS_MODE_ARM: typeof KS_MODE_ARM;
declare const _const_KS_MODE_BIG_ENDIAN: typeof KS_MODE_BIG_ENDIAN;
declare const _const_KS_MODE_LITTLE_ENDIAN: typeof KS_MODE_LITTLE_ENDIAN;
declare const _const_KS_MODE_MICRO: typeof KS_MODE_MICRO;
declare const _const_KS_MODE_MIPS3: typeof KS_MODE_MIPS3;
declare const _const_KS_MODE_MIPS32: typeof KS_MODE_MIPS32;
declare const _const_KS_MODE_MIPS32R6: typeof KS_MODE_MIPS32R6;
declare const _const_KS_MODE_MIPS64: typeof KS_MODE_MIPS64;
declare const _const_KS_MODE_PPC32: typeof KS_MODE_PPC32;
declare const _const_KS_MODE_PPC64: typeof KS_MODE_PPC64;
declare const _const_KS_MODE_QPX: typeof KS_MODE_QPX;
declare const _const_KS_MODE_RISCV32: typeof KS_MODE_RISCV32;
declare const _const_KS_MODE_RISCV64: typeof KS_MODE_RISCV64;
declare const _const_KS_MODE_SPARC32: typeof KS_MODE_SPARC32;
declare const _const_KS_MODE_SPARC64: typeof KS_MODE_SPARC64;
declare const _const_KS_MODE_THUMB: typeof KS_MODE_THUMB;
declare const _const_KS_MODE_V8: typeof KS_MODE_V8;
declare const _const_KS_MODE_V9: typeof KS_MODE_V9;
declare const _const_KS_OPT_SYM_RESOLVER: typeof KS_OPT_SYM_RESOLVER;
declare const _const_KS_OPT_SYNTAX: typeof KS_OPT_SYNTAX;
declare const _const_KS_OPT_SYNTAX_ATT: typeof KS_OPT_SYNTAX_ATT;
declare const _const_KS_OPT_SYNTAX_GAS: typeof KS_OPT_SYNTAX_GAS;
declare const _const_KS_OPT_SYNTAX_INTEL: typeof KS_OPT_SYNTAX_INTEL;
declare const _const_KS_OPT_SYNTAX_MASM: typeof KS_OPT_SYNTAX_MASM;
declare const _const_KS_OPT_SYNTAX_NASM: typeof KS_OPT_SYNTAX_NASM;
declare const _const_KS_OPT_SYNTAX_RADIX16: typeof KS_OPT_SYNTAX_RADIX16;
declare const _const_KS_VERSION_EXTRA: typeof KS_VERSION_EXTRA;
declare const _const_KS_VERSION_MAJOR: typeof KS_VERSION_MAJOR;
declare const _const_KS_VERSION_MINOR: typeof KS_VERSION_MINOR;
declare namespace _const {
  export {
    _const_KS_API_MAJOR as KS_API_MAJOR,
    _const_KS_API_MINOR as KS_API_MINOR,
    _const_KS_ARCH_ARM as KS_ARCH_ARM,
    _const_KS_ARCH_ARM64 as KS_ARCH_ARM64,
    _const_KS_ARCH_EVM as KS_ARCH_EVM,
    _const_KS_ARCH_HEXAGON as KS_ARCH_HEXAGON,
    _const_KS_ARCH_MAX as KS_ARCH_MAX,
    _const_KS_ARCH_MIPS as KS_ARCH_MIPS,
    _const_KS_ARCH_PPC as KS_ARCH_PPC,
    _const_KS_ARCH_RISCV as KS_ARCH_RISCV,
    _const_KS_ARCH_SPARC as KS_ARCH_SPARC,
    _const_KS_ARCH_SYSTEMZ as KS_ARCH_SYSTEMZ,
    _const_KS_ARCH_X86 as KS_ARCH_X86,
    _const_KS_ERR_ARCH as KS_ERR_ARCH,
    _const_KS_ERR_ASM as KS_ERR_ASM,
    _const_KS_ERR_ASM_ARCH as KS_ERR_ASM_ARCH,
    _const_KS_ERR_ASM_DIRECTIVE_COMMA as KS_ERR_ASM_DIRECTIVE_COMMA,
    _const_KS_ERR_ASM_DIRECTIVE_EQU as KS_ERR_ASM_DIRECTIVE_EQU,
    _const_KS_ERR_ASM_DIRECTIVE_FPOINT as KS_ERR_ASM_DIRECTIVE_FPOINT,
    _const_KS_ERR_ASM_DIRECTIVE_ID as KS_ERR_ASM_DIRECTIVE_ID,
    _const_KS_ERR_ASM_DIRECTIVE_INVALID as KS_ERR_ASM_DIRECTIVE_INVALID,
    _const_KS_ERR_ASM_DIRECTIVE_RELOC_NAME as KS_ERR_ASM_DIRECTIVE_RELOC_NAME,
    _const_KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN as KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN,
    _const_KS_ERR_ASM_DIRECTIVE_STR as KS_ERR_ASM_DIRECTIVE_STR,
    _const_KS_ERR_ASM_DIRECTIVE_TOKEN as KS_ERR_ASM_DIRECTIVE_TOKEN,
    _const_KS_ERR_ASM_DIRECTIVE_UNKNOWN as KS_ERR_ASM_DIRECTIVE_UNKNOWN,
    _const_KS_ERR_ASM_DIRECTIVE_VALUE_RANGE as KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,
    _const_KS_ERR_ASM_ESC_BACKSLASH as KS_ERR_ASM_ESC_BACKSLASH,
    _const_KS_ERR_ASM_ESC_OCTAL as KS_ERR_ASM_ESC_OCTAL,
    _const_KS_ERR_ASM_ESC_SEQUENCE as KS_ERR_ASM_ESC_SEQUENCE,
    _const_KS_ERR_ASM_ESC_STR as KS_ERR_ASM_ESC_STR,
    _const_KS_ERR_ASM_EXPR_BRACKET as KS_ERR_ASM_EXPR_BRACKET,
    _const_KS_ERR_ASM_EXPR_TOKEN as KS_ERR_ASM_EXPR_TOKEN,
    _const_KS_ERR_ASM_FIXUP_INVALID as KS_ERR_ASM_FIXUP_INVALID,
    _const_KS_ERR_ASM_FRAGMENT_INVALID as KS_ERR_ASM_FRAGMENT_INVALID,
    _const_KS_ERR_ASM_INSN_UNSUPPORTED as KS_ERR_ASM_INSN_UNSUPPORTED,
    _const_KS_ERR_ASM_INVALIDOPERAND as KS_ERR_ASM_INVALIDOPERAND,
    _const_KS_ERR_ASM_LABEL_INVALID as KS_ERR_ASM_LABEL_INVALID,
    _const_KS_ERR_ASM_MACRO_ARGS as KS_ERR_ASM_MACRO_ARGS,
    _const_KS_ERR_ASM_MACRO_EQU as KS_ERR_ASM_MACRO_EQU,
    _const_KS_ERR_ASM_MACRO_INVALID as KS_ERR_ASM_MACRO_INVALID,
    _const_KS_ERR_ASM_MACRO_LEVELS_EXCEED as KS_ERR_ASM_MACRO_LEVELS_EXCEED,
    _const_KS_ERR_ASM_MACRO_PAREN as KS_ERR_ASM_MACRO_PAREN,
    _const_KS_ERR_ASM_MACRO_STR as KS_ERR_ASM_MACRO_STR,
    _const_KS_ERR_ASM_MACRO_TOKEN as KS_ERR_ASM_MACRO_TOKEN,
    _const_KS_ERR_ASM_MISSINGFEATURE as KS_ERR_ASM_MISSINGFEATURE,
    _const_KS_ERR_ASM_MNEMONICFAIL as KS_ERR_ASM_MNEMONICFAIL,
    _const_KS_ERR_ASM_RPAREN as KS_ERR_ASM_RPAREN,
    _const_KS_ERR_ASM_STAT_TOKEN as KS_ERR_ASM_STAT_TOKEN,
    _const_KS_ERR_ASM_SYMBOL_MISSING as KS_ERR_ASM_SYMBOL_MISSING,
    _const_KS_ERR_ASM_SYMBOL_MODIFIER as KS_ERR_ASM_SYMBOL_MODIFIER,
    _const_KS_ERR_ASM_SYMBOL_REDEFINED as KS_ERR_ASM_SYMBOL_REDEFINED,
    _const_KS_ERR_ASM_TOKEN_INVALID as KS_ERR_ASM_TOKEN_INVALID,
    _const_KS_ERR_ASM_UNSUPPORTED as KS_ERR_ASM_UNSUPPORTED,
    _const_KS_ERR_ASM_VARIANT_INVALID as KS_ERR_ASM_VARIANT_INVALID,
    _const_KS_ERR_HANDLE as KS_ERR_HANDLE,
    _const_KS_ERR_MODE as KS_ERR_MODE,
    _const_KS_ERR_NOMEM as KS_ERR_NOMEM,
    _const_KS_ERR_OK as KS_ERR_OK,
    _const_KS_ERR_OPT_INVALID as KS_ERR_OPT_INVALID,
    _const_KS_ERR_VERSION as KS_ERR_VERSION,
    _const_KS_MODE_16 as KS_MODE_16,
    _const_KS_MODE_32 as KS_MODE_32,
    _const_KS_MODE_64 as KS_MODE_64,
    _const_KS_MODE_ARM as KS_MODE_ARM,
    _const_KS_MODE_BIG_ENDIAN as KS_MODE_BIG_ENDIAN,
    _const_KS_MODE_LITTLE_ENDIAN as KS_MODE_LITTLE_ENDIAN,
    _const_KS_MODE_MICRO as KS_MODE_MICRO,
    _const_KS_MODE_MIPS3 as KS_MODE_MIPS3,
    _const_KS_MODE_MIPS32 as KS_MODE_MIPS32,
    _const_KS_MODE_MIPS32R6 as KS_MODE_MIPS32R6,
    _const_KS_MODE_MIPS64 as KS_MODE_MIPS64,
    _const_KS_MODE_PPC32 as KS_MODE_PPC32,
    _const_KS_MODE_PPC64 as KS_MODE_PPC64,
    _const_KS_MODE_QPX as KS_MODE_QPX,
    _const_KS_MODE_RISCV32 as KS_MODE_RISCV32,
    _const_KS_MODE_RISCV64 as KS_MODE_RISCV64,
    _const_KS_MODE_SPARC32 as KS_MODE_SPARC32,
    _const_KS_MODE_SPARC64 as KS_MODE_SPARC64,
    _const_KS_MODE_THUMB as KS_MODE_THUMB,
    _const_KS_MODE_V8 as KS_MODE_V8,
    _const_KS_MODE_V9 as KS_MODE_V9,
    _const_KS_OPT_SYM_RESOLVER as KS_OPT_SYM_RESOLVER,
    _const_KS_OPT_SYNTAX as KS_OPT_SYNTAX,
    _const_KS_OPT_SYNTAX_ATT as KS_OPT_SYNTAX_ATT,
    _const_KS_OPT_SYNTAX_GAS as KS_OPT_SYNTAX_GAS,
    _const_KS_OPT_SYNTAX_INTEL as KS_OPT_SYNTAX_INTEL,
    _const_KS_OPT_SYNTAX_MASM as KS_OPT_SYNTAX_MASM,
    _const_KS_OPT_SYNTAX_NASM as KS_OPT_SYNTAX_NASM,
    _const_KS_OPT_SYNTAX_RADIX16 as KS_OPT_SYNTAX_RADIX16,
    _const_KS_VERSION_EXTRA as KS_VERSION_EXTRA,
    _const_KS_VERSION_MAJOR as KS_VERSION_MAJOR,
    _const_KS_VERSION_MINOR as KS_VERSION_MINOR,
  };
}

export { _const as Const, Keystone, factory as loadKeystone };
