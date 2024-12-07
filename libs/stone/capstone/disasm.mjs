import {
    Const,
    Capstone,
    loadCapstone,
} from 'capstone-wasm';

await loadCapstone();

const ARCHS = {
    ARM: 'CS_ARCH_ARM',
    ARM64: 'CS_ARCH_ARM64',
    X86: 'CS_ARCH_X86',
};

const MODES = {
    16: 'CS_MODE_16',
    32: 'CS_MODE_32',
    64: 'CS_MODE_64',
    ARM: 'CS_MODE_ARM',
    THUMB: 'CS_MODE_THUMB',
    V8: 'CS_MODE_V8'
};

const ENDIANS = {
    LITTLE: 'CS_MODE_LITTLE_ENDIAN',
    BIG: 'CS_MODE_BIG_ENDIAN',
};

function parseArgs() {
    const args = process.argv.slice(2);  // skip node and script path
    const options = {  // default
        arch: 'X86',
        mode: '32',
        endian: 'LITTLE',
        offset: 0x10000,
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--arch':
                options.arch = args[i + 1].toUpperCase();
                i++;
                break;
            case '--mode':
                options.mode = args[i + 1].toUpperCase();
                i++;
                break;
            case '--endian':
                options.endian = args[i + 1].toUpperCase();
                i++;
                break;
            case '--offset':
                options.offset = parseInt(args[i + 1], 16);
                i++;
                break;
            default:
                console.error('Unknown argument: ' + args[i]);
                process.exit(1);
        }
    }

    return options;
}

function validateAndMapOptions(options) {
    if (!(options.arch in ARCHS)) {
        console.error('Unsupported architecture: ' + options.arch);
        process.exit(1);
    }
    const csArch = ARCHS[options.arch];

    const modes = options.mode.split(',').map(mode => mode.trim());
    let csMode = 0;
    for (const mode of modes) {
        if (!(mode in MODES)) {
            console.error('Unsupported mode: ' + mode);
            process.exit(1);
        }
        csMode += Const[MODES[mode]];
    }

    if (options.endian in ENDIANS) {
        if (['ARM', 'ARM64', 'MIPS', 'PPC'].includes(options.arch)) {
            csMode += Const[ENDIANS[options.endian]];
        } else if (options.arch === 'X86') {
            console.warn('Endianness is not applicable for x86 architecture. Ignoring --endian option.');
        } else {
            console.warn('Endianness for architecture ' + options.arch + ' is not explicitly supported. Proceeding without endianness configuration.');
        }
    }

    if (isNaN(options.offset) || options.offset < 0) {
        console.error('Invalid offset. It must be a non-negative hexadecimal number.');
        process.exit(1);
    }

    return { csArch, csMode, csOffset: options.offset };
}

// Clean and convert input data into byte array
function parseInput(input) {
    const cleanedInput = input.trim().replace(/[^0-9a-fA-F]/g, '');
    if (cleanedInput.length % 2 !== 0) {
        console.error('Invalid input: Hexadecimal input should have an even number of digits.');
        process.exit(1);
    }
    return cleanedInput.match(/.{2}/g).map(byte => parseInt(byte, 16));
}

function printDisassembly(insns, csOffset) {
    const maxByteLength = Math.max(...insns.map(insn => insn.bytes.length));
    const maxMnemonicLength = Math.max(...insns.map(insn => insn.mnemonic.length));

    const byteColumnPadding = maxByteLength * 3 + 1;  // 3 chars per byte + 1 space
    const mnemonicColumnPadding = maxMnemonicLength + 2;  // Add extra space for separation

    insns.forEach(insn => {
        const address = '0x' + insn.address.toString(16).toUpperCase().padStart(8, '0');
        const bytes = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
        const mnemonic = insn.mnemonic.padEnd(mnemonicColumnPadding, ' ');
        const operands = insn.opStr || '';

        console.log(address + '  ' + bytes.padEnd(byteColumnPadding) + ' ' + mnemonic + ' ' + operands);
    });
}

function main() {
    const options = parseArgs();
    const { csArch, csMode, csOffset } = validateAndMapOptions(options);

    let inputData = '';
    process.stdin.on('data', chunk => (inputData += chunk));

    process.stdin.on('end', () => {
        try {
            const code = parseInput(inputData);
            const capstone = new Capstone(Const[csArch], csMode);
            const insns = capstone.disasm(code, { address: csOffset });
            printDisassembly(insns, csOffset);

            // Delete decoder
            capstone.close();
        } catch (e) {
            console.error('Capstone disassembly error: ' + e.message);
            process.exit(1);
        }
    });
}

main();
