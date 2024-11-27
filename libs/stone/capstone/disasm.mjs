import {
    Const,
    Capstone,
    loadCapstone,
} from 'capstone-wasm';

await loadCapstone();

// Supported architectures, modes, and endian
const ARCHS = {
    ARM: 'CS_ARCH_ARM',
    ARM64: 'CS_ARCH_ARM64',
    X86: 'CS_ARCH_X86'
};

const MODES = {
    16: 'CS_MODE_16',
    32: 'CS_MODE_32',
    64: 'CS_MODE_64',
    ARM: 'CS_MODE_ARM',
    THUMB: 'CS_MODE_THUMB'
};

const ENDIANS = {
    LITTLE: 'CS_MODE_LITTLE_ENDIAN',
    BIG: 'CS_MODE_BIG_ENDIAN'
};

// Helper function to parse arguments
function parseArgs() {
    const args = process.argv.slice(2); // Skip node and script path
    const options = {
        arch: 'X86', // Default architecture
        mode: '32', // Default mode
        endian: 'little', // Default endian
        offset: 0x10000, // Default offset
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

// Parse the command-line arguments
const options = parseArgs();

// Validate and map architecture
if (!ARCHS[options.arch]) {
    console.error('Unsupported architecture: ' + options.arch);
    process.exit(1);
}
const csArch = ARCHS[options.arch];

// Validate and map mode
if (!MODES[options.mode]) {
    console.error('Unsupported mode: ' + options.mode);
    process.exit(1);
}
let csMode = Const[MODES[options.mode]];

// Validate and map endian
if (ENDIANS[options.endian]) {
    if (['ARM', 'ARM64', 'MIPS', 'PPC'].includes(options.arch)) {
        csMode = csMode + Const[ENDIANS[options.endian]]
    } else if (options.arch === 'X86') {
        console.warn('Endianness is not applicable for x86 architecture. Ignoring --endian option.');
    } else {
        console.warn('Endianness for architecture ' + options.arch + ' is not explicitly supported. Proceeding without endianness configuration.');
    }
}

// Validate and map offset
if (isNaN(options.offset) || options.offset < 0) {
    console.error('Invalid offset. It must be a non-negative hexadecimal number.');
    process.exit(1);
}
const csOffset = options.offset;

// Read input from stdin
let inputData = '';
process.stdin.on('data', (chunk) => {
    inputData += chunk;
});

process.stdin.on('end', () => {
    let code;
    try {
        // Remove any spaces or non-hex characters, then group the input into bytes
        const cleanedInput = inputData.trim().replace(/[^0-9a-fA-F]/g, ''); // Clean non-hex characters
        if (cleanedInput.length % 2 !== 0) {
            console.error('Invalid input: Hexadecimal input should have an even number of digits.');
            process.exit(1);
        }
        // Split the cleaned input into pairs of characters (representing bytes)
        code = cleanedInput.match(/.{2}/g).map(byte => parseInt(byte, 16)); // Convert pairs to byte values
    } catch (e) {
        console.error('Invalid input data. Expected valid hex bytes.');
        process.exit(1);
    }

    try {
        // Initialize the decoder
        const capstone = new Capstone(Const[csArch], csMode);

        // Disassemble the code
        const insns = capstone.disasm(code, {
            address: csOffset,
        });

        // Function to calculate space padding dynamically
        function getBytesPadding(byteLength) {
            return byteLength * 3 + 1; // 3 characters per byte + 1 space for separation
        }

        // Function to calculate space padding dynamically for mnemonic column
        function getMnemonicPadding(maxMnemonicLength) {
            return maxMnemonicLength + 2; // Add extra space for separation
        }

        // Determine the maximum byte length and mnemonic length from all instructions
        const maxByteLength = Math.max(...insns.map(insn => insn.bytes.length));
        const maxMnemonicLength = Math.max(...insns.map(insn => insn.mnemonic.length));

        // For each instruction, calculate dynamic space for bytes, mnemonic, and output
        insns.forEach(insn => {
            const address = '0x' + insn.address.toString(16).toUpperCase().padStart(8, '0');
            const bytes = Array.from(insn.bytes)
                .map(b => b.toString(16).padStart(2, '0').toUpperCase())
                .join(' ');

            // Calculate the padding for the bytes column
            const byteColumnPadding = getBytesPadding(maxByteLength);

            // Calculate the padding for the mnemonic column
            const mnemonicColumnPadding = getMnemonicPadding(maxMnemonicLength);

            // Output the instruction with aligned columns
            const mnemonic = insn.mnemonic.padEnd(mnemonicColumnPadding, ' ');
            const operands = insn.opStr || '';

            console.log(address + '  ' + bytes.padEnd(byteColumnPadding) + ' ' + mnemonic + ' ' + operands);
        });

        // Delete decoder
        capstone.close();
    } catch (e) {
        console.error('Capstone disassembly error: ' + e.message);
        process.exit(1);
    }
});
