import {
    Const,
    Keystone,
    loadKeystone,
} from 'keystone-wasm';

await loadKeystone();

// Supported architectures, modes, and endian
const ARCHS = {
    ARM: 'KS_ARCH_ARM',
    ARM64: 'KS_ARCH_ARM64',
    X86: 'KS_ARCH_X86',
};

const MODES = {
    16: 'KS_MODE_16',
    32: 'KS_MODE_32',
    64: 'KS_MODE_64',
    ARM: 'KS_MODE_ARM',
    THUMB: 'KS_MODE_THUMB',
};

const ENDIANS = {
    LITTLE: 'KS_MODE_LITTLE_ENDIAN',
    BIG: 'KS_MODE_BIG_ENDIAN',
};

// Helper function to parse arguments
function parseArgs() {
    const args = process.argv.slice(2); // Skip node and script path
    const options = { // Default
        arch: 'X86',
        mode: '32',
        endian: 'LITTLE',
        offset: 0x10000,
        bytes_per_line: 24,
        uppercase: true,
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
            case '--bytes_per_line':
                options.bytes_per_line = parseInt(args[i + 1], 10);
                i++;
                break;
            case '--uppercase':
                options.uppercase = args[i + 1].toLowerCase() === 'true';
                i++;
                break;
            default:
                console.error('Unknown argument: ' + args[i]);
                process.exit(1);
        }
    }

    return options;
}

// Helper function to validate and map the arguments
function validateAndMapOptions(options) {
    const ksArch = ARCHS[options.arch];
    if (!ksArch) {
        console.error('Unsupported architecture: ' + options.arch);
        process.exit(1);
    }

    let ksMode = Const[MODES[options.mode]];
    if (!ksMode) {
        console.error('Unsupported mode: ' + options.mode);
        process.exit(1);
    }

    // Endian validation
    if (ENDIANS[options.endian]) {
        if (['ARM', 'ARM64', 'MIPS', 'PPC'].includes(options.arch)) {
            ksMode += Const[ENDIANS[options.endian]];
        } else if (options.arch === 'X86') {
            console.warn('Endianness is not applicable for x86 architecture. Ignoring --endian option.');
        } else {
            console.warn('Endianness for architecture ' + options.arch + ' is not explicitly supported. Proceeding without endianness configuration.');
        }
    }

    // Offset validation
    if (isNaN(options.offset) || options.offset < 0) {
        console.error('Invalid offset. It must be a non-negative hexadecimal number.');
        process.exit(1);
    }

    // Bytes per line validation
    if (isNaN(options.bytes_per_line) || options.bytes_per_line <= 0) {
        console.error('Invalid bytes_per_line. It must be a positive number.');
        process.exit(1);
    }

    return { ksArch, ksMode, ksOffset: options.offset, bytesPerLine: options.bytes_per_line };
}

// Main logic
function main() {
    const options = parseArgs();
    const { ksArch, ksMode, ksOffset, bytesPerLine } = validateAndMapOptions(options);

    // Read input from stdin
    let inputData = '';
    process.stdin.on('data', (chunk) => {
        inputData += chunk;
    });

    process.stdin.on('end', () => {
        try {
            const keystone = new Keystone(Const[ksArch], ksMode);
            const code = inputData.trim();

            // Assemble the code
            const insns = keystone.asm(code, { address: ksOffset });

            // Collect and format hex bytes
            let hexBytes = [];
            insns.forEach(byte => {
                const b = byte.toString(16).padStart(2, '0')
                hexBytes.push(options.uppercase ? b.toUpperCase() : b);
            });

            // Group bytes into lines
            for (let i = 0; i < hexBytes.length; i += bytesPerLine) {
                console.log(hexBytes.slice(i, i + bytesPerLine).join(' '));
            }

            // Delete encoder
            keystone.close();
        } catch (error) {
            console.error('Keystone assembly error: ' + e.message);
            process.exit(1);
        }
    });
}

main();
