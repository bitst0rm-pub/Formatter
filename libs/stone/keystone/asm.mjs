import {
    Const,
    Keystone,
    loadKeystone,
} from 'keystone-wasm';

await loadKeystone();

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
    V8: 'KS_MODE_V8'
};

const ENDIANS = {
    LITTLE: 'KS_MODE_LITTLE_ENDIAN',
    BIG: 'KS_MODE_BIG_ENDIAN',
};

function parseArgs() {
    const args = process.argv.slice(2);  // skip node and script path
    const options = {  // default
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

function validateAndMapOptions(options) {
    if (!(options.arch in ARCHS)) {
        console.error('Unsupported architecture: ' + options.arch);
        process.exit(1);
    }
    const ksArch = ARCHS[options.arch];

    let ksMode = 0;
    if (options.arch === 'ARM64') {
        // arm64 does not have any modes
        ksMode = 0;
    } else {
        const modes = options.mode.split(',').map(mode => mode.trim());
        for (const mode of modes) {
            if (!(mode in MODES)) {
                console.error('Unsupported mode: ' + mode);
                process.exit(1);
            }
            ksMode += Const[MODES[mode]];
        }
    }

    if (options.endian in ENDIANS) {
        if (['ARM', 'ARM64', 'MIPS', 'PPC'].includes(options.arch)) {
            ksMode += Const[ENDIANS[options.endian]];
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

    if (isNaN(options.bytes_per_line) || options.bytes_per_line <= 0) {
        console.error('Invalid bytes_per_line. It must be a positive number.');
        process.exit(1);
    }

    return { ksArch, ksMode, ksOffset: options.offset, bytesPerLine: options.bytes_per_line };
}

function main() {
    const options = parseArgs();
    const { ksArch, ksMode, ksOffset, bytesPerLine } = validateAndMapOptions(options);

    // Read input from stdin
    let inputData = '';
    process.stdin.on('data', chunk => (inputData += chunk));

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
        } catch (e) {
            console.error('Keystone assembly error: ' + e.message);
            process.exit(1);
        }
    });
}

main();
