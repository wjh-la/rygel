#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const WEBKIT = 'WebKit-7619.1.12.2';
const ICU = 'release-75-1';

main()

function main() {
    process.chdir(__dirname);

    let icu = false;
    let webkit = false;
    let jobs = os.cpus().length + 1;
    let debug = false;

    // Parse options
    {
        if (process.argv[2] == '--help') {
            printUsage();
            return;
        }

        for (let i = 2; i < process.argv.length; i++) {
            let arg = process.argv[i];
            let value = null;

            if (arg[0] == '-') {
                if (arg.length > 2 && arg[1] != '-') {
                    value = arg.substr(2);
                    arg = arg.substr(0, 2);
                } else if (arg[1] == '-') {
                    let offset = arg.indexOf('=');

                    if (offset > 2 && arg.length > offset + 1) {
                        value = arg.substr(offset + 1);
                        arg = arg.substr(0, offset);
                    }
                }
                if (value == null && process.argv[i + 1] != null && process.argv[i + 1][0] != '-') {
                    value = process.argv[i + 1];
                    i++; // Skip this value next iteration
                }
            }

            if (arg == '--help') {
                printUsage();
                return;
            } else if (arg == '--icu') {
                icu = true;
            } else if (arg == '--webkit') {
                webkit = true;
            } else if (arg == '-j' || arg == '--jobs') {
                jobs = parseInt(value, 10);

                if (isNaN(jobs))
                    throw new Error(`Missing or invalid value for --jobs`);
            } else if (arg == '-d' || arg == '--debug') {
                debug = true;
            } else if (arg[0] == '-') {
                throw new Error(`Unexpected argument '${arg}'`);
            }
        }
    }

    if (!icu && !webkit) {
        icu = true;
        webkit = true;
    }

    // Clone repositories
    if (icu)
        clone('icu', ICU, 'https://github.com/unicode-org/icu.git');
    if (webkit)
        clone('webkit', WEBKIT, 'https://github.com/WebKit/WebKit.git');

    // And build
    if (icu)
        buildICU(jobs, debug);
    if (webkit)
        buildWebKit(jobs, debug);
}

function printUsage() {
    console.log('./build.js [--debug] [-j <cores>] [--icu] [--webkit]');
}

function clone(name, branch, url) {
    if (!fs.existsSync(name + '/VERSION') || fs.readFileSync(name + '/VERSION', { encoding: 'UTF-8' }).trim() != branch)
        fs.rmSync(name, { recursive: true, force: true });

    if (!fs.existsSync(name)) {
        run('.', 'git', ['clone', '--branch', branch, '--depth', '1', url, name]);
        fs.rmSync(name + '/.git', { recursive: true, force: true });

        for (let basename of fs.readdirSync('../_patches')) {
            if (!basename.startsWith(name + '_'))
                continue;

            let filename = '../_patches/' + basename;
            run('.', 'git', ['apply', filename]);
        }

        fs.writeFileSync(name + '/VERSION', branch, { encoding: 'UTF-8' });
    }
}

function buildICU(jobs, debug) {
    fs.mkdirSync('icu/build', { mode: 0o755, recursive: true });

    // Build WebAssembly ICU
    {
        let args = ['wasm32', '--enable-static', '--disable-shared'];

        if (debug)
            args.push('--enable-debug');

        run('icu/build', '../icu4c/source/runConfigureICU', args);
        run('icu/build', 'emmake', ['make', '-j' + jobs]);
    }

    // Copy library files
    {
        let src_dir = 'icu/build/lib';
        let lib_dir = 'lib';

        fs.mkdirSync(lib_dir, { recursive: true, mode: 0o755 });

        fs.copyFileSync(src_dir + '/libicudata.a', lib_dir + '/libicudata.a');
        fs.copyFileSync(src_dir + '/libicui18n.a', lib_dir + '/libicui18n.a');
        fs.copyFileSync(src_dir + '/libicuuc.a', lib_dir + '/libicuuc.a');
    }

    // Regroup header files
    {
        let source_dirs = ['icu/icu4c/source/common/unicode', 'icu/icu4c/source/i18n/unicode'];
        let include_dir = 'icu/build/include/unicode';

        if (fs.existsSync(include_dir))
            fs.rmSync(include_dir, { recursive: true, force: true });
        fs.mkdirSync(include_dir, { recursive: true, mode: 0o755 });

        for (let src_dir of source_dirs) {
            for (let basename of fs.readdirSync(src_dir)) {
                if (!basename.endsWith('.h'))
                    continue;

                let src_filename = src_dir + '/' + basename;
                let dest_filename = include_dir + '/' + basename;

                fs.copyFileSync(src_filename, dest_filename);
            }
        }
    }
}

function buildWebKit(jobs, debug) {
    fs.mkdirSync('webkit/build', { mode: 0o755, recursive: true });

    // Build in WebAssembly
    {
        run('webkit/build', 'emcmake', [
            'cmake', '-G', 'Ninja', '-DPORT=JSCOnly',
            '-DICU_INCLUDE_DIR=../../icu/build/include',
            '-DICU_DATA_LIBRARY_RELEASE=../../icu/build/lib/libicudata.a',
            '-DICU_I18N_LIBRARY_RELEASE=../../icu/build/lib/libicui18n.a',
            '-DICU_UC_LIBRARY_RELEASE=../../icu/build/lib/libicuuc.a',
            '-DCMAKE_CXX_FLAGS=-DU_STATIC_IMPLEMENTATION',
            '-DCMAKE_BUILD_TYPE=' + (debug ? 'RelWithDebInfo' : 'MinSizeRel'),
            '-DENABLE_TOOLS=OFF', '-DDEVELOPER_MODE=OFF',
            '-DENABLE_JIT=OFF', '-DENABLE_C_LOOP=ON',
            '-DENABLE_SAMPLING_PROFILER=OFF', '-DENABLE_WEBASSEMBLY=OFF',
            '-DENABLE_STATIC_JSC=OFF', '-DUSE_THIN_ARCHIVES=OFF',
            '..'
        ]);

        run('webkit/build', 'ninja', ['-j' + jobs]);
    }

    // Copy library files
    {
        let src_dir = 'webkit/build/lib';
        let lib_dir = 'lib';

        fs.mkdirSync(lib_dir, { recursive: true, mode: 0o755 });

        for (let basename of fs.readdirSync(src_dir)) {
            if (!basename.endsWith('.a'))
                continue;

            let src_filename = src_dir + '/' + basename;
            let dest_filename = lib_dir + '/' + basename;

            fs.copyFileSync(src_filename, dest_filename);
        }
    }

    // Copy and patch header files
    {
        let src_dir = 'webkit/build/JavaScriptCore/Headers/JavaScriptCore';
        let include_dir = 'include/JavaScriptCore';

        if (fs.existsSync(include_dir))
            fs.rmSync(include_dir, { recursive: true, force: true });
        fs.mkdirSync(include_dir, { recursive: true, mode: 0o755 });

        for (let basename of fs.readdirSync(src_dir)) {
            if (!basename.endsWith('.h'))
                continue;

            let src_filename = src_dir + '/' + basename;
            let dest_filename = include_dir + '/' + basename;

            let header = fs.readFileSync(src_filename, { encoding: 'utf8' });
            let patched = header.replace(/<JavaScriptCore\/([A-Za-z0-9_\.]+)>/g, '"$1"');

            fs.writeFileSync(dest_filename, patched);
        }
    }
}

function run(cwd, cmd, args = []) {
    console.log(cmd, ...args);

    let proc = spawnSync(cmd, args, { cwd: cwd, stdio: 'inherit' });
    if (proc.status !== 0)
        throw new Error(`Command failed: ${cmd}`);
}

function capture(cwd, cmd, args = []) {
    let proc = spawnSync(cmd, args, { cwd: cwd, stdio: ['inherit', 'pipe', 'inherit'] });
    if (proc.status !== 0)
        throw new Error(`Command failed: ${cmd}`);

    let output = proc.stdout.toString('utf-8').trim();
    return output;
}
