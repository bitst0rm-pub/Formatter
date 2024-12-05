'use strict';

var _documentCurrentScript = typeof document !== 'undefined' ? document.currentScript : null;
var keystone$1 = (()=>{
    var _scriptName = (typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href));
    return async function(moduleArg = {}) {
        var moduleRtn;
        // include: shell.js
        // The Module object: Our interface to the outside world. We import
        // and export values on it. There are various ways Module can be used:
        // 1. Not defined. We create it here
        // 2. A function parameter, function(moduleArg) => Promise<Module>
        // 3. pre-run appended it, var Module = {}; ..generated code..
        // 4. External script tag defines var Module.
        // We need to check if Module already exists (e.g. case 3 above).
        // Substitution will be replaced with actual code on later stage of the build,
        // this way Closure Compiler will not mangle it (e.g. case 4. above).
        // Note that if you want to run closure, and also to use Module
        // after the generated code, you will need to define   var Module = {};
        // before the code. Then that object will be used in the code, and you
        // can continue to use Module afterwards as well.
        var Module = moduleArg;
        // Set up the promise that indicates the Module is initialized
        var readyPromiseResolve, readyPromiseReject;
        var readyPromise = new Promise((resolve, reject)=>{
            readyPromiseResolve = resolve;
            readyPromiseReject = reject;
        });
        // Determine the runtime environment we are in. You can customize this by
        // setting the ENVIRONMENT setting at compile time (see settings.js).
        // Attempt to auto-detect the environment
        var ENVIRONMENT_IS_WEB = typeof window == "object";
        var ENVIRONMENT_IS_WORKER = typeof WorkerGlobalScope != "undefined";
        // N.b. Electron.js environment is simultaneously a NODE-environment, but
        // also a web environment.
        var ENVIRONMENT_IS_NODE = typeof process == "object" && typeof process.versions == "object" && typeof process.versions.node == "string" && process.type != "renderer";
        if (ENVIRONMENT_IS_NODE) {
            // `require()` is no-op in an ESM module, use `createRequire()` to construct
            // the require()` function.  This is only necessary for multi-environment
            // builds, `-sENVIRONMENT=node` emits a static import declaration instead.
            // TODO: Swap all `require()`'s with `import()`'s?
            const { createRequire } = await import('module');
            let dirname = (typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href));
            if (dirname.startsWith("data:")) {
                dirname = "/";
            }
            /** @suppress{duplicate} */ var require$1 = createRequire(dirname);
        }
        // --pre-jses are emitted after the Module integration code, so that they can
        // refer to Module (if they choose; they can also define Module)
        // Sometimes an existing Module object exists with properties
        // meant to overwrite the default module functionality. Here
        // we collect those properties and reapply _after_ we configure
        // the current environment's defaults to avoid having to be so
        // defensive during initialization.
        var moduleOverrides = Object.assign({}, Module);
        var thisProgram = "./this.program";
        var quit_ = (status, toThrow)=>{
            throw toThrow;
        };
        // `/` should be present at the end if `scriptDirectory` is not empty
        var scriptDirectory = "";
        function locateFile(path) {
            if (Module["locateFile"]) {
                return Module["locateFile"](path, scriptDirectory);
            }
            return scriptDirectory + path;
        }
        // Hooks that are implemented differently in different runtime environments.
        var readAsync, readBinary;
        if (ENVIRONMENT_IS_NODE) {
            // These modules will usually be used on Node.js. Load them eagerly to avoid
            // the complexity of lazy-loading.
            var fs = require$1("fs");
            var nodePath = require$1("path");
            // EXPORT_ES6 + ENVIRONMENT_IS_NODE always requires use of import.meta.url,
            // since there's no way getting the current absolute path of the module when
            // support for that is not available.
            if (!(typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href)).startsWith("data:")) {
                scriptDirectory = nodePath.dirname(require$1("url").fileURLToPath((typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href)))) + "/";
            }
            // include: node_shell_read.js
            readBinary = (filename)=>{
                // We need to re-wrap `file://` strings to URLs. Normalizing isn't
                // necessary in that case, the path should already be absolute.
                filename = isFileURI(filename) ? new URL(filename) : nodePath.normalize(filename);
                var ret = fs.readFileSync(filename);
                return ret;
            };
            readAsync = (filename, binary = true)=>{
                // See the comment in the `readBinary` function.
                filename = isFileURI(filename) ? new URL(filename) : nodePath.normalize(filename);
                return new Promise((resolve, reject)=>{
                    fs.readFile(filename, binary ? undefined : "utf8", (err, data)=>{
                        if (err) reject(err);
                        else resolve(binary ? data.buffer : data);
                    });
                });
            };
            // end include: node_shell_read.js
            if (!Module["thisProgram"] && process.argv.length > 1) {
                thisProgram = process.argv[1].replace(/\\/g, "/");
            }
            process.argv.slice(2);
            // MODULARIZE will export the module in the proper place outside, we don't need to export here
            quit_ = (status, toThrow)=>{
                process.exitCode = status;
                throw toThrow;
            };
        } else // Node.js workers are detected as a combination of ENVIRONMENT_IS_WORKER and
        // ENVIRONMENT_IS_NODE.
        if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
            if (ENVIRONMENT_IS_WORKER) {
                // Check worker, not web, since window could be polyfilled
                scriptDirectory = self.location.href;
            } else if (typeof document != "undefined" && document.currentScript) {
                // web
                scriptDirectory = document.currentScript.src;
            }
            // When MODULARIZE, this JS may be executed later, after document.currentScript
            // is gone, so we saved it, and we use it here instead of any other info.
            if (_scriptName) {
                scriptDirectory = _scriptName;
            }
            // blob urls look like blob:http://site.com/etc/etc and we cannot infer anything from them.
            // otherwise, slice off the final part of the url to find the script directory.
            // if scriptDirectory does not contain a slash, lastIndexOf will return -1,
            // and scriptDirectory will correctly be replaced with an empty string.
            // If scriptDirectory contains a query (starting with ?) or a fragment (starting with #),
            // they are removed because they could contain a slash.
            if (scriptDirectory.startsWith("blob:")) {
                scriptDirectory = "";
            } else {
                scriptDirectory = scriptDirectory.substr(0, scriptDirectory.replace(/[?#].*/, "").lastIndexOf("/") + 1);
            }
            {
                // include: web_or_worker_shell_read.js
                if (ENVIRONMENT_IS_WORKER) {
                    readBinary = (url)=>{
                        var xhr = new XMLHttpRequest;
                        xhr.open("GET", url, false);
                        xhr.responseType = "arraybuffer";
                        xhr.send(null);
                        return new Uint8Array(/** @type{!ArrayBuffer} */ xhr.response);
                    };
                }
                readAsync = (url)=>{
                    // Fetch has some additional restrictions over XHR, like it can't be used on a file:// url.
                    // See https://github.com/github/fetch/pull/92#issuecomment-140665932
                    // Cordova or Electron apps are typically loaded from a file:// url.
                    // So use XHR on webview if URL is a file URL.
                    if (isFileURI(url)) {
                        return new Promise((resolve, reject)=>{
                            var xhr = new XMLHttpRequest;
                            xhr.open("GET", url, true);
                            xhr.responseType = "arraybuffer";
                            xhr.onload = ()=>{
                                if (xhr.status == 200 || xhr.status == 0 && xhr.response) {
                                    // file URLs can return 0
                                    resolve(xhr.response);
                                    return;
                                }
                                reject(xhr.status);
                            };
                            xhr.onerror = reject;
                            xhr.send(null);
                        });
                    }
                    return fetch(url, {
                        credentials: "same-origin"
                    }).then((response)=>{
                        if (response.ok) {
                            return response.arrayBuffer();
                        }
                        return Promise.reject(new Error(response.status + " : " + response.url));
                    });
                };
            }
        } else ;
        var out = Module["print"] || console.log.bind(console);
        var err = Module["printErr"] || console.error.bind(console);
        // Merge back in the overrides
        Object.assign(Module, moduleOverrides);
        // Free the object hierarchy contained in the overrides, this lets the GC
        // reclaim data used.
        moduleOverrides = null;
        // Emit code to handle expected values on the Module object. This applies Module.x
        // to the proper local x. This has two benefits: first, we only emit it if it is
        // expected to arrive, and second, by using a local everywhere else that can be
        // minified.
        if (Module["arguments"]) Module["arguments"];
        if (Module["thisProgram"]) thisProgram = Module["thisProgram"];
        // perform assertions in shell.js after we set up out() and err(), as otherwise if an assertion fails it cannot print the message
        // end include: shell.js
        // include: preamble.js
        // === Preamble library stuff ===
        // Documentation for the public APIs defined in this file must be updated in:
        //    site/source/docs/api_reference/preamble.js.rst
        // A prebuilt local version of the documentation is available at:
        //    site/build/text/docs/api_reference/preamble.js.txt
        // You can also build docs locally as HTML or other formats in site/
        // An online HTML version (which may be of a different version of Emscripten)
        //    is up at http://kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html
        var wasmBinary = Module["wasmBinary"];
        // Wasm globals
        var wasmMemory;
        //========================================
        // Runtime essentials
        //========================================
        // whether we are quitting the application. no code should run after this.
        // set in exit() and abort()
        var ABORT = false;
        // Memory management
        var /** @type {!Int8Array} */ HEAP8, /** @type {!Uint8Array} */ HEAPU8, /** @type {!Int16Array} */ HEAP16, /** @type {!Int32Array} */ HEAP32, /** @type {!Uint32Array} */ HEAPU32, /** @type {!Float32Array} */ HEAPF32, /* BigInt64Array type is not correctly defined in closure
/** not-@type {!BigInt64Array} */ HEAP64, /** @type {!Float64Array} */ HEAPF64;
        // include: runtime_shared.js
        function updateMemoryViews() {
            var b = wasmMemory.buffer;
            Module["HEAP8"] = HEAP8 = new Int8Array(b);
            Module["HEAP16"] = HEAP16 = new Int16Array(b);
            Module["HEAPU8"] = HEAPU8 = new Uint8Array(b);
            Module["HEAPU16"] = new Uint16Array(b);
            Module["HEAP32"] = HEAP32 = new Int32Array(b);
            Module["HEAPU32"] = HEAPU32 = new Uint32Array(b);
            Module["HEAPF32"] = HEAPF32 = new Float32Array(b);
            Module["HEAPF64"] = HEAPF64 = new Float64Array(b);
            Module["HEAP64"] = HEAP64 = new BigInt64Array(b);
            Module["HEAPU64"] = new BigUint64Array(b);
        }
        // end include: runtime_shared.js
        // include: runtime_stack_check.js
        // end include: runtime_stack_check.js
        var __ATPRERUN__ = [];
        // functions called before the runtime is initialized
        var __ATINIT__ = [];
        // functions called during shutdown
        var __ATPOSTRUN__ = [];
        function preRun() {
            if (Module["preRun"]) {
                if (typeof Module["preRun"] == "function") Module["preRun"] = [
                    Module["preRun"]
                ];
                while(Module["preRun"].length){
                    addOnPreRun(Module["preRun"].shift());
                }
            }
            callRuntimeCallbacks(__ATPRERUN__);
        }
        function initRuntime() {
            callRuntimeCallbacks(__ATINIT__);
        }
        function postRun() {
            if (Module["postRun"]) {
                if (typeof Module["postRun"] == "function") Module["postRun"] = [
                    Module["postRun"]
                ];
                while(Module["postRun"].length){
                    addOnPostRun(Module["postRun"].shift());
                }
            }
            callRuntimeCallbacks(__ATPOSTRUN__);
        }
        function addOnPreRun(cb) {
            __ATPRERUN__.unshift(cb);
        }
        function addOnInit(cb) {
            __ATINIT__.unshift(cb);
        }
        function addOnPostRun(cb) {
            __ATPOSTRUN__.unshift(cb);
        }
        // include: runtime_math.js
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/imul
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/fround
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/clz32
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/trunc
        // end include: runtime_math.js
        // A counter of dependencies for calling run(). If we need to
        // do asynchronous work before running, increment this and
        // decrement it. Incrementing must happen in a place like
        // Module.preRun (used by emcc to add file preloading).
        // Note that you can add dependencies in preRun, even though
        // it happens right before run - run will be postponed until
        // the dependencies are met.
        var runDependencies = 0;
        var dependenciesFulfilled = null;
        function addRunDependency(id) {
            runDependencies++;
            Module["monitorRunDependencies"]?.(runDependencies);
        }
        function removeRunDependency(id) {
            runDependencies--;
            Module["monitorRunDependencies"]?.(runDependencies);
            if (runDependencies == 0) {
                if (dependenciesFulfilled) {
                    var callback = dependenciesFulfilled;
                    dependenciesFulfilled = null;
                    callback();
                }
            }
        }
        /** @param {string|number=} what */ function abort(what) {
            Module["onAbort"]?.(what);
            what = "Aborted(" + what + ")";
            // TODO(sbc): Should we remove printing and leave it up to whoever
            // catches the exception?
            err(what);
            ABORT = true;
            what += ". Build with -sASSERTIONS for more info.";
            // Use a wasm runtime error, because a JS error might be seen as a foreign
            // exception, which means we'd run destructors on it. We need the error to
            // simply make the program stop.
            // FIXME This approach does not work in Wasm EH because it currently does not assume
            // all RuntimeErrors are from traps; it decides whether a RuntimeError is from
            // a trap or not based on a hidden field within the object. So at the moment
            // we don't have a way of throwing a wasm trap from JS. TODO Make a JS API that
            // allows this in the wasm spec.
            // Suppress closure compiler warning here. Closure compiler's builtin extern
            // definition for WebAssembly.RuntimeError claims it takes no arguments even
            // though it can.
            // TODO(https://github.com/google/closure-compiler/pull/3913): Remove if/when upstream closure gets fixed.
            /** @suppress {checkTypes} */ var e = new WebAssembly.RuntimeError(what);
            readyPromiseReject(e);
            // Throw the error whether or not MODULARIZE is set because abort is used
            // in code paths apart from instantiation where an exception is expected
            // to be thrown when abort is called.
            throw e;
        }
        // include: memoryprofiler.js
        // end include: memoryprofiler.js
        // include: URIUtils.js
        // Prefix of data URIs emitted by SINGLE_FILE and related options.
        var dataURIPrefix = "data:application/octet-stream;base64,";
        /**
 * Indicates whether filename is a base64 data URI.
 * @noinline
 */ var isDataURI = (filename)=>filename.startsWith(dataURIPrefix);
        /**
 * Indicates whether filename is delivered via file protocol (as opposed to http/https)
 * @noinline
 */ var isFileURI = (filename)=>filename.startsWith("file://");
        // end include: URIUtils.js
        // include: runtime_exceptions.js
        // end include: runtime_exceptions.js
        function findWasmBinary() {
            if (Module["locateFile"]) {
                var f = "keystone.wasm";
                if (!isDataURI(f)) {
                    return locateFile(f);
                }
                return f;
            }
            // Use bundler-friendly `new URL(..., import.meta.url)` pattern; works in browsers too.
            return new URL("keystone.wasm", (typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href))).href;
        }
        var wasmBinaryFile;
        function getBinarySync(file) {
            if (file == wasmBinaryFile && wasmBinary) {
                return new Uint8Array(wasmBinary);
            }
            if (readBinary) {
                return readBinary(file);
            }
            throw "both async and sync fetching of the wasm failed";
        }
        function getBinaryPromise(binaryFile) {
            // If we don't have the binary yet, load it asynchronously using readAsync.
            if (!wasmBinary) {
                // Fetch the binary using readAsync
                return readAsync(binaryFile).then((response)=>new Uint8Array(/** @type{!ArrayBuffer} */ response), ()=>getBinarySync(binaryFile));
            }
            // Otherwise, getBinarySync should be able to get it synchronously
            return Promise.resolve().then(()=>getBinarySync(binaryFile));
        }
        function instantiateArrayBuffer(binaryFile, imports, receiver) {
            return getBinaryPromise(binaryFile).then((binary)=>WebAssembly.instantiate(binary, imports)).then(receiver, (reason)=>{
                err(`failed to asynchronously prepare wasm: ${reason}`);
                abort(reason);
            });
        }
        function instantiateAsync(binary, binaryFile, imports, callback) {
            if (!binary && typeof WebAssembly.instantiateStreaming == "function" && !isDataURI(binaryFile) && // Don't use streaming for file:// delivered objects in a webview, fetch them synchronously.
            !isFileURI(binaryFile) && // Avoid instantiateStreaming() on Node.js environment for now, as while
            // Node.js v18.1.0 implements it, it does not have a full fetch()
            // implementation yet.
            // Reference:
            //   https://github.com/emscripten-core/emscripten/pull/16917
            !ENVIRONMENT_IS_NODE && typeof fetch == "function") {
                return fetch(binaryFile, {
                    credentials: "same-origin"
                }).then((response)=>{
                    // Suppress closure warning here since the upstream definition for
                    // instantiateStreaming only allows Promise<Repsponse> rather than
                    // an actual Response.
                    // TODO(https://github.com/google/closure-compiler/pull/3913): Remove if/when upstream closure is fixed.
                    /** @suppress {checkTypes} */ var result = WebAssembly.instantiateStreaming(response, imports);
                    return result.then(callback, function(reason) {
                        // We expect the most common failure cause to be a bad MIME type for the binary,
                        // in which case falling back to ArrayBuffer instantiation should work.
                        err(`wasm streaming compile failed: ${reason}`);
                        err("falling back to ArrayBuffer instantiation");
                        return instantiateArrayBuffer(binaryFile, imports, callback);
                    });
                });
            }
            return instantiateArrayBuffer(binaryFile, imports, callback);
        }
        function getWasmImports() {
            // prepare imports
            return {
                "a": wasmImports
            };
        }
        // Create the wasm instance.
        // Receives the wasm imports, returns the exports.
        function createWasm() {
            // Load the wasm module and create an instance of using native support in the JS engine.
            // handle a generated wasm instance, receiving its exports and
            // performing other necessary setup
            /** @param {WebAssembly.Module=} module*/ function receiveInstance(instance, module) {
                wasmExports = instance.exports;
                wasmMemory = wasmExports["u"];
                updateMemoryViews();
                addOnInit(wasmExports["v"]);
                removeRunDependency();
                return wasmExports;
            }
            // wait for the pthread pool (if any)
            addRunDependency();
            // Prefer streaming instantiation if available.
            function receiveInstantiationResult(result) {
                // 'result' is a ResultObject object which has both the module and instance.
                // receiveInstance() will swap in the exports (to Module.asm) so they can be called
                // TODO: Due to Closure regression https://github.com/google/closure-compiler/issues/3193, the above line no longer optimizes out down to the following line.
                // When the regression is fixed, can restore the above PTHREADS-enabled path.
                receiveInstance(result["instance"]);
            }
            var info = getWasmImports();
            // User shell pages can write their own Module.instantiateWasm = function(imports, successCallback) callback
            // to manually instantiate the Wasm module themselves. This allows pages to
            // run the instantiation parallel to any other async startup actions they are
            // performing.
            // Also pthreads and wasm workers initialize the wasm instance through this
            // path.
            if (Module["instantiateWasm"]) {
                try {
                    return Module["instantiateWasm"](info, receiveInstance);
                } catch (e) {
                    err(`Module.instantiateWasm callback failed with error: ${e}`);
                    // If instantiation fails, reject the module ready promise.
                    readyPromiseReject(e);
                }
            }
            wasmBinaryFile ?? (wasmBinaryFile = findWasmBinary());
            // If instantiation fails, reject the module ready promise.
            instantiateAsync(wasmBinary, wasmBinaryFile, info, receiveInstantiationResult).catch(readyPromiseReject);
            return {};
        }
        // include: runtime_debug.js
        // end include: runtime_debug.js
        // === Body ===
        // end include: preamble.js
        class ExitStatus {
            constructor(status){
                this.name = "ExitStatus";
                this.message = `Program terminated with exit(${status})`;
                this.status = status;
            }
        }
        var callRuntimeCallbacks = (callbacks)=>{
            while(callbacks.length > 0){
                // Pass the module as the first argument.
                callbacks.shift()(Module);
            }
        };
        /**
     * @param {number} ptr
     * @param {string} type
     */ function getValue(ptr, type = "i8") {
            if (type.endsWith("*")) type = "*";
            switch(type){
                case "i1":
                    return HEAP8[ptr];
                case "i8":
                    return HEAP8[ptr];
                case "i16":
                    return HEAP16[ptr >> 1];
                case "i32":
                    return HEAP32[ptr >> 2];
                case "i64":
                    return HEAP64[ptr >> 3];
                case "float":
                    return HEAPF32[ptr >> 2];
                case "double":
                    return HEAPF64[ptr >> 3];
                case "*":
                    return HEAPU32[ptr >> 2];
                default:
                    abort(`invalid type for getValue: ${type}`);
            }
        }
        var noExitRuntime = Module["noExitRuntime"] || true;
        var stackRestore = (val)=>__emscripten_stack_restore(val);
        var stackSave = ()=>_emscripten_stack_get_current();
        class ExceptionInfo {
            set_type(type) {
                HEAPU32[this.ptr + 4 >> 2] = type;
            }
            get_type() {
                return HEAPU32[this.ptr + 4 >> 2];
            }
            set_destructor(destructor) {
                HEAPU32[this.ptr + 8 >> 2] = destructor;
            }
            get_destructor() {
                return HEAPU32[this.ptr + 8 >> 2];
            }
            set_caught(caught) {
                caught = caught ? 1 : 0;
                HEAP8[this.ptr + 12] = caught;
            }
            get_caught() {
                return HEAP8[this.ptr + 12] != 0;
            }
            set_rethrown(rethrown) {
                rethrown = rethrown ? 1 : 0;
                HEAP8[this.ptr + 13] = rethrown;
            }
            get_rethrown() {
                return HEAP8[this.ptr + 13] != 0;
            }
            // Initialize native structure fields. Should be called once after allocated.
            init(type, destructor) {
                this.set_adjusted_ptr(0);
                this.set_type(type);
                this.set_destructor(destructor);
            }
            set_adjusted_ptr(adjustedPtr) {
                HEAPU32[this.ptr + 16 >> 2] = adjustedPtr;
            }
            get_adjusted_ptr() {
                return HEAPU32[this.ptr + 16 >> 2];
            }
            // excPtr - Thrown object pointer to wrap. Metadata pointer is calculated from it.
            constructor(excPtr){
                this.excPtr = excPtr;
                this.ptr = excPtr - 24;
            }
        }
        var exceptionLast = 0;
        var ___cxa_throw = (ptr, type, destructor)=>{
            var info = new ExceptionInfo(ptr);
            // Initialize ExceptionInfo content after it was allocated in __cxa_allocate_exception.
            info.init(type, destructor);
            exceptionLast = ptr;
            throw exceptionLast;
        };
        var ___syscall_fstat64 = (fd, buf)=>{};
        var lengthBytesUTF8 = (str)=>{
            var len = 0;
            for(var i = 0; i < str.length; ++i){
                // Gotcha: charCodeAt returns a 16-bit word that is a UTF-16 encoded code
                // unit, not a Unicode code point of the character! So decode
                // UTF16->UTF32->UTF8.
                // See http://unicode.org/faq/utf_bom.html#utf16-3
                var c = str.charCodeAt(i);
                // possibly a lead surrogate
                if (c <= 127) {
                    len++;
                } else if (c <= 2047) {
                    len += 2;
                } else if (c >= 55296 && c <= 57343) {
                    len += 4;
                    ++i;
                } else {
                    len += 3;
                }
            }
            return len;
        };
        var stringToUTF8Array = (str, heap, outIdx, maxBytesToWrite)=>{
            // Parameter maxBytesToWrite is not optional. Negative values, 0, null,
            // undefined and false each don't write out any bytes.
            if (!(maxBytesToWrite > 0)) return 0;
            var startIdx = outIdx;
            var endIdx = outIdx + maxBytesToWrite - 1;
            // -1 for string null terminator.
            for(var i = 0; i < str.length; ++i){
                // Gotcha: charCodeAt returns a 16-bit word that is a UTF-16 encoded code
                // unit, not a Unicode code point of the character! So decode
                // UTF16->UTF32->UTF8.
                // See http://unicode.org/faq/utf_bom.html#utf16-3
                // For UTF8 byte structure, see http://en.wikipedia.org/wiki/UTF-8#Description
                // and https://www.ietf.org/rfc/rfc2279.txt
                // and https://tools.ietf.org/html/rfc3629
                var u = str.charCodeAt(i);
                // possibly a lead surrogate
                if (u >= 55296 && u <= 57343) {
                    var u1 = str.charCodeAt(++i);
                    u = 65536 + ((u & 1023) << 10) | u1 & 1023;
                }
                if (u <= 127) {
                    if (outIdx >= endIdx) break;
                    heap[outIdx++] = u;
                } else if (u <= 2047) {
                    if (outIdx + 1 >= endIdx) break;
                    heap[outIdx++] = 192 | u >> 6;
                    heap[outIdx++] = 128 | u & 63;
                } else if (u <= 65535) {
                    if (outIdx + 2 >= endIdx) break;
                    heap[outIdx++] = 224 | u >> 12;
                    heap[outIdx++] = 128 | u >> 6 & 63;
                    heap[outIdx++] = 128 | u & 63;
                } else {
                    if (outIdx + 3 >= endIdx) break;
                    heap[outIdx++] = 240 | u >> 18;
                    heap[outIdx++] = 128 | u >> 12 & 63;
                    heap[outIdx++] = 128 | u >> 6 & 63;
                    heap[outIdx++] = 128 | u & 63;
                }
            }
            // Null-terminate the pointer to the buffer.
            heap[outIdx] = 0;
            return outIdx - startIdx;
        };
        var stringToUTF8 = (str, outPtr, maxBytesToWrite)=>stringToUTF8Array(str, HEAPU8, outPtr, maxBytesToWrite);
        var ___syscall_getcwd = (buf, size)=>{};
        var ___syscall_lstat64 = (path, buf)=>{};
        var ___syscall_newfstatat = (dirfd, path, buf, flags)=>{};
        var UTF8Decoder = typeof TextDecoder != "undefined" ? new TextDecoder : undefined;
        /**
     * Given a pointer 'idx' to a null-terminated UTF8-encoded string in the given
     * array that contains uint8 values, returns a copy of that string as a
     * Javascript String object.
     * heapOrArray is either a regular array, or a JavaScript typed array view.
     * @param {number=} idx
     * @param {number=} maxBytesToRead
     * @return {string}
     */ var UTF8ArrayToString = (heapOrArray, idx = 0, maxBytesToRead = NaN)=>{
            var endIdx = idx + maxBytesToRead;
            var endPtr = idx;
            // TextDecoder needs to know the byte length in advance, it doesn't stop on
            // null terminator by itself.  Also, use the length info to avoid running tiny
            // strings through TextDecoder, since .subarray() allocates garbage.
            // (As a tiny code save trick, compare endPtr against endIdx using a negation,
            // so that undefined/NaN means Infinity)
            while(heapOrArray[endPtr] && !(endPtr >= endIdx))++endPtr;
            if (endPtr - idx > 16 && heapOrArray.buffer && UTF8Decoder) {
                return UTF8Decoder.decode(heapOrArray.subarray(idx, endPtr));
            }
            var str = "";
            // If building with TextDecoder, we have already computed the string length
            // above, so test loop end condition against that
            while(idx < endPtr){
                // For UTF8 byte structure, see:
                // http://en.wikipedia.org/wiki/UTF-8#Description
                // https://www.ietf.org/rfc/rfc2279.txt
                // https://tools.ietf.org/html/rfc3629
                var u0 = heapOrArray[idx++];
                if (!(u0 & 128)) {
                    str += String.fromCharCode(u0);
                    continue;
                }
                var u1 = heapOrArray[idx++] & 63;
                if ((u0 & 224) == 192) {
                    str += String.fromCharCode((u0 & 31) << 6 | u1);
                    continue;
                }
                var u2 = heapOrArray[idx++] & 63;
                if ((u0 & 240) == 224) {
                    u0 = (u0 & 15) << 12 | u1 << 6 | u2;
                } else {
                    u0 = (u0 & 7) << 18 | u1 << 12 | u2 << 6 | heapOrArray[idx++] & 63;
                }
                if (u0 < 65536) {
                    str += String.fromCharCode(u0);
                } else {
                    var ch = u0 - 65536;
                    str += String.fromCharCode(55296 | ch >> 10, 56320 | ch & 1023);
                }
            }
            return str;
        };
        /**
     * Given a pointer 'ptr' to a null-terminated UTF8-encoded string in the
     * emscripten HEAP, returns a copy of that string as a Javascript String object.
     *
     * @param {number} ptr
     * @param {number=} maxBytesToRead - An optional length that specifies the
     *   maximum number of bytes to read. You can omit this parameter to scan the
     *   string until the first 0 byte. If maxBytesToRead is passed, and the string
     *   at [ptr, ptr+maxBytesToReadr[ contains a null byte in the middle, then the
     *   string will cut short at that byte index (i.e. maxBytesToRead will not
     *   produce a string of exact length [ptr, ptr+maxBytesToRead[) N.B. mixing
     *   frequent uses of UTF8ToString() with and without maxBytesToRead may throw
     *   JS JIT optimizations off, so it is worth to consider consistently using one
     * @return {string}
     */ var UTF8ToString = (ptr, maxBytesToRead)=>ptr ? UTF8ArrayToString(HEAPU8, ptr, maxBytesToRead) : "";
        function ___syscall_openat(dirfd, path, flags, varargs) {
        }
        var ___syscall_stat64 = (path, buf)=>{};
        var __abort_js = ()=>abort("");
        function __mmap_js(len, prot, flags, fd, offset, allocated, addr) {
            return -52;
        }
        function __munmap_js(addr, len, prot, flags, fd, offset) {
        }
        var abortOnCannotGrowMemory = (requestedSize)=>{
            abort("OOM");
        };
        var _emscripten_resize_heap = (requestedSize)=>{
            HEAPU8.length;
            abortOnCannotGrowMemory();
        };
        var ENV = {};
        var getExecutableName = ()=>thisProgram || "./this.program";
        var getEnvStrings = ()=>{
            if (!getEnvStrings.strings) {
                // Default values.
                // Browser language detection #8751
                var lang = (typeof navigator == "object" && navigator.languages && navigator.languages[0] || "C").replace("-", "_") + ".UTF-8";
                var env = {
                    "USER": "web_user",
                    "LOGNAME": "web_user",
                    "PATH": "/",
                    "PWD": "/",
                    "HOME": "/home/web_user",
                    "LANG": lang,
                    "_": getExecutableName()
                };
                // Apply the user-provided values, if any.
                for(var x in ENV){
                    // x is a key in ENV; if ENV[x] is undefined, that means it was
                    // explicitly set to be so. We allow user code to do that to
                    // force variables with default values to remain unset.
                    if (ENV[x] === undefined) delete env[x];
                    else env[x] = ENV[x];
                }
                var strings = [];
                for(var x in env){
                    strings.push(`${x}=${env[x]}`);
                }
                getEnvStrings.strings = strings;
            }
            return getEnvStrings.strings;
        };
        var stringToAscii = (str, buffer)=>{
            for(var i = 0; i < str.length; ++i){
                HEAP8[buffer++] = str.charCodeAt(i);
            }
            // Null-terminate the string
            HEAP8[buffer] = 0;
        };
        var _environ_get = (__environ, environ_buf)=>{
            var bufSize = 0;
            getEnvStrings().forEach((string, i)=>{
                var ptr = environ_buf + bufSize;
                HEAPU32[__environ + i * 4 >> 2] = ptr;
                stringToAscii(string, ptr);
                bufSize += string.length + 1;
            });
            return 0;
        };
        var _environ_sizes_get = (penviron_count, penviron_buf_size)=>{
            var strings = getEnvStrings();
            HEAPU32[penviron_count >> 2] = strings.length;
            var bufSize = 0;
            strings.forEach((string)=>bufSize += string.length + 1);
            HEAPU32[penviron_buf_size >> 2] = bufSize;
            return 0;
        };
        var runtimeKeepaliveCounter = 0;
        var keepRuntimeAlive = ()=>noExitRuntime || runtimeKeepaliveCounter > 0;
        var _proc_exit = (code)=>{
            if (!keepRuntimeAlive()) {
                Module["onExit"]?.(code);
                ABORT = true;
            }
            quit_(code, new ExitStatus(code));
        };
        /** @suppress {duplicate } */ /** @param {boolean|number=} implicit */ var exitJS = (status, implicit)=>{
            _proc_exit(status);
        };
        var _exit = exitJS;
        var _fd_close = (fd)=>52;
        var _fd_fdstat_get = (fd, pbuf)=>{
            var rightsBase = 0;
            var rightsInheriting = 0;
            var flags = 0;
            {
                // Hack to support printf in SYSCALLS_REQUIRE_FILESYSTEM=0. We support at
                // least stdin, stdout, stderr in a simple way.
                var type = 2;
                if (fd == 0) {
                    rightsBase = 2;
                } else if (fd == 1 || fd == 2) {
                    rightsBase = 64;
                }
                flags = 1;
            }
            HEAP8[pbuf] = type;
            HEAP16[pbuf + 2 >> 1] = flags;
            HEAP64[pbuf + 8 >> 3] = BigInt(rightsBase);
            HEAP64[pbuf + 16 >> 3] = BigInt(rightsInheriting);
            return 0;
        };
        function _fd_pread(fd, iov, iovcnt, offset, pnum) {
            return 52;
        }
        var _fd_read = (fd, iov, iovcnt, pnum)=>52;
        function _fd_seek(fd, offset, whence, newOffset) {
            return 70;
        }
        var printCharBuffers = [
            null,
            [],
            []
        ];
        var printChar = (stream, curr)=>{
            var buffer = printCharBuffers[stream];
            if (curr === 0 || curr === 10) {
                (stream === 1 ? out : err)(UTF8ArrayToString(buffer));
                buffer.length = 0;
            } else {
                buffer.push(curr);
            }
        };
        var _fd_write = (fd, iov, iovcnt, pnum)=>{
            // hack to support printf in SYSCALLS_REQUIRE_FILESYSTEM=0
            var num = 0;
            for(var i = 0; i < iovcnt; i++){
                var ptr = HEAPU32[iov >> 2];
                var len = HEAPU32[iov + 4 >> 2];
                iov += 8;
                for(var j = 0; j < len; j++){
                    printChar(fd, HEAPU8[ptr + j]);
                }
                num += len;
            }
            HEAPU32[pnum >> 2] = num;
            return 0;
        };
        var getCFunc = (ident)=>{
            var func = Module["_" + ident];
            // closure exported function
            return func;
        };
        var writeArrayToMemory = (array, buffer)=>{
            HEAP8.set(array, buffer);
        };
        var stackAlloc = (sz)=>__emscripten_stack_alloc(sz);
        var stringToUTF8OnStack = (str)=>{
            var size = lengthBytesUTF8(str) + 1;
            var ret = stackAlloc(size);
            stringToUTF8(str, ret, size);
            return ret;
        };
        /**
     * @param {string|null=} returnType
     * @param {Array=} argTypes
     * @param {Arguments|Array=} args
     * @param {Object=} opts
     */ var ccall = (ident, returnType, argTypes, args, opts)=>{
            // For fast lookup of conversion functions
            var toC = {
                "string": (str)=>{
                    var ret = 0;
                    if (str !== null && str !== undefined && str !== 0) {
                        // null string
                        ret = stringToUTF8OnStack(str);
                    }
                    return ret;
                },
                "array": (arr)=>{
                    var ret = stackAlloc(arr.length);
                    writeArrayToMemory(arr, ret);
                    return ret;
                }
            };
            function convertReturnValue(ret) {
                if (returnType === "string") {
                    return UTF8ToString(ret);
                }
                if (returnType === "boolean") return Boolean(ret);
                return ret;
            }
            var func = getCFunc(ident);
            var cArgs = [];
            var stack = 0;
            if (args) {
                for(var i = 0; i < args.length; i++){
                    var converter = toC[argTypes[i]];
                    if (converter) {
                        if (stack === 0) stack = stackSave();
                        cArgs[i] = converter(args[i]);
                    } else {
                        cArgs[i] = args[i];
                    }
                }
            }
            var ret = func(...cArgs);
            function onDone(ret) {
                if (stack !== 0) stackRestore(stack);
                return convertReturnValue(ret);
            }
            ret = onDone(ret);
            return ret;
        };
        /**
     * @param {string=} returnType
     * @param {Array=} argTypes
     * @param {Object=} opts
     */ var cwrap = (ident, returnType, argTypes, opts)=>{
            // When the function takes numbers and returns a number, we can just return
            // the original function
            var numericArgs = !argTypes || argTypes.every((type)=>type === "number" || type === "boolean");
            var numericRet = returnType !== "string";
            if (numericRet && numericArgs && !opts) {
                return getCFunc(ident);
            }
            return (...args)=>ccall(ident, returnType, argTypes, args);
        };
        var wasmImports = {
            /** @export */ a: ___cxa_throw,
            /** @export */ g: ___syscall_fstat64,
            /** @export */ o: ___syscall_getcwd,
            /** @export */ d: ___syscall_lstat64,
            /** @export */ e: ___syscall_newfstatat,
            /** @export */ p: ___syscall_openat,
            /** @export */ f: ___syscall_stat64,
            /** @export */ s: __abort_js,
            /** @export */ k: __mmap_js,
            /** @export */ l: __munmap_js,
            /** @export */ t: _emscripten_resize_heap,
            /** @export */ m: _environ_get,
            /** @export */ n: _environ_sizes_get,
            /** @export */ h: _exit,
            /** @export */ c: _fd_close,
            /** @export */ b: _fd_fdstat_get,
            /** @export */ i: _fd_pread,
            /** @export */ r: _fd_read,
            /** @export */ j: _fd_seek,
            /** @export */ q: _fd_write
        };
        var wasmExports = createWasm();
        Module["_ks_version"] = (a0, a1)=>(Module["_ks_version"] = wasmExports["w"])(a0, a1);
        Module["_ks_errno"] = (a0)=>(Module["_ks_errno"] = wasmExports["x"])(a0);
        Module["_ks_strerror"] = (a0)=>(Module["_ks_strerror"] = wasmExports["y"])(a0);
        Module["_ks_arch_supported"] = (a0)=>(Module["_ks_arch_supported"] = wasmExports["z"])(a0);
        Module["_ks_open"] = (a0, a1, a2)=>(Module["_ks_open"] = wasmExports["A"])(a0, a1, a2);
        Module["_ks_close"] = (a0)=>(Module["_ks_close"] = wasmExports["B"])(a0);
        Module["_ks_option"] = (a0, a1, a2)=>(Module["_ks_option"] = wasmExports["C"])(a0, a1, a2);
        Module["_ks_free"] = (a0)=>(Module["_ks_free"] = wasmExports["D"])(a0);
        Module["_ks_asm"] = (a0, a1, a2, a3, a4, a5)=>(Module["_ks_asm"] = wasmExports["E"])(a0, a1, a2, a3, a4, a5);
        Module["_malloc"] = (a0)=>(Module["_malloc"] = wasmExports["F"])(a0);
        Module["_free"] = (a0)=>(Module["_free"] = wasmExports["G"])(a0);
        var __emscripten_stack_restore = (a0)=>(__emscripten_stack_restore = wasmExports["H"])(a0);
        var __emscripten_stack_alloc = (a0)=>(__emscripten_stack_alloc = wasmExports["I"])(a0);
        var _emscripten_stack_get_current = ()=>(_emscripten_stack_get_current = wasmExports["J"])();
        // include: postamble.js
        // === Auto-generated postamble setup entry stuff ===
        Module["ccall"] = ccall;
        Module["cwrap"] = cwrap;
        Module["getValue"] = getValue;
        Module["UTF8ToString"] = UTF8ToString;
        var calledRun;
        dependenciesFulfilled = function runCaller() {
            // If run has never been called, and we should call run (INVOKE_RUN is true, and Module.noInitialRun is not false)
            if (!calledRun) run();
            if (!calledRun) dependenciesFulfilled = runCaller;
        };
        // try this again later, after new deps are fulfilled
        function run() {
            if (runDependencies > 0) {
                return;
            }
            preRun();
            // a preRun added a dependency, run will be called later
            if (runDependencies > 0) {
                return;
            }
            function doRun() {
                // run may have just been called through dependencies being fulfilled just in this very frame,
                // or while the async setStatus time below was happening
                if (calledRun) return;
                calledRun = true;
                Module["calledRun"] = true;
                if (ABORT) return;
                initRuntime();
                readyPromiseResolve(Module);
                Module["onRuntimeInitialized"]?.();
                postRun();
            }
            if (Module["setStatus"]) {
                Module["setStatus"]("Running...");
                setTimeout(()=>{
                    setTimeout(()=>Module["setStatus"](""), 1);
                    doRun();
                }, 1);
            } else {
                doRun();
            }
        }
        if (Module["preInit"]) {
            if (typeof Module["preInit"] == "function") Module["preInit"] = [
                Module["preInit"]
            ];
            while(Module["preInit"].length > 0){
                Module["preInit"].pop()();
            }
        }
        run();
        // end include: postamble.js
        // include: postamble_modularize.js
        // In MODULARIZE mode we wrap the generated code in a factory function
        // and return either the Module itself, or a promise of the module.
        // We assign to the `moduleRtn` global here and configure closure to see
        // this as and extern so it won't get minified.
        moduleRtn = readyPromise;
        return moduleRtn;
    };
})();

// AUTO-GENERATED FILE, DO NOT EDIT
/* eslint-disable */ const KS_API_MAJOR = 0;
const KS_API_MINOR = 9;
const KS_VERSION_MAJOR = 0;
const KS_VERSION_MINOR = 9;
const KS_VERSION_EXTRA = 2;
const KS_ARCH_ARM = 1;
const KS_ARCH_ARM64 = 2;
const KS_ARCH_MIPS = 3;
const KS_ARCH_X86 = 4;
const KS_ARCH_PPC = 5;
const KS_ARCH_SPARC = 6;
const KS_ARCH_SYSTEMZ = 7;
const KS_ARCH_HEXAGON = 8;
const KS_ARCH_EVM = 9;
const KS_ARCH_RISCV = 10;
const KS_ARCH_MAX = 11;
const KS_MODE_LITTLE_ENDIAN = 0;
const KS_MODE_BIG_ENDIAN = 1073741824;
const KS_MODE_ARM = 1;
const KS_MODE_THUMB = 16;
const KS_MODE_V8 = 64;
const KS_MODE_MICRO = 16;
const KS_MODE_MIPS3 = 32;
const KS_MODE_MIPS32R6 = 64;
const KS_MODE_MIPS32 = 4;
const KS_MODE_MIPS64 = 8;
const KS_MODE_16 = 2;
const KS_MODE_32 = 4;
const KS_MODE_64 = 8;
const KS_MODE_PPC32 = 4;
const KS_MODE_PPC64 = 8;
const KS_MODE_QPX = 16;
const KS_MODE_RISCV32 = 4;
const KS_MODE_RISCV64 = 8;
const KS_MODE_SPARC32 = 4;
const KS_MODE_SPARC64 = 8;
const KS_MODE_V9 = 16;
const KS_ERR_ASM = 128;
const KS_ERR_ASM_ARCH = 512;
const KS_ERR_OK = 0;
const KS_ERR_NOMEM = 1;
const KS_ERR_ARCH = 2;
const KS_ERR_HANDLE = 3;
const KS_ERR_MODE = 4;
const KS_ERR_VERSION = 5;
const KS_ERR_OPT_INVALID = 6;
const KS_ERR_ASM_EXPR_TOKEN = 128;
const KS_ERR_ASM_DIRECTIVE_VALUE_RANGE = 129;
const KS_ERR_ASM_DIRECTIVE_ID = 130;
const KS_ERR_ASM_DIRECTIVE_TOKEN = 131;
const KS_ERR_ASM_DIRECTIVE_STR = 132;
const KS_ERR_ASM_DIRECTIVE_COMMA = 133;
const KS_ERR_ASM_DIRECTIVE_RELOC_NAME = 134;
const KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN = 135;
const KS_ERR_ASM_DIRECTIVE_FPOINT = 136;
const KS_ERR_ASM_DIRECTIVE_UNKNOWN = 137;
const KS_ERR_ASM_DIRECTIVE_EQU = 138;
const KS_ERR_ASM_DIRECTIVE_INVALID = 139;
const KS_ERR_ASM_VARIANT_INVALID = 140;
const KS_ERR_ASM_EXPR_BRACKET = 141;
const KS_ERR_ASM_SYMBOL_MODIFIER = 142;
const KS_ERR_ASM_SYMBOL_REDEFINED = 143;
const KS_ERR_ASM_SYMBOL_MISSING = 144;
const KS_ERR_ASM_RPAREN = 145;
const KS_ERR_ASM_STAT_TOKEN = 146;
const KS_ERR_ASM_UNSUPPORTED = 147;
const KS_ERR_ASM_MACRO_TOKEN = 148;
const KS_ERR_ASM_MACRO_PAREN = 149;
const KS_ERR_ASM_MACRO_EQU = 150;
const KS_ERR_ASM_MACRO_ARGS = 151;
const KS_ERR_ASM_MACRO_LEVELS_EXCEED = 152;
const KS_ERR_ASM_MACRO_STR = 153;
const KS_ERR_ASM_MACRO_INVALID = 154;
const KS_ERR_ASM_ESC_BACKSLASH = 155;
const KS_ERR_ASM_ESC_OCTAL = 156;
const KS_ERR_ASM_ESC_SEQUENCE = 157;
const KS_ERR_ASM_ESC_STR = 158;
const KS_ERR_ASM_TOKEN_INVALID = 159;
const KS_ERR_ASM_INSN_UNSUPPORTED = 160;
const KS_ERR_ASM_FIXUP_INVALID = 161;
const KS_ERR_ASM_LABEL_INVALID = 162;
const KS_ERR_ASM_FRAGMENT_INVALID = 163;
const KS_ERR_ASM_INVALIDOPERAND = 512;
const KS_ERR_ASM_MISSINGFEATURE = 513;
const KS_ERR_ASM_MNEMONICFAIL = 514;
const KS_OPT_SYNTAX = 1;
const KS_OPT_SYM_RESOLVER = 2;
const KS_OPT_SYNTAX_INTEL = 1;
const KS_OPT_SYNTAX_ATT = 2;
const KS_OPT_SYNTAX_NASM = 4;
const KS_OPT_SYNTAX_MASM = 8;
const KS_OPT_SYNTAX_GAS = 16;
const KS_OPT_SYNTAX_RADIX16 = 32;

var _const = /*#__PURE__*/Object.freeze({
  __proto__: null,
  KS_API_MAJOR: KS_API_MAJOR,
  KS_API_MINOR: KS_API_MINOR,
  KS_ARCH_ARM: KS_ARCH_ARM,
  KS_ARCH_ARM64: KS_ARCH_ARM64,
  KS_ARCH_EVM: KS_ARCH_EVM,
  KS_ARCH_HEXAGON: KS_ARCH_HEXAGON,
  KS_ARCH_MAX: KS_ARCH_MAX,
  KS_ARCH_MIPS: KS_ARCH_MIPS,
  KS_ARCH_PPC: KS_ARCH_PPC,
  KS_ARCH_RISCV: KS_ARCH_RISCV,
  KS_ARCH_SPARC: KS_ARCH_SPARC,
  KS_ARCH_SYSTEMZ: KS_ARCH_SYSTEMZ,
  KS_ARCH_X86: KS_ARCH_X86,
  KS_ERR_ARCH: KS_ERR_ARCH,
  KS_ERR_ASM: KS_ERR_ASM,
  KS_ERR_ASM_ARCH: KS_ERR_ASM_ARCH,
  KS_ERR_ASM_DIRECTIVE_COMMA: KS_ERR_ASM_DIRECTIVE_COMMA,
  KS_ERR_ASM_DIRECTIVE_EQU: KS_ERR_ASM_DIRECTIVE_EQU,
  KS_ERR_ASM_DIRECTIVE_FPOINT: KS_ERR_ASM_DIRECTIVE_FPOINT,
  KS_ERR_ASM_DIRECTIVE_ID: KS_ERR_ASM_DIRECTIVE_ID,
  KS_ERR_ASM_DIRECTIVE_INVALID: KS_ERR_ASM_DIRECTIVE_INVALID,
  KS_ERR_ASM_DIRECTIVE_RELOC_NAME: KS_ERR_ASM_DIRECTIVE_RELOC_NAME,
  KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN: KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN,
  KS_ERR_ASM_DIRECTIVE_STR: KS_ERR_ASM_DIRECTIVE_STR,
  KS_ERR_ASM_DIRECTIVE_TOKEN: KS_ERR_ASM_DIRECTIVE_TOKEN,
  KS_ERR_ASM_DIRECTIVE_UNKNOWN: KS_ERR_ASM_DIRECTIVE_UNKNOWN,
  KS_ERR_ASM_DIRECTIVE_VALUE_RANGE: KS_ERR_ASM_DIRECTIVE_VALUE_RANGE,
  KS_ERR_ASM_ESC_BACKSLASH: KS_ERR_ASM_ESC_BACKSLASH,
  KS_ERR_ASM_ESC_OCTAL: KS_ERR_ASM_ESC_OCTAL,
  KS_ERR_ASM_ESC_SEQUENCE: KS_ERR_ASM_ESC_SEQUENCE,
  KS_ERR_ASM_ESC_STR: KS_ERR_ASM_ESC_STR,
  KS_ERR_ASM_EXPR_BRACKET: KS_ERR_ASM_EXPR_BRACKET,
  KS_ERR_ASM_EXPR_TOKEN: KS_ERR_ASM_EXPR_TOKEN,
  KS_ERR_ASM_FIXUP_INVALID: KS_ERR_ASM_FIXUP_INVALID,
  KS_ERR_ASM_FRAGMENT_INVALID: KS_ERR_ASM_FRAGMENT_INVALID,
  KS_ERR_ASM_INSN_UNSUPPORTED: KS_ERR_ASM_INSN_UNSUPPORTED,
  KS_ERR_ASM_INVALIDOPERAND: KS_ERR_ASM_INVALIDOPERAND,
  KS_ERR_ASM_LABEL_INVALID: KS_ERR_ASM_LABEL_INVALID,
  KS_ERR_ASM_MACRO_ARGS: KS_ERR_ASM_MACRO_ARGS,
  KS_ERR_ASM_MACRO_EQU: KS_ERR_ASM_MACRO_EQU,
  KS_ERR_ASM_MACRO_INVALID: KS_ERR_ASM_MACRO_INVALID,
  KS_ERR_ASM_MACRO_LEVELS_EXCEED: KS_ERR_ASM_MACRO_LEVELS_EXCEED,
  KS_ERR_ASM_MACRO_PAREN: KS_ERR_ASM_MACRO_PAREN,
  KS_ERR_ASM_MACRO_STR: KS_ERR_ASM_MACRO_STR,
  KS_ERR_ASM_MACRO_TOKEN: KS_ERR_ASM_MACRO_TOKEN,
  KS_ERR_ASM_MISSINGFEATURE: KS_ERR_ASM_MISSINGFEATURE,
  KS_ERR_ASM_MNEMONICFAIL: KS_ERR_ASM_MNEMONICFAIL,
  KS_ERR_ASM_RPAREN: KS_ERR_ASM_RPAREN,
  KS_ERR_ASM_STAT_TOKEN: KS_ERR_ASM_STAT_TOKEN,
  KS_ERR_ASM_SYMBOL_MISSING: KS_ERR_ASM_SYMBOL_MISSING,
  KS_ERR_ASM_SYMBOL_MODIFIER: KS_ERR_ASM_SYMBOL_MODIFIER,
  KS_ERR_ASM_SYMBOL_REDEFINED: KS_ERR_ASM_SYMBOL_REDEFINED,
  KS_ERR_ASM_TOKEN_INVALID: KS_ERR_ASM_TOKEN_INVALID,
  KS_ERR_ASM_UNSUPPORTED: KS_ERR_ASM_UNSUPPORTED,
  KS_ERR_ASM_VARIANT_INVALID: KS_ERR_ASM_VARIANT_INVALID,
  KS_ERR_HANDLE: KS_ERR_HANDLE,
  KS_ERR_MODE: KS_ERR_MODE,
  KS_ERR_NOMEM: KS_ERR_NOMEM,
  KS_ERR_OK: KS_ERR_OK,
  KS_ERR_OPT_INVALID: KS_ERR_OPT_INVALID,
  KS_ERR_VERSION: KS_ERR_VERSION,
  KS_MODE_16: KS_MODE_16,
  KS_MODE_32: KS_MODE_32,
  KS_MODE_64: KS_MODE_64,
  KS_MODE_ARM: KS_MODE_ARM,
  KS_MODE_BIG_ENDIAN: KS_MODE_BIG_ENDIAN,
  KS_MODE_LITTLE_ENDIAN: KS_MODE_LITTLE_ENDIAN,
  KS_MODE_MICRO: KS_MODE_MICRO,
  KS_MODE_MIPS3: KS_MODE_MIPS3,
  KS_MODE_MIPS32: KS_MODE_MIPS32,
  KS_MODE_MIPS32R6: KS_MODE_MIPS32R6,
  KS_MODE_MIPS64: KS_MODE_MIPS64,
  KS_MODE_PPC32: KS_MODE_PPC32,
  KS_MODE_PPC64: KS_MODE_PPC64,
  KS_MODE_QPX: KS_MODE_QPX,
  KS_MODE_RISCV32: KS_MODE_RISCV32,
  KS_MODE_RISCV64: KS_MODE_RISCV64,
  KS_MODE_SPARC32: KS_MODE_SPARC32,
  KS_MODE_SPARC64: KS_MODE_SPARC64,
  KS_MODE_THUMB: KS_MODE_THUMB,
  KS_MODE_V8: KS_MODE_V8,
  KS_MODE_V9: KS_MODE_V9,
  KS_OPT_SYM_RESOLVER: KS_OPT_SYM_RESOLVER,
  KS_OPT_SYNTAX: KS_OPT_SYNTAX,
  KS_OPT_SYNTAX_ATT: KS_OPT_SYNTAX_ATT,
  KS_OPT_SYNTAX_GAS: KS_OPT_SYNTAX_GAS,
  KS_OPT_SYNTAX_INTEL: KS_OPT_SYNTAX_INTEL,
  KS_OPT_SYNTAX_MASM: KS_OPT_SYNTAX_MASM,
  KS_OPT_SYNTAX_NASM: KS_OPT_SYNTAX_NASM,
  KS_OPT_SYNTAX_RADIX16: KS_OPT_SYNTAX_RADIX16,
  KS_VERSION_EXTRA: KS_VERSION_EXTRA,
  KS_VERSION_MAJOR: KS_VERSION_MAJOR,
  KS_VERSION_MINOR: KS_VERSION_MINOR
});

const POINTER_SIZE = 4;
function defineMethods(obj) {
    return obj;
}

const METHODS_TYPES = defineMethods({
    ks_open: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    ks_asm: {
        returnType: 'number',
        argTypes: [
            'number',
            'string',
            'number',
            'number',
            'number',
            'number'
        ]
    },
    ks_free: {
        returnType: null,
        argTypes: [
            'number'
        ]
    },
    ks_close: {
        returnType: 'number',
        argTypes: [
            'number'
        ]
    },
    ks_option: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    ks_errno: {
        returnType: 'number',
        argTypes: [
            'number'
        ]
    },
    ks_version: {
        returnType: 'number',
        argTypes: [
            'number',
            'number'
        ]
    },
    ks_arch_supported: {
        returnType: 'boolean',
        argTypes: [
            'number'
        ]
    },
    ks_strerror: {
        returnType: 'string',
        argTypes: [
            'number'
        ]
    },
    malloc: {
        returnType: 'number',
        argTypes: [
            'number'
        ]
    },
    free: {
        returnType: null,
        argTypes: [
            'number'
        ]
    }
});
let keystone;
class Keystone {
    get handle() {
        return keystone.getValue(this.handle_ptr, '*');
    }
    setOption(opt, value) {
        return Keystone.call('ks_option', this.handle, opt, value);
    }
    close() {
        const ret = Keystone.call('ks_close', this.handle);
        if (ret !== KS_ERR_OK) {
            throw new Error(`Failed to close keystone: ${Keystone.strError(ret)}`);
        }
        this.handle_ptr = null;
    }
    asm(data, options = {}) {
        const { address = 0 } = options;
        const bytesPtrPtr = Keystone.call('malloc', POINTER_SIZE);
        const bytesLenPtr = Keystone.call('malloc', POINTER_SIZE);
        const statCountPtr = Keystone.call('malloc', POINTER_SIZE);
        const errNo = Keystone.call('ks_asm', this.handle, data, BigInt(address), bytesPtrPtr, bytesLenPtr, statCountPtr);
        try {
            if (errNo !== KS_ERR_OK) {
                throw new Error(`Failed to assemble, error: ${Keystone.strError(this.errNo())}`);
            }
            const bytesPtr = keystone.getValue(bytesPtrPtr, '*');
            const bytesLen = keystone.getValue(bytesLenPtr, 'i32');
            const bytes = keystone.HEAPU8.slice(bytesPtr, bytesPtr + bytesLen);
            Keystone.call('ks_free', bytesPtr);
            return bytes;
        } finally{
            Keystone.call('free', bytesPtrPtr);
            Keystone.call('free', bytesLenPtr);
            Keystone.call('free', statCountPtr);
        }
    }
    errNo() {
        return Keystone.call('ks_errno', this.handle);
    }
    static call(name, ...args) {
        const methodType = METHODS_TYPES[name];
        return keystone.ccall(name, methodType.returnType, methodType.argTypes, args);
    }
    static version() {
        const int = this.call('ks_version');
        /* eslint-disable no-bitwise */ return {
            major: int >> 8,
            minor: int & 0xff
        };
    /* eslint-enable no-bitwise */ }
    static archSupported(query) {
        return this.call('ks_arch_supported', query);
    }
    static strError(errNo) {
        return this.call('ks_strerror', errNo);
    }
    constructor(arch, mode){
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = Keystone.call('malloc', POINTER_SIZE);
        const ret = Keystone.call('ks_open', arch, mode, this.handle_ptr);
        if (ret !== KS_ERR_OK) {
            throw new Error(`Failed to initialize keystone: ${Keystone.strError(ret)}`);
        }
    }
}
async function factory(args) {
    if (keystone) {
        return;
    }
    keystone = await keystone$1(args);
}

exports.Const = _const;
exports.Keystone = Keystone;
exports.loadKeystone = factory;
