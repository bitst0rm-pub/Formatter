'use strict';

var _documentCurrentScript = typeof document !== 'undefined' ? document.currentScript : null;
var capstone$1 = (()=>{
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
                process.argv[1].replace(/\\/g, "/");
            }
            process.argv.slice(2);
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
        Module["print"] || console.log.bind(console);
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
        if (Module["thisProgram"]) Module["thisProgram"];
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
                var f = "capstone.wasm";
                if (!isDataURI(f)) {
                    return locateFile(f);
                }
                return f;
            }
            // Use bundler-friendly `new URL(..., import.meta.url)` pattern; works in browsers too.
            return new URL("capstone.wasm", (typeof document === 'undefined' ? require('u' + 'rl').pathToFileURL(__filename).href : (_documentCurrentScript && _documentCurrentScript.tagName.toUpperCase() === 'SCRIPT' && _documentCurrentScript.src || new URL('index.cjs', document.baseURI).href))).href;
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
                wasmMemory = wasmExports["b"];
                updateMemoryViews();
                addOnInit(wasmExports["c"]);
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
        Module["noExitRuntime"] || true;
        var stackRestore = (val)=>__emscripten_stack_restore(val);
        var stackSave = ()=>_emscripten_stack_get_current();
        var abortOnCannotGrowMemory = (requestedSize)=>{
            abort("OOM");
        };
        var _emscripten_resize_heap = (requestedSize)=>{
            HEAPU8.length;
            abortOnCannotGrowMemory();
        };
        var getCFunc = (ident)=>{
            var func = Module["_" + ident];
            // closure exported function
            return func;
        };
        var writeArrayToMemory = (array, buffer)=>{
            HEAP8.set(array, buffer);
        };
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
        var stackAlloc = (sz)=>__emscripten_stack_alloc(sz);
        var stringToUTF8OnStack = (str)=>{
            var size = lengthBytesUTF8(str) + 1;
            var ret = stackAlloc(size);
            stringToUTF8(str, ret, size);
            return ret;
        };
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
            /** @export */ a: _emscripten_resize_heap
        };
        var wasmExports = createWasm();
        Module["_cs_version"] = (a0, a1)=>(Module["_cs_version"] = wasmExports["d"])(a0, a1);
        Module["_cs_support"] = (a0)=>(Module["_cs_support"] = wasmExports["e"])(a0);
        Module["_cs_errno"] = (a0)=>(Module["_cs_errno"] = wasmExports["f"])(a0);
        Module["_cs_strerror"] = (a0)=>(Module["_cs_strerror"] = wasmExports["g"])(a0);
        Module["_cs_open"] = (a0, a1, a2)=>(Module["_cs_open"] = wasmExports["h"])(a0, a1, a2);
        Module["_cs_close"] = (a0)=>(Module["_cs_close"] = wasmExports["i"])(a0);
        Module["_cs_option"] = (a0, a1, a2)=>(Module["_cs_option"] = wasmExports["j"])(a0, a1, a2);
        Module["_cs_disasm"] = (a0, a1, a2, a3, a4, a5)=>(Module["_cs_disasm"] = wasmExports["k"])(a0, a1, a2, a3, a4, a5);
        Module["_cs_free"] = (a0, a1)=>(Module["_cs_free"] = wasmExports["l"])(a0, a1);
        Module["_cs_malloc"] = (a0)=>(Module["_cs_malloc"] = wasmExports["m"])(a0);
        Module["_cs_reg_name"] = (a0, a1)=>(Module["_cs_reg_name"] = wasmExports["n"])(a0, a1);
        Module["_cs_insn_name"] = (a0, a1)=>(Module["_cs_insn_name"] = wasmExports["o"])(a0, a1);
        Module["_cs_group_name"] = (a0, a1)=>(Module["_cs_group_name"] = wasmExports["p"])(a0, a1);
        Module["_cs_insn_group"] = (a0, a1, a2)=>(Module["_cs_insn_group"] = wasmExports["q"])(a0, a1, a2);
        Module["_cs_reg_read"] = (a0, a1, a2)=>(Module["_cs_reg_read"] = wasmExports["r"])(a0, a1, a2);
        Module["_cs_reg_write"] = (a0, a1, a2)=>(Module["_cs_reg_write"] = wasmExports["s"])(a0, a1, a2);
        Module["_cs_op_count"] = (a0, a1, a2)=>(Module["_cs_op_count"] = wasmExports["t"])(a0, a1, a2);
        Module["_cs_op_index"] = (a0, a1, a2, a3)=>(Module["_cs_op_index"] = wasmExports["u"])(a0, a1, a2, a3);
        Module["_cs_regs_access"] = (a0, a1, a2, a3, a4, a5)=>(Module["_cs_regs_access"] = wasmExports["v"])(a0, a1, a2, a3, a4, a5);
        Module["_malloc"] = (a0)=>(Module["_malloc"] = wasmExports["w"])(a0);
        Module["_free"] = (a0)=>(Module["_free"] = wasmExports["x"])(a0);
        var __emscripten_stack_restore = (a0)=>(__emscripten_stack_restore = wasmExports["y"])(a0);
        var __emscripten_stack_alloc = (a0)=>(__emscripten_stack_alloc = wasmExports["z"])(a0);
        var _emscripten_stack_get_current = ()=>(_emscripten_stack_get_current = wasmExports["A"])();
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
/* eslint-disable */ const CS_API_MAJOR = 5;
const CS_API_MINOR = 0;
const CS_ARCH_ARM = 0;
const CS_ARCH_ARM64 = 1;
const CS_ARCH_MIPS = 2;
const CS_ARCH_X86 = 3;
const CS_ARCH_PPC = 4;
const CS_ARCH_SPARC = 5;
const CS_ARCH_SYSZ = 6;
const CS_ARCH_XCORE = 7;
const CS_ARCH_M68K = 8;
const CS_ARCH_TMS320C64X = 9;
const CS_ARCH_M680X = 10;
const CS_ARCH_MAX = 11;
const CS_ARCH_ALL = 0xFFFF;
const CS_MODE_LITTLE_ENDIAN = 0;
const CS_MODE_ARM = 0;
const CS_MODE_16 = 1 << 1;
const CS_MODE_32 = 1 << 2;
const CS_MODE_64 = 1 << 3;
const CS_MODE_THUMB = 1 << 4;
const CS_MODE_MCLASS = 1 << 5;
const CS_MODE_V8 = 1 << 6;
const CS_MODE_MICRO = 1 << 4;
const CS_MODE_MIPS3 = 1 << 5;
const CS_MODE_MIPS32R6 = 1 << 6;
const CS_MODE_MIPS2 = 1 << 7;
const CS_MODE_BIG_ENDIAN = 1 << 31;
const CS_MODE_V9 = 1 << 4;
const CS_MODE_MIPS32 = CS_MODE_32;
const CS_MODE_MIPS64 = CS_MODE_64;
const CS_MODE_QPX = 1 << 4;
const CS_MODE_SPE = 1 << 5;
const CS_MODE_BOOKE = 1 << 6;
const CS_MODE_PS = 1 << 7;
const CS_MODE_M680X_6301 = 1 << 1;
const CS_MODE_M680X_6309 = 1 << 2;
const CS_MODE_M680X_6800 = 1 << 3;
const CS_MODE_M680X_6801 = 1 << 4;
const CS_MODE_M680X_6805 = 1 << 5;
const CS_MODE_M680X_6808 = 1 << 6;
const CS_MODE_M680X_6809 = 1 << 7;
const CS_MODE_M680X_6811 = 1 << 8;
const CS_MODE_M680X_CPU12 = 1 << 9;
const CS_MODE_M680X_HCS08 = 1 << 10;
const CS_ERR_OK = 0;
const CS_ERR_MEM = 1;
const CS_ERR_ARCH = 2;
const CS_ERR_HANDLE = 3;
const CS_ERR_CSH = 4;
const CS_ERR_MODE = 5;
const CS_ERR_OPTION = 6;
const CS_ERR_DETAIL = 7;
const CS_ERR_MEMSETUP = 8;
const CS_ERR_VERSION = 9;
const CS_ERR_DIET = 10;
const CS_ERR_SKIPDATA = 11;
const CS_ERR_X86_ATT = 12;
const CS_ERR_X86_INTEL = 13;
const CS_OPT_SYNTAX = 1;
const CS_OPT_DETAIL = 2;
const CS_OPT_MODE = 3;
const CS_OPT_OFF = 0;
const CS_OPT_SYNTAX_INTEL = 1;
const CS_OPT_SYNTAX_ATT = 2;
const CS_OPT_ON = 3;
const CS_OPT_SYNTAX_NOREGNAME = 3;
const CS_OP_INVALID = 0;
const CS_OP_REG = 1;
const CS_OP_IMM = 2;
const CS_OP_MEM = 3;
const CS_OP_FP = 4;
const CS_AC_INVALID = 0;
const CS_AC_READ = 1 << 0;
const CS_AC_WRITE = 1 << 1;
const CS_GRP_INVALID = 0;
const CS_GRP_JUMP = 1;
const CS_GRP_CALL = 2;
const CS_GRP_RET = 3;
const CS_GRP_INT = 4;
const CS_GRP_IRET = 5;
const CS_GRP_PRIVILEGE = 6;
const CS_SUPPORT_DIET = CS_ARCH_ALL + 1;
const CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL + 2;

var _const = /*#__PURE__*/Object.freeze({
  __proto__: null,
  CS_AC_INVALID: CS_AC_INVALID,
  CS_AC_READ: CS_AC_READ,
  CS_AC_WRITE: CS_AC_WRITE,
  CS_API_MAJOR: CS_API_MAJOR,
  CS_API_MINOR: CS_API_MINOR,
  CS_ARCH_ALL: CS_ARCH_ALL,
  CS_ARCH_ARM: CS_ARCH_ARM,
  CS_ARCH_ARM64: CS_ARCH_ARM64,
  CS_ARCH_M680X: CS_ARCH_M680X,
  CS_ARCH_M68K: CS_ARCH_M68K,
  CS_ARCH_MAX: CS_ARCH_MAX,
  CS_ARCH_MIPS: CS_ARCH_MIPS,
  CS_ARCH_PPC: CS_ARCH_PPC,
  CS_ARCH_SPARC: CS_ARCH_SPARC,
  CS_ARCH_SYSZ: CS_ARCH_SYSZ,
  CS_ARCH_TMS320C64X: CS_ARCH_TMS320C64X,
  CS_ARCH_X86: CS_ARCH_X86,
  CS_ARCH_XCORE: CS_ARCH_XCORE,
  CS_ERR_ARCH: CS_ERR_ARCH,
  CS_ERR_CSH: CS_ERR_CSH,
  CS_ERR_DETAIL: CS_ERR_DETAIL,
  CS_ERR_DIET: CS_ERR_DIET,
  CS_ERR_HANDLE: CS_ERR_HANDLE,
  CS_ERR_MEM: CS_ERR_MEM,
  CS_ERR_MEMSETUP: CS_ERR_MEMSETUP,
  CS_ERR_MODE: CS_ERR_MODE,
  CS_ERR_OK: CS_ERR_OK,
  CS_ERR_OPTION: CS_ERR_OPTION,
  CS_ERR_SKIPDATA: CS_ERR_SKIPDATA,
  CS_ERR_VERSION: CS_ERR_VERSION,
  CS_ERR_X86_ATT: CS_ERR_X86_ATT,
  CS_ERR_X86_INTEL: CS_ERR_X86_INTEL,
  CS_GRP_CALL: CS_GRP_CALL,
  CS_GRP_INT: CS_GRP_INT,
  CS_GRP_INVALID: CS_GRP_INVALID,
  CS_GRP_IRET: CS_GRP_IRET,
  CS_GRP_JUMP: CS_GRP_JUMP,
  CS_GRP_PRIVILEGE: CS_GRP_PRIVILEGE,
  CS_GRP_RET: CS_GRP_RET,
  CS_MODE_16: CS_MODE_16,
  CS_MODE_32: CS_MODE_32,
  CS_MODE_64: CS_MODE_64,
  CS_MODE_ARM: CS_MODE_ARM,
  CS_MODE_BIG_ENDIAN: CS_MODE_BIG_ENDIAN,
  CS_MODE_BOOKE: CS_MODE_BOOKE,
  CS_MODE_LITTLE_ENDIAN: CS_MODE_LITTLE_ENDIAN,
  CS_MODE_M680X_6301: CS_MODE_M680X_6301,
  CS_MODE_M680X_6309: CS_MODE_M680X_6309,
  CS_MODE_M680X_6800: CS_MODE_M680X_6800,
  CS_MODE_M680X_6801: CS_MODE_M680X_6801,
  CS_MODE_M680X_6805: CS_MODE_M680X_6805,
  CS_MODE_M680X_6808: CS_MODE_M680X_6808,
  CS_MODE_M680X_6809: CS_MODE_M680X_6809,
  CS_MODE_M680X_6811: CS_MODE_M680X_6811,
  CS_MODE_M680X_CPU12: CS_MODE_M680X_CPU12,
  CS_MODE_M680X_HCS08: CS_MODE_M680X_HCS08,
  CS_MODE_MCLASS: CS_MODE_MCLASS,
  CS_MODE_MICRO: CS_MODE_MICRO,
  CS_MODE_MIPS2: CS_MODE_MIPS2,
  CS_MODE_MIPS3: CS_MODE_MIPS3,
  CS_MODE_MIPS32: CS_MODE_MIPS32,
  CS_MODE_MIPS32R6: CS_MODE_MIPS32R6,
  CS_MODE_MIPS64: CS_MODE_MIPS64,
  CS_MODE_PS: CS_MODE_PS,
  CS_MODE_QPX: CS_MODE_QPX,
  CS_MODE_SPE: CS_MODE_SPE,
  CS_MODE_THUMB: CS_MODE_THUMB,
  CS_MODE_V8: CS_MODE_V8,
  CS_MODE_V9: CS_MODE_V9,
  CS_OPT_DETAIL: CS_OPT_DETAIL,
  CS_OPT_MODE: CS_OPT_MODE,
  CS_OPT_OFF: CS_OPT_OFF,
  CS_OPT_ON: CS_OPT_ON,
  CS_OPT_SYNTAX: CS_OPT_SYNTAX,
  CS_OPT_SYNTAX_ATT: CS_OPT_SYNTAX_ATT,
  CS_OPT_SYNTAX_INTEL: CS_OPT_SYNTAX_INTEL,
  CS_OPT_SYNTAX_NOREGNAME: CS_OPT_SYNTAX_NOREGNAME,
  CS_OP_FP: CS_OP_FP,
  CS_OP_IMM: CS_OP_IMM,
  CS_OP_INVALID: CS_OP_INVALID,
  CS_OP_MEM: CS_OP_MEM,
  CS_OP_REG: CS_OP_REG,
  CS_SUPPORT_DIET: CS_SUPPORT_DIET,
  CS_SUPPORT_X86_REDUCE: CS_SUPPORT_X86_REDUCE
});

const POINTER_SIZE = 4;
function defineMethods(obj) {
    return obj;
}
function getNativeTypeSize(type) {
    switch(type){
        case '*':
            return POINTER_SIZE;
        case 'i1':
        case 'i8':
            return 1;
        case 'i16':
            return 2;
        case 'i32':
            return 4;
        case 'i64':
            return 8;
        case 'float':
            return 4;
        case 'double':
            return 8;
        default:
            {
                throw new Error(`Unsupported type: ${type}`);
            }
    }
}
function getFieldSize(field) {
    if (field.type === 'string' || field.type === 'bytes') {
        return field.size;
    }
    return getNativeTypeSize(field.type);
}
function getStructFieldPadding(offset, size) {
    const remainder = offset % size;
    if (remainder) {
        return size - remainder;
    }
    return 0;
}
function sizeOfStruct(fields) {
    return fields.reduce((acc, field)=>{
        const size = getFieldSize(field);
        const padding = field.type === 'string' || field.type === 'bytes' ? 0 : getStructFieldPadding(acc, size);
        return acc + padding + size;
    }, 0);
}
function readStruct(module, ptr, fields) {
    let offset = 0;
    return fields.reduce((obj, field)=>{
        let value;
        let size;
        if (field.type === 'string') {
            size = field.size;
            value = module.UTF8ToString(ptr + offset, size);
        } else if (field.type === 'bytes') {
            size = field.size;
            value = module.HEAPU8.slice(ptr + offset, ptr + offset + size);
        } else {
            size = getNativeTypeSize(field.type);
            offset += getStructFieldPadding(offset, size);
            value = module.getValue(ptr + offset, field.type);
        }
        offset += size;
        if (field.name) {
            return {
                ...obj,
                [field.name]: value
            };
        }
        return obj;
    }, {});
}

const METHODS_TYPES = defineMethods({
    cs_open: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_disasm: {
        returnType: 'number',
        argTypes: [
            'number',
            'array',
            'number',
            'number',
            'number',
            'number'
        ]
    },
    cs_free: {
        returnType: null,
        argTypes: [
            'number',
            'number'
        ]
    },
    cs_close: {
        returnType: 'number',
        argTypes: [
            'number'
        ]
    },
    cs_option: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_reg_name: {
        returnType: 'string',
        argTypes: [
            'number',
            'number'
        ]
    },
    cs_op_count: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_op_index: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number',
            'number'
        ]
    },
    cs_insn_name: {
        returnType: 'string',
        argTypes: [
            'number',
            'number'
        ]
    },
    cs_group_name: {
        returnType: 'string',
        argTypes: [
            'number',
            'number'
        ]
    },
    cs_insn_group: {
        returnType: 'boolean',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_reg_read: {
        returnType: 'boolean',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_reg_write: {
        returnType: 'boolean',
        argTypes: [
            'number',
            'number',
            'number'
        ]
    },
    cs_errno: {
        returnType: 'number',
        argTypes: [
            'number'
        ]
    },
    cs_version: {
        returnType: 'number',
        argTypes: [
            'number',
            'number'
        ]
    },
    cs_support: {
        returnType: 'boolean',
        argTypes: [
            'number'
        ]
    },
    cs_strerror: {
        returnType: 'string',
        argTypes: [
            'number'
        ]
    },
    cs_regs_access: {
        returnType: 'number',
        argTypes: [
            'number',
            'number',
            'number',
            'number',
            'number',
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
let capstone;
const INSN_FIELDS = [
    {
        name: 'id',
        type: 'i32'
    },
    {
        name: 'address',
        type: 'i64'
    },
    {
        name: 'size',
        type: 'i16'
    },
    {
        name: 'bytes',
        type: 'bytes',
        size: 24
    },
    {
        name: 'mnemonic',
        type: 'string',
        size: 32
    },
    {
        name: 'opStr',
        type: 'string',
        size: 160
    },
    {
        // detail pointer
        type: 'i32'
    }
];
const INSN_SIZE = sizeOfStruct(INSN_FIELDS);
class Capstone {
    get handle() {
        return capstone.getValue(this.handle_ptr, '*');
    }
    setOption(opt, value) {
        return Capstone.call('cs_option', this.handle, opt, value);
    }
    close() {
        const ret = Capstone.call('cs_close', this.handle_ptr);
        if (ret !== CS_ERR_OK) {
            throw new Error(`Failed to close capstone: ${Capstone.strError(ret)}`);
        }
        this.handle_ptr = null;
    }
    static readInsn(insnPtr) {
        const insn = readStruct(capstone, insnPtr, INSN_FIELDS);
        insn.bytes = insn.bytes.subarray(0, insn.size);
        return insn;
    }
    disasm(data, options = {}) {
        const { address = 0, count: maxCount = 0 } = options;
        const insnPtrPtr = Capstone.call('malloc', POINTER_SIZE);
        const count = Capstone.call('cs_disasm', this.handle, data, data.length, BigInt(address), maxCount, insnPtrPtr);
        if (count === 0) {
            Capstone.call('free', insnPtrPtr);
            throw new Error(`Failed to disassemble, error: ${Capstone.strError(this.errNo())}`);
        }
        const insnPtr = capstone.getValue(insnPtrPtr, '*');
        const instructions = [];
        for(let i = 0; i < count; i++){
            const insn = Capstone.readInsn(insnPtr + i * INSN_SIZE);
            if (insn.address <= Number.MAX_SAFE_INTEGER) {
                insn.address = Number(insn.address);
            }
            instructions.push(insn);
        }
        Capstone.call('cs_free', insnPtr, count);
        Capstone.call('free', insnPtrPtr);
        return instructions;
    }
    getRegName(id) {
        return Capstone.call('cs_reg_name', this.handle, id);
    }
    getInsnName(id) {
        return Capstone.call('cs_insn_name', this.handle, id);
    }
    getGroupName(id) {
        return Capstone.call('cs_group_name', this.handle, id);
    }
    errNo() {
        return Capstone.call('cs_errno', this.handle);
    }
    static call(name, ...args) {
        const methodType = METHODS_TYPES[name];
        return capstone.ccall(name, methodType.returnType, methodType.argTypes, args);
    }
    static version() {
        const int = this.call('cs_version');
        /* eslint-disable no-bitwise */ return {
            major: int >> 8,
            minor: int & 0xff
        };
    /* eslint-enable no-bitwise */ }
    static support(query) {
        return this.call('cs_support', query);
    }
    static strError(errNo) {
        return this.call('cs_strerror', errNo);
    }
    constructor(arch, mode){
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = Capstone.call('malloc', POINTER_SIZE);
        const ret = Capstone.call('cs_open', arch, mode, this.handle_ptr);
        if (ret !== CS_ERR_OK) {
            throw new Error(`Failed to initialize capstone: ${Capstone.strError(ret)}`);
        }
    }
}
async function factory(args) {
    if (capstone) {
        return;
    }
    capstone = await capstone$1(args);
}

exports.Capstone = Capstone;
exports.Const = _const;
exports.loadCapstone = factory;
