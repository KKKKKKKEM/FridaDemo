// 代码提示: npm i  @types/frida-gum
// 代码提示全局: npm i  @types/frida-gum -g
// 获取前台 activity 与包名：adb shell dumpsys window | findstr "mCurrentFocus"


const HookBox = {
    Native: {
        newStringUTF: function (...exprs) {
            /*
             * hook So NewStringUTF方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */

            var NewStringUTF_addr = null;
            var symbols = Module.enumerateSymbolsSync("libart.so");

            for (var i in symbols) {
                var symbol = symbols[i];
                if (symbol.name == "_ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc") {
                    NewStringUTF_addr = symbol.address;
                }
            }

            if (NewStringUTF_addr) {

                Interceptor.attach(NewStringUTF_addr, {


                    onEnter: function (args) {

                        var string = Memory.readCString(args[1]);
                        for (let index = 0; index < exprs.length; index++) {
                            const element = exprs[index];
                            if (string && string.toString().toLowerCase().indexOf(element) >= 0) { HookBox.tools.log("[NewStringUTF]", 2, `string: ${string.toString()}`) }

                        }


                    },
                    onLeave: function (retvalue) { }

                })



            }
        },
        getStringUTFChars: function (...exprs) {
            /*
             * hook So GetStringUTFChars 方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */

            var GetStringUTFChars_addr = null;
            var symbols = Module.enumerateSymbolsSync("libart.so");

            for (var i in symbols) {
                var symbol = symbols[i];
                if (symbol.name == "_ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh") {
                    GetStringUTFChars_addr = symbol.address;
                }
            }

            if (GetStringUTFChars_addr) {

                Interceptor.attach(GetStringUTFChars_addr, {


                    onEnter: function (args) { },
                    onLeave: function (retval) {
                        var bytes = retval && Memory.readCString(retval);
                        for (let index = 0; index < exprs.length; index++) {
                            const element = exprs[index];
                            if (bytes && bytes.toString().toLowerCase().indexOf(element) >= 0) {
                                HookBox.tools.log("[GetStringUTFChars]", 2, `string: ${bytes.toString()}`)
                            }
                        }
                    }

                })



            }
        },
        registerNatives: function (...exprs) {

            var RegisterNatives_addr = null;
            var symbols = Module.enumerateSymbolsSync("libart.so");

            for (var i in symbols) {
                var symbol = symbols[i];

                if (
                    symbol.name == "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi"
                    // symbol.name.toLowerCase().indexOf("art") >= 0 &&
                    // symbol.name.toLowerCase().indexOf("JNI") >= 0 &&
                    // symbol.name.toLowerCase().indexOf("RegisterNatives") >= 0 &&
                    // symbol.name.toLowerCase().indexOf("CheckJNI") < 0
                ) {
                    Interceptor.attach(symbol.address, {


                        onEnter: function (args) {
                            let env = Java.vm.tryGetEnv()
                            let jClass = env.getClassName(args[1])
                            let methodsPtr = ptr(args[2])
                            let methodCount = ptr(args[3])

                            for (let index = 0; index < methodCount; index++) {
                                // index * Process.pointerSize * 3 只是为了兼容性， 实际是 0
                                let namePtr = Memory.readPointer(methodsPtr.add(index * Process.pointerSize * 3))
                                let sigPtr = Memory.readPointer(methodsPtr.add(index * Process.pointerSize * 3 + Process.pointerSize))
                                // 这里是函数引用
                                let fnPtr = Memory.readPointer(methodsPtr.add(index * Process.pointerSize * 3 + Process.pointerSize * 2))

                                let nameStr = Memory.readCString(namePtr)
                                let sigStr = Memory.readCString(sigPtr)
                                // 从引用中获取信息
                                let fnSymbol = DebugSymbol.fromAddress(fnPtr)
                                let debugSymbol = DebugSymbol.fromAddress(this.returnAddress)

                                for (let index = 0; index < exprs.length; index++) {
                                    const element = exprs[index];
                                    if (nameStr ? nameStr.toLowerCase().indexOf(element) >= 0 : true || fnSymbol ? fnSymbol.toLowerCase().indexOf(element) >= 0 : true) {
                                        HookBox.tools.log(
                                            `[RegisterNatives]`,
                                            0,
                                            `jClass: ${jClass}`,
                                            `name: ${nameStr}`,
                                            `sig: ${sigStr}`,
                                            // `so: ${String(fnSymbol).split(" ")[1].split("!")[0]}`,
                                            // `offset / symbol: ${String(fnSymbol).split(" ")[1].split("!")[1]}`,
                                            // `fnPtr: ${fnPtr}`,
                                            `fnSymbol: ${fnSymbol}`,
                                            `debugSymbol: ${debugSymbol}`,
                                        )


                                    }

                                }


                            }
                        },
                        onLeave: function (retvalue) { }

                    })
                }
            }
        },
        getStaticMethodID: function (...exprs) {
            /*
             * hook So getStaticMethodID 方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */

            var getStaticMethodID_addr = null;
            var symbols = Module.enumerateSymbolsSync("libart.so");

            for (var i in symbols) {
                var symbol = symbols[i];
                if (symbol.name == "_ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_") {
                    getStaticMethodID_addr = symbol.address;
                }
            }

            if (getStaticMethodID_addr) {

                Interceptor.attach(getStaticMethodID_addr, {


                    onEnter: function (args) {
                        if (args[2] != null) {
                            var clazz = args[1];
                            var className = Java.vm.tryGetEnv().getClassName(clazz);
                            var name = Memory.readCString(args[2]);
                            for (let index = 0; index < exprs.length; index++) {
                                const element = exprs[index];
                                if (name && name.toLowerCase().indexOf(element) >= 0) {
                                    let debugSymbol = DebugSymbol.fromAddress(this.returnAddress)
                                    if (args[3] != null) {
                                        var sig = Memory.readCString(args[3]);

                                    } else {
                                        var sig = ""
                                    }

                                    HookBox.tools.log(
                                        "[GetStaticMethodID]",
                                        2,
                                        `className: ${className}`,
                                        `name: ${name}`,
                                        `sig: ${sig}`,
                                        `debugSymbol: ${debugSymbol}`,
                                    )

                                }

                            }



                        }
                    },
                    onLeave: function (retvalue) { }

                })



            }
        },
    },
    jsonObject: {
        put: function (...exprs) {
            /*
             * hook Java JsonObject 的 Put 方法
             * 匹配方式为或的关系
             * exprs -- object 与的关系
                * kexprs: key 规则， 使用 indexOf 进行匹配
                * c value 规则， 使用 indexOf 进行匹配
                * key：key 的值， 使用 === 进行匹配
                * value：value 的值， 使用 === 进行匹配
             */
            let JSONObject = Java.use("org.json.JSONObject");
            JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }

                return this.put(key, value)
            }

            JSONObject.put.overload('java.lang.String', 'double').implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }
                return this.put(key, value)
            }

            JSONObject.put.overload('java.lang.String', 'long').implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }
                return this.put(key, value)
            }

            JSONObject.put.overload('java.lang.String', 'int').implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }
                return this.put(key, value)
            }

            JSONObject.put.overload('java.lang.String', 'boolean').implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }
                return this.put(key, value)
            }
        }
    },
    hashMap: {
        put: function (...exprs) {
            /*
             * hook Java HashMap 的 Put 方法
             * 匹配方式为或的关系
             * exprs -- object 与的关系
                * kexprs: key 规则， 使用 indexOf 进行匹配
                * vexprs： value 规则， 使用 indexOf 进行匹配
                * key：key 的值， 使用 === 进行匹配
                * value：value 的值， 使用 === 进行匹配
             */

            // 获取 Java 的 HashMap
            var linkerHashMap = Java.use('java.util.HashMap');

            // 重载  put 方法 
            linkerHashMap.put.implementation = function (key, value) {

                for (let expr = 0; expr < exprs.length; expr++) {
                    const element = exprs[expr];
                    if (
                        (element.kexprs ? String(key).toLowerCase().indexOf(element.kexprs) > -1 : true) &&
                        (element.vexprs ? String(value).toLowerCase().indexOf(element.vexprs) > -1 : true) &&
                        (element.key ? key === element.key : true) &&
                        (element.value ? value === element.value : true)
                    ) {
                        HookBox.tools.log("[HashMap.put]", 1, `key: ${key}`, `value: ${value}`)
                    }

                }

                return this.put(key, value);


            }



        }
    },
    javaString: {
        getBytes: function (...exprs) {
            /*
             * hook Java String GetBytes 方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */

            // 获取 Java 的字符串
            const str = Java.use('java.lang.String');

            // 重载  getBytes 方法 (但是我也不知道为什么要这样, 是大佬的经验)
            str.getBytes.overload().implementation = function () {


                var response = this.getBytes()
                var string = this.toString();

                for (let index = 0; index < exprs.length; index++) {
                    const element = exprs[index];
                    if (string && string.toLowerCase().indexOf(element) >= 0) {

                        HookBox.tools.log("[String.getBytes]", 1, `target: ${element}`, `string: ${string}`)
                        break
                    }

                }

                return response;
            }
        }
    },
    stringBuilder: {
        toString: function (...exprs) {
            /*
             * hook Java StringBuilder ToString 方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */

            const StringBuilder = Java.use('java.lang.StringBuilder');
            StringBuilder.toString.implementation = function () {

                var string = this.toString();
                for (let index = 0; index < exprs.length; index++) {
                    const element = exprs[index];
                    if (string && string.toLowerCase().indexOf(element) >= 0) {
                        HookBox.tools.log("[StringBuilder.toString]", 1, `string: ${string}`)
                    }


                    return string;
                };

            }
        },
        append: function (...exprs) {
            /*
             * hook Java StringBuilder Append 方法
             * 匹配方式为或的关系
             * exprs -- 使用 indexOf 进行匹配 
             */


            /*
                    .overload('char')
                    .overload('double')
                    .overload('float')
                    .overload('int')
                    .overload('long')
                    .overload('java.lang.CharSequence')
                    .overload('java.lang.Object')
                    .overload('java.lang.String')
                    .overload('java.lang.StringBuffer')
                    .overload('boolean')
                    .overload('[C')
                    .overload('java.lang.CharSequence', 'int', 'int')
                    .overload('[C', 'int', 'int')
            
            */


            const StringBuilder = Java.use('java.lang.StringBuilder');
            StringBuilder.append.overload('java.lang.String').implementation = function (x) {

                for (let index = 0; index < exprs.length; index++) {
                    const element = exprs[index];
                    if (x && String(x).toLowerCase().indexOf(element) >= 0) {
                        HookBox.tools.log("[StringBuilder.append]", 1, `string: ${x}`)
                    }

                    return this.append(x);
                };

            }
        }

    },
    cert: {
        set_custom_verify: function () {
            var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
            if (android_dlopen_ext != null) {
                Interceptor.attach(android_dlopen_ext, {
                    onEnter: function (args) {
                        var soName = args[0].readCString();
                        if (soName.toLowerCase().indexOf("libsscronet.so") != -1) {
                            this.loaded = true;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.loaded) {

                            var set_custom_verify = Module.findExportByName("libttboringssl.so", "SSL_CTX_set_custom_verify");

                            HookBox.tools.log("[set_custom_verify]", 0, `address: ${set_custom_verify}`)
                            Interceptor.attach(set_custom_verify, {
                                onEnter: function (args) {
                                    var callback = args[2];
                                    Interceptor.attach(callback, {
                                        onLeave(retval) {
                                            retval.replace(0); // 0 就是成功
                                        }
                                    });
                                }, onLeave(retval) {
                                }
                            });
                        }
                    }
                });
            }
        }
    },
    tools: {
        switchClassLoader: function (exprs = "") {

            Java.enumerateClassLoaders({
                "onMatch": function (loader) {

                    // 当这个 loader 包含我们的 so 文件时, 进入
                    if (exprs && loader.toString().toLowerCase().indexOf(exprs) >= 0) {
                        // 将当前class factory中的loader指定为我们需要的
                        Java.classFactory.loader = loader;
                        this.loader = loader
                    }
                },
                "onComplete": function () {
                    if (exprs && this.loader >= 0) {
                        // 将当前class factory中的loader指定为我们需要的
                        HookBox.tools.log("[switch loader]", 0, `target: ${exprs}`, `loader: ${this.loader.toString()}`)

                    }

                }
            }
            );
        },
        getJavaStack: function (mode) {
            mode = mode || 1


            function Where(stack) {
                var at = ""
                for (var i = 0; i < stack.length; ++i) {
                    at += stack[i].toString() + "\n"
                }
                return at
            }

            if (mode == 1) {
                return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new())
            } else {
                const thredRef = Java.use("java.lang.Thread")
                var threadIns = thredRef.$new()
                let stack = threadIns.currentThread().getStackTrace()
                return Where(stack)
            }

        },
        log: function (tag, withstack, ...msg) {
            tag = tag || ""
            let msgString = ""
            withstack = withstack || 0
            if (tag) {
                msgString = `=========== ${tag} ===========\n`
            } else {
                msgString = `\n`
            }


            for (let index = 0; index < msg.length; index++) {
                const element = msg[index];
                msgString += element + "\n"

            }

            switch (withstack) {
                case 1:
                    msgString += "\n" + this.getJavaStack()
                    break;

                case 2:
                    msgString += "\n" + this.getJavaStack(2)
                    break;

                default:
                    break;
            }

            console.log(msgString)

        },
        hookClickEvent: function () {
            function getObjClassName(obj) {
                if (!jclazz) {
                    var jclazz = Java.use("java.lang.Class");
                }
                if (!jobj) {
                    var jobj = Java.use("java.lang.Object");
                }
                return jclazz.getName.call(jobj.getClass.call(obj));
            }


            function watch(obj, mtdName) {
                var listener_name = getObjClassName(obj);
                var target = Java.use(listener_name);
                if (!target || !mtdName in target) {
                    return;
                }


                target[mtdName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        HookBox.tools.log("[OnClickEvent]", 2, `mtdName: ${getObjClassName(this)}`)
                        return this[mtdName].apply(this, arguments);
                    };
                })
            }

            Java.use("android.view.View").setOnClickListener.implementation = function (listener) {
                if (listener != null) {
                    watch(listener, 'onClick');
                }
                return this.setOnClickListener(listener);
            };
        },
        sslUnpinning: function () {
            /*
            hook list:
            1.SSLcontext
            2.okhttp
            3.webview
            4.XUtils
            5.httpclientandroidlib
            6.JSSE
            7.network\_security\_config (android 7.0+)
            8.Apache Http client (support partly)
            9.OpenSSLSocketImpl
            10.TrustKit
            11.Cronet
            */

            // Attempts to bypass SSL pinning implementations in a number of
            // ways. These include implementing a new TrustManager that will
            // accept any SSL certificate, overriding OkHTTP v3 check()
            // method etc.
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            // Helper method to honor the quiet flag.

            // Implement a new TrustManager
            // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
            // Java.registerClass() is only supported on ART for now(201803). 所以android 4.4以下不兼容,4.4要切换成ART使用.
            /*
        06-07 16:15:38.541 27021-27073/mi.sslpinningdemo W/System.err: java.lang.IllegalArgumentException: Required method checkServerTrusted(X509Certificate[], String, String, String) missing
        06-07 16:15:38.542 27021-27073/mi.sslpinningdemo W/System.err:     at android.net.http.X509TrustManagerExtensions.<init>(X509TrustManagerExtensions.java:73)
                at mi.ssl.MiPinningTrustManger.<init>(MiPinningTrustManger.java:61)
        06-07 16:15:38.543 27021-27073/mi.sslpinningdemo W/System.err:     at mi.sslpinningdemo.OkHttpUtil.getSecPinningClient(OkHttpUtil.java:112)
                at mi.sslpinningdemo.OkHttpUtil.get(OkHttpUtil.java:62)
                at mi.sslpinningdemo.MainActivity$1$1.run(MainActivity.java:36)
        */
            // var X509Certificate = Java.use("java.security.cert.X509Certificate");
            var TrustManager;
            try {
                TrustManager = Java.registerClass({
                    name: 'org.wooyun.TrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function (chain, authType) { },
                        checkServerTrusted: function (chain, authType) { },
                        getAcceptedIssuers: function () {
                            // var certs = [X509Certificate.$new()];
                            // return certs;
                            return [];
                        }
                    }
                });
            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning]: error: ${e.message}`)
            }





            // Prepare the TrustManagers array to pass to SSLContext.init()
            var TrustManagers = [TrustManager.$new()];

            try {
                // Prepare a Empty SSLFactory
                var TLS_SSLContext = SSLContext.getInstance("TLS");
                TLS_SSLContext.init(null, TrustManagers, null);
                var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] error: ${e.message}`)
            }
            HookBox.tools.log(null, 0, `[SSLUnpinning] Custom, Empty TrustManager ready`)

            // Get a handle on the init() on the SSLContext class
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

            // Override the init method, specifying our new TrustManager
            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] Overriding SSLContext.init() with the custom TrustManager`)

                SSLContext_init.call(this, null, TrustManagers, null);
            };

            /*** okhttp3.x unpinning ***/


            // Wrap the logic in a try/catch as not all applications will have
            // okhttp as part of the app.
            try {

                var CertificatePinner = Java.use('okhttp3.CertificatePinner');

                HookBox.tools.log(null, 0, `[SSLUnpinning] OkHTTP 3.x Found`)

                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {

                    HookBox.tools.log(null, 0, `[SSLUnpinning] OkHTTP 3.x check() called. Not throwing an exception.`)
                }

            } catch (err) {

                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {

                    throw new Error(err);
                }
            }

            // Appcelerator Titanium PinningTrustManager

            // Wrap the logic in a try/catch as not all applications will have
            // appcelerator as part of the app.
            try {

                var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
                HookBox.tools.log(null, 0, `[SSLUnpinning] Appcelerator Titanium Found`)

                PinningTrustManager.checkServerTrusted.implementation = function () {

                    HookBox.tools.log(null, 0, `[SSLUnpinning] Appcelerator checkServerTrusted() called. Not throwing an exception.`)
                }

            } catch (err) {

                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {

                    throw new Error(err);
                }
            }

            /*** okhttp unpinning ***/


            try {
                var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
                OkHttpClient.setCertificatePinner.implementation = function (certificatePinner) {
                    // do nothing
                    HookBox.tools.log(null, 0, `[SSLUnpinning] OkHttpClient.setCertificatePinner Called!`);
                    return this;
                };

                // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
                var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (p0, p1) {
                    // do nothing
                    HookBox.tools.log(null, 0, `[SSLUnpinning] okhttp Called! [Certificate]`);
                    return;
                };
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (p0, p1) {
                    // do nothing
                    HookBox.tools.log(null, 0, `[SSLUnpinning] okhttp Called! [List]`);
                    return;
                };
            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] com.squareup.okhttp not found`);
            }

            /*** WebView Hooks ***/

            /* frameworks/base/core/java/android/webkit/WebViewClient.java */
            /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
            var WebViewClient = Java.use("android.webkit.WebViewClient");

            WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] WebViewClient onReceivedSslError invoke`);
                //执行proceed方法
                sslErrorHandler.proceed();
                return;
            };

            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c, d) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] WebViewClient onReceivedError invoked`);
                return;
            };

            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function () {
                HookBox.tools.log(null, 0, `[SSLUnpinning] WebViewClient onReceivedError invoked`);
                return;
            };

            /*** JSSE Hooks ***/

            /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
            /* public final TrustManager[] getTrustManager() */
            /* TrustManagerFactory.getTrustManagers maybe cause X509TrustManagerExtensions error  */
            // var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            // TrustManagerFactory.getTrustManagers.implementation = function(){
            //     HookBox.tools.log(null, 0, `[SSLUnpinning] TrustManagerFactory getTrustManagers invoked");
            //     return TrustManagers;
            // }

            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setDefaultHostnameVerifier(HostnameVerifier) */
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] HttpsURLConnection.setDefaultHostnameVerifier invoked`);
                return null;
            };
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setSSLSocketFactory(SSLSocketFactory) */
            HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] HttpsURLConnection.setSSLSocketFactory invoked`);
                return null;
            };
            /* libcore/luni/src/main/java/javax/net/ssl/HttpsURLConnection.java */
            /* public void setHostnameVerifier(HostnameVerifier) */
            HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] HttpsURLConnection.setHostnameVerifier invoked`);
                return null;
            };

            /*** Xutils3.x hooks ***/
            //Implement a new HostnameVerifier
            var TrustHostnameVerifier;
            try {
                TrustHostnameVerifier = Java.registerClass({
                    name: 'org.wooyun.TrustHostnameVerifier',
                    implements: [HostnameVerifier],
                    method: {
                        verify: function (hostname, session) {
                            return true;
                        }
                    }
                });

            } catch (e) {
                //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
                HookBox.tools.log(null, 0, `[SSLUnpinning] registerClass from hostnameVerifier >>>>>>>> ` + e.message);
            }

            try {
                var RequestParams = Java.use('org.xutils.http.RequestParams');
                RequestParams.setSslSocketFactory.implementation = function (sslSocketFactory) {
                    sslSocketFactory = EmptySSLFactory;
                    return null;
                }

                RequestParams.setHostnameVerifier.implementation = function (hostnameVerifier) {
                    hostnameVerifier = TrustHostnameVerifier.$new();
                    return null;
                }

            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] Xutils hooks not Found`);
            }

            /*** httpclientandroidlib Hooks ***/
            try {
                var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function () {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] httpclientandroidlib Hooks`);
                    return null;
                }
            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] httpclientandroidlib Hooks not found`);
            }

            /***
        android 7.0+ network_security_config TrustManagerImpl hook
        apache httpclient partly
        ***/
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            // try {
            //     var Arrays = Java.use("java.util.Arrays");
            //     //apache http client pinning maybe baypass
            //     //https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#471
            //     TrustManagerImpl.checkTrusted.implementation = function (chain, authType, session, parameters, authType) {
            //         HookBox.tools.log(null, 0, `[SSLUnpinning] TrustManagerImpl checkTrusted called");
            //         //Generics currently result in java.lang.Object
            //         return Arrays.asList(chain);
            //     }
            //
            // } catch (e) {
            //     HookBox.tools.log(null, 0, `[SSLUnpinning] TrustManagerImpl checkTrusted nout found");
            // }

            try {
                // Android 7+ TrustManagerImpl
                TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] TrustManagerImpl verifyChain called`);
                    // Skip all the logic and just return the chain again :P
                    //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                    return untrustedChain;
                }
            } catch (e) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] TrustManagerImpl verifyChain nout found below 7.0`);
            }
            // OpenSSLSocketImpl
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] OpenSSLSocketImpl.verifyCertificateChain`);
                }

                HookBox.tools.log(null, 0, `[SSLUnpinning] OpenSSLSocketImpl pinning`)
            } catch (err) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] OpenSSLSocketImpl pinner not found`);
            }
            // Trustkit
            try {
                var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] Trustkit.verify1: ` + str);
                    return true;
                };
                Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] Trustkit.verify2: ` + str);
                    return true;
                };

                HookBox.tools.log(null, 0, `[SSLUnpinning] Trustkit pinning`)
            } catch (err) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] Trustkit pinner not found`)
            }

            try {
                //cronet pinner hook
                //weibo don't invoke

                var netBuilder = Java.use("org.chromium.net.CronetEngine$Builder");

                //https://developer.android.com/guide/topics/connectivity/cronet/reference/org/chromium/net/CronetEngine.Builder.html#enablePublicKeyPinningBypassForLocalTrustAnchors(boolean)
                netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function (arg) {

                    //weibo not invoke
                    // HookBox.tools.log(null, 0, `[SSLUnpinning] Enables or disables public key pinning bypass for local trust anchors = " + arg);
                    HookBox.tools.log(null, 0, `[SSLUnpinning] Enables or disables public key pinning bypass for local trust anchors = ` + arg);
                    //true to enable the bypass, false to disable.
                    var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return ret;
                };

                netBuilder.addPublicKeyPins.implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                    HookBox.tools.log(null, 0, `[SSLUnpinning] cronet addPublicKeyPins hostName = ${hostName}`);
                    //var ret = netBuilder.addPublicKeyPins.call(this,hostName, pinsSha256,includeSubdomains, expirationDate);
                    //this 是调用 addPublicKeyPins 前的对象吗? Yes,CronetEngine.Builder
                    return this;
                };

            } catch (err) {
                HookBox.tools.log(null, 0, `[SSLUnpinning] [-] Cronet pinner not found`)
            }

        }
    },
    start: (func, delay) => {
        let container = null
        if (delay) {
            container = setTimeout
        } else {
            container = setImmediate
        }

        container(() => { Java.perform(func) }, delay)
    }

}



HookBox.start(
    () => {
        // 在这里写你的 frida 代码， 不需要使用  Java.perform 包裹， 因为内部已经做好了
        HookBox.tools.hookClickEvent()

    },

    // 这里是你代码延迟运行的时间，当然你也可以不填
    // 6000
)


