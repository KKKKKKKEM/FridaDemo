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
                            if (string && string.toString().toLowerCase().indexOf(element) >= 0) { HookBox.tools.prettyPrint("[NewStringUTF]", 2, `string: ${string.toString()}`) }

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
                                HookBox.tools.prettyPrint("[GetStringUTFChars]", 2, `string: ${bytes.toString()}`)
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
                                        HookBox.tools.prettyPrint(
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

                                    HookBox.tools.prettyPrint(
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
                        HookBox.tools.prettyPrint("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
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
                        HookBox.tools.prettyPrint("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
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
                        HookBox.tools.prettyPrint("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
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
                        HookBox.tools.prettyPrint("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
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
                        HookBox.tools.prettyPrint("[JsonObject.put]", 1, `key: ${key}`, `value: ${value}`)
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
                        HookBox.tools.prettyPrint("[HashMap.put]", 1, `key: ${key}`, `value: ${value}`)
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

                        HookBox.tools.prettyPrint("[String.getBytes]", 1, `target: ${element}`, `string: ${string}`)
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
                        HookBox.tools.prettyPrint("[StringBuilder.toString]", 1, `string: ${string}`)
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
                        HookBox.tools.prettyPrint("[StringBuilder.append]", 1, `string: ${x}`)
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

                            HookBox.tools.prettyPrint("[set_custom_verify]", 0, `address: ${set_custom_verify}`)
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
                        HookBox.tools.prettyPrint("[switch loader]", 0, `target: ${exprs}`, `loader: ${this.loader.toString()}`)

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
        prettyPrint: function (tag, withstack, ...msg) {
            tag = tag || ""
            withstack = withstack || 0

            let msgString = `=========== ${tag} ===========\n`

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
        HookBox.Native.getStringUTFChars("8404")

    },

    // 这里是你代码延迟运行的时间，当然你也可以不填
    // 6000
)


