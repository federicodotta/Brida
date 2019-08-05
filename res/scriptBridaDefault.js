'use strict';

// 1 - FRIDA EXPORTS

rpc.exports = {
	
	// BE CAREFUL: Do not use uppercase characters in exported function name (automatically converted lowercase by Pyro)
	
	exportedfunction: function() {
	
		// Do stuff...	
		// This functions can be called from custom plugins or from Brida "Execute method" dedicated tab

	},
	
	// Function executed when executed Brida contextual menu option 1.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom1: function(message) {
		return "6566";
	},
	
	// Function executed when executed Brida contextual menu option 2.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom2: function(message) {
		return "6768";
	},
	
	// Function executed when executed Brida contextual menu option 3.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom3: function(message) {
		return "6768";
	},
	
	// Function executed when executed Brida contextual menu option 4.
	// Input is passed from Brida encoded in ASCII HEX and must be returned in ASCII HEX (because Brida will decode the output
	// from ASCII HEX). Use auxiliary functions for the conversions.
	contextcustom4: function(message) {
		return "6768";
	},

	// Generic Android hook that could be enabled from GUI
	customandroidhook1: function() {
	},

	// Generic Android hook that could be enabled from GUI
	customandroidhook2: function() {
	},

	// Generic Android hook that could be enabled from GUI
	customandroidhook3: function() {
	},

	// Generic iOS hook that could be enabled from GUI
	customioshook1: function() {
	},

	// Generic iOS hook that could be enabled from GUI
	customioshook2: function() {
	},

	// Generic iOS hook that could be enabled from GUI
	customioshook3: function() {
	},

	// Generic OS (not Android or iOS) hook that could be enabled from GUI
	customgenenrichook1: function() {
	},

	// Generic OS (not Android or iOS) hook that could be enabled from GUI
	customgenenrichook2: function() {
	},

	// Generic OS (not Android or iOS) hook that could be enabled from GUI
	customgenenrichook3: function() {
	},

	// **** BE CAREFULL ****
	// Do not remove these functions. They are used by Brida plugin in the "Hooks and functions" tab!
	// *********************	

	androidpinningwithca1: function() {

		Java.perform(function () {

		    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
		    var FileInputStream = Java.use("java.io.FileInputStream");
		    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
		    var X509Certificate = Java.use("java.security.cert.X509Certificate");
		    var KeyStore = Java.use("java.security.KeyStore");
		    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
		    var SSLContext = Java.use("javax.net.ssl.SSLContext");

		    // Load CAs from an InputStream
		    console.log("[+] Loading our CA...")
		    var cf = CertificateFactory.getInstance("X.509");
		    
		    try {
		    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
		    }
		    catch(err) {
		    	console.log("[o] " + err);
		    }
		    
		    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
		  	var ca = cf.generateCertificate(bufferedInputStream);
		    bufferedInputStream.close();

			var certInfo = Java.cast(ca, X509Certificate);
		    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

		    // Create a KeyStore containing our trusted CAs
		    console.log("[+] Creating a KeyStore for our CA...");
		    var keyStoreType = KeyStore.getDefaultType();
		    var keyStore = KeyStore.getInstance(keyStoreType);
		    keyStore.load(null, null);
		    keyStore.setCertificateEntry("ca", ca);
		    
		    // Create a TrustManager that trusts the CAs in our KeyStore
		    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
		    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
		    tmf.init(keyStore);
		    console.log("[+] Our TrustManager is ready...");

		    console.log("[+] Hijacking SSLContext methods now...")
		    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

		   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
		   		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
		   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
		   		console.log("[+] SSLContext initialized with our custom TrustManager!");
		   	}

			auxiliary_android_pinning_hooks();

		});
	},

	androidpinningwithoutca1: function() {

		Java.perform(function () {

		    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
		    var SSLContext = Java.use('javax.net.ssl.SSLContext');

		    // TrustManager (Android < 7)
		    var TrustManager = Java.registerClass({
		        // Implement a custom TrustManager
		        name: 'com.sensepost.test.TrustManager',
		        implements: [X509TrustManager],
		        methods: {
		            checkClientTrusted: function (chain, authType) {},
		            checkServerTrusted: function (chain, authType) {},
		            getAcceptedIssuers: function () {return []; }
		        }
		    });

		    // Prepare the TrustManager array to pass to SSLContext.init()
		    var TrustManagers = [TrustManager.$new()];
		    // Get a handle on the init() on the SSLContext class
		    var SSLContext_init = SSLContext.init.overload(
		        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
		    try {
		        // Override the init method, specifying the custom TrustManager
		        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
		            console.log('[+] Intercepted Trustmanager (Android < 7) request');
		            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
		        };

		        console.log('[+] Setup custom TrustManager (Android < 7)');
		    } catch (err) {
		        console.log('[-] TrustManager (Android < 7) pinner not found');
		    }			

			auxiliary_android_pinning_hooks();

		});
	},

	androidrooting1: function() {

		Java.perform(function() {
		    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
		        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
		        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
		        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
		        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
		        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
		        "eu.chainfire.supersu.pro", "com.kingouser.com"
		    ];

		    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk"];

		    var RootProperties = {
		        "ro.build.selinux": "1",
		        "ro.debuggable": "0",
		        "service.adb.root": "0",
		        "ro.secure": "1"
		    };

		    var RootPropertiesKeys = [];

		    for (var k in RootProperties) RootPropertiesKeys.push(k);

		    var PackageManager = Java.use("android.app.ApplicationPackageManager");

		    var Runtime = Java.use('java.lang.Runtime');

		    var NativeFile = Java.use('java.io.File');

		    var String = Java.use('java.lang.String');

		    var SystemProperties = Java.use('android.os.SystemProperties');

		    var BufferedReader = Java.use('java.io.BufferedReader');

		    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

		    var StringBuffer = Java.use('java.lang.StringBuffer');

		    var loaded_classes = Java.enumerateLoadedClassesSync();

		    send("Loaded " + loaded_classes.length + " classes!");

		    var useKeyInfo = false;

		    var useProcessManager = false;

		    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

		    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
		        try {
		            //useProcessManager = true;
		            //var ProcessManager = Java.use('java.lang.ProcessManager');
		        } catch (err) {
		            send("ProcessManager Hook failed: " + err);
		        }
		    } else {
		        send("ProcessManager hook not loaded");
		    }

		    var KeyInfo = null;

		    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
		        try {
		            //useKeyInfo = true;
		            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
		        } catch (err) {
		            send("KeyInfo Hook failed: " + err);
		        }
		    } else {
		        send("KeyInfo hook not loaded");
		    }

		    PackageManager.getPackageInfo.implementation = function(pname, flags) {
		        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
		        if (shouldFakePackage) {
		            send("Bypass root check for package: " + pname);
		            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
		        }
		        return this.getPackageInfo.call(this, pname, flags);
		    };

		    NativeFile.exists.implementation = function() {
		        var name = NativeFile.getName.call(this);
		        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
		        if (shouldFakeReturn) {
		            send("Bypass return value for binary: " + name);
		            return false;
		        } else {
		            return this.exists.call(this);
		        }
		    };

		    var exec = Runtime.exec.overload('[Ljava.lang.String;');
		    var exec1 = Runtime.exec.overload('java.lang.String');
		    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
		    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
		    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
		    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

		    exec5.implementation = function(cmd, env, dir) {
		        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
		            var fakeCmd = "grep";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        if (cmd == "su") {
		            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        return exec5.call(this, cmd, env, dir);
		    };

		    exec4.implementation = function(cmdarr, env, file) {
		        for (var i = 0; i < cmdarr.length; i = i + 1) {
		            var tmp_cmd = cmdarr[i];
		            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
		                var fakeCmd = "grep";
		                send("Bypass " + cmdarr + " command");
		                return exec1.call(this, fakeCmd);
		            }

		            if (tmp_cmd == "su") {
		                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		                send("Bypass " + cmdarr + " command");
		                return exec1.call(this, fakeCmd);
		            }
		        }
		        return exec4.call(this, cmdarr, env, file);
		    };

		    exec3.implementation = function(cmdarr, envp) {
		        for (var i = 0; i < cmdarr.length; i = i + 1) {
		            var tmp_cmd = cmdarr[i];
		            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
		                var fakeCmd = "grep";
		                send("Bypass " + cmdarr + " command");
		                return exec1.call(this, fakeCmd);
		            }

		            if (tmp_cmd == "su") {
		                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		                send("Bypass " + cmdarr + " command");
		                return exec1.call(this, fakeCmd);
		            }
		        }
		        return exec3.call(this, cmdarr, envp);
		    };

		    exec2.implementation = function(cmd, env) {
		        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
		            var fakeCmd = "grep";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        if (cmd == "su") {
		            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        return exec2.call(this, cmd, env);
		    };

		    exec.implementation = function(cmd) {
		        for (var i = 0; i < cmd.length; i = i + 1) {
		            var tmp_cmd = cmd[i];
		            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
		                var fakeCmd = "grep";
		                send("Bypass " + cmd + " command");
		                return exec1.call(this, fakeCmd);
		            }

		            if (tmp_cmd == "su") {
		                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		                send("Bypass " + cmd + " command");
		                return exec1.call(this, fakeCmd);
		            }
		        }

		        return exec.call(this, cmd);
		    };

		    exec1.implementation = function(cmd) {
		        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
		            var fakeCmd = "grep";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        if (cmd == "su") {
		            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
		            send("Bypass " + cmd + " command");
		            return exec1.call(this, fakeCmd);
		        }
		        return exec1.call(this, cmd);
		    };

		    String.contains.implementation = function(name) {
		        if (name == "test-keys") {
		            send("Bypass test-keys check");
		            return false;
		        }
		        return this.contains.call(this, name);
		    };

		    var get = SystemProperties.get.overload('java.lang.String');

		    get.implementation = function(name) {
		        if (RootPropertiesKeys.indexOf(name) != -1) {
		            send("Bypass " + name);
		            return RootProperties[name];
		        }
		        return this.get.call(this, name);
		    };

		    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
		        onEnter: function(args) {
		            var path = Memory.readCString(args[0]);
		            path = path.split("/");
		            var executable = path[path.length - 1];
		            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
		            if (shouldFakeReturn) {
		                Memory.writeUtf8String(args[0], "/notexists");
		                send("Bypass native fopen");
		            }
		        },
		        onLeave: function(retval) {

		        }
		    });

		    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
		        onEnter: function(args) {
		            var cmd = Memory.readCString(args[0]);
		            send("SYSTEM CMD: " + cmd);
		            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
		                send("Bypass native system: " + cmd);
		                Memory.writeUtf8String(args[0], "grep");
		            }
		            if (cmd == "su") {
		                send("Bypass native system: " + cmd);
		                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
		            }
		        },
		        onLeave: function(retval) {

		        }
		    });

		    BufferedReader.readLine.implementation = function() {
		        var text = this.readLine.call(this);
		        if (text === null) {
		            // just pass , i know it's ugly as hell but test != null won't work :(
		        } else {
		            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
		            if (shouldFakeRead) {
		                send("Bypass build.prop file read");
		                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
		            }
		        }
		        return text;
		    };

		    var executeCommand = ProcessBuilder.command.overload('java.util.List');

		    ProcessBuilder.start.implementation = function() {
		        var cmd = this.command.call(this);
		        var shouldModifyCommand = false;
		        for (var i = 0; i < cmd.size(); i = i + 1) {
		            var tmp_cmd = cmd.get(i).toString();
		            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
		                shouldModifyCommand = true;
		            }
		        }
		        if (shouldModifyCommand) {
		            send("Bypass ProcessBuilder " + cmd);
		            this.command.call(this, ["grep"]);
		            return this.start.call(this);
		        }
		        if (cmd.indexOf("su") != -1) {
		            send("Bypass ProcessBuilder " + cmd);
		            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
		            return this.start.call(this);
		        }

		        return this.start.call(this);
		    };

		    if (useProcessManager) {
		        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
		        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

		        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
		            var fake_cmd = cmd;
		            for (var i = 0; i < cmd.length; i = i + 1) {
		                var tmp_cmd = cmd[i];
		                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
		                    var fake_cmd = ["grep"];
		                    send("Bypass " + cmdarr + " command");
		                }

		                if (tmp_cmd == "su") {
		                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
		                    send("Bypass " + cmdarr + " command");
		                }
		            }
		            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
		        };

		        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
		            var fake_cmd = cmd;
		            for (var i = 0; i < cmd.length; i = i + 1) {
		                var tmp_cmd = cmd[i];
		                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
		                    var fake_cmd = ["grep"];
		                    send("Bypass " + cmdarr + " command");
		                }

		                if (tmp_cmd == "su") {
		                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
		                    send("Bypass " + cmdarr + " command");
		                }
		            }
		            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
		        };
		    }

		    if (useKeyInfo) {
		        KeyInfo.isInsideSecureHardware.implementation = function() {
		            send("Bypass isInsideSecureHardware");
		            return true;
		        }
		    }

		});

	},

	androiddumpkeystore1: function() {

		Java.perform(function () {
		    keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');

		    /* following function hooks to a Keystore.load(InputStream stream, char[] password) */
		    keyStoreLoadStream.implementation = function(stream, charArray) {

		        /* sometimes this happen, I have no idea why, tho... */
		        if (stream == null) {
		            /* just to avoid interfering with app's flow */
		            this.load(stream, charArray);
		            return;
		        }

		        /* read the buffer stream to a variable */
		        var hexString = readStreamToHex (stream);

		        console.log("[+] Hooked keystore")
		        console.log("  [+] Cert Type: " + this.getType());		        
		        console.log("  [+] Password: " + charArray);
		        console.log("  [+] Keystore content (HEX encoded):");
		        console.log(hexString);
		        console.log("");

		        /* call the original implementation of 'load' */
		        this.load(stream, charArray);

		        /* no need to return anything */
		    }
		});

		/* following function reads an InputStream and returns an ASCII char representation of it */
		function readStreamToHex (stream) {
		    var data = [];
		    var byteRead = stream.read();
		    while (byteRead != -1)
		    {
		        data.push( ('0' + (byteRead & 0xFF).toString(16)).slice(-2) );
		                /* <---------------- binary to hex ---------------> */
		        byteRead = stream.read();
		    }
		    stream.close();
		    return data.join('');
		}		

	},


	// **** BE CAREFULL ****
	// Do not remove these functions. They are used by Brida plugin in the "Analyze binary" tab!
	// *********************
	getallclasses: function() {
		var result = []
		if (ObjC.available) {
			for (var className in ObjC.classes) {
				if (ObjC.classes.hasOwnProperty(className)) {
					result.push(className);
				}
			}
		} else if(Java.available) {
			Java.perform(function() {
				Java.enumerateLoadedClasses({
					onMatch: function (className) {
						result.push(className);
					},
					onComplete: function() {
					}
				});
			});
		}
		return result;
	},

	getallmodules: function() {
		var results = {}
		var matches = Process.enumerateModules( {
			onMatch: function (module) {
				results[module['name']] = module['base'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getmoduleimports: function(importname) {
		var results = {}
		var matches = Module.enumerateImports(importname, {
			onMatch: function (module) {
				results[module['type'] + ": " + module['name']] = module['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getmoduleexports: function(exportname) {
		var results = {}
		var matches = Module.enumerateExports(exportname, {
			onMatch: function (module) {
				results[module['type'] + ": " + module['name']] = module['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	getclassmethods: function(classname) {
		var results = {}
		if (ObjC.available) {
			var resolver = new ApiResolver("objc");
			var matches = resolver.enumerateMatches("*[" + classname + " *]", {
				onMatch: function (match) {
					results[match['name']] = match['address'];
				},
				onComplete: function () {
				}
			});
		} else if(Java.available) {
			Java.perform(function() {
				results = getJavaMethodArgumentTypes(classname);
			});
		}
		return results;
	},

	findobjcmethods: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("objc");
		var matches = resolver.enumerateMatches("*[*" + searchstring + "* *]", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("*[* *" + searchstring + "*]", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	findimports: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("module");
		var matches = resolver.enumerateMatches("imports:*" + searchstring + "*!*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("imports:*!*" + searchstring + "*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	findexports: function(searchstring) {
		var results = {}
		var resolver = new ApiResolver("module");
		var matches = resolver.enumerateMatches("exports:*" + searchstring + "*!*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		matches = resolver.enumerateMatches("exports:*!*" + searchstring + "*", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
		return results;
	},

	detachall: function() {
		Interceptor.detachAll();
	},

	// generic trace
	trace: function (pattern,type,backtrace) {
		// SINGLE EXPORT (ALL EXPORT OF A MODULE CAN BE A MESS AND CRASH THE APP)
		if(type == "export") {
			var res = new ApiResolver("module");
			pattern = "exports:" + pattern;
			var matches = res.enumerateMatchesSync(pattern);
			var targets = uniqBy(matches, JSON.stringify);
			targets.forEach(function(target) {
				traceModule(target.address, target.name, backtrace);
			});
		//OBJC
		} else if(type.startsWith("objc")) {
			if (ObjC.available) {
				var res;
				if(type === "objc_class") {
					res = new ApiResolver("objc");
					pattern = "*[" + pattern + " *]";
				} else if(type === "objc_method") {
					res = new ApiResolver("objc");
				}
				var matches = res.enumerateMatchesSync(pattern);
				var targets = uniqBy(matches, JSON.stringify);
				targets.forEach(function(target) {
					traceObjC(target.address, target.name,backtrace);
				});
			}
		// ANDROID
		} else if(type.startsWith("java")) {
			if(Java.available) {
				Java.perform(function() {
					if(type === "java_class") {
						var methodsDictionary = getJavaMethodArgumentTypes(pattern);
						var targets = Object.keys(methodsDictionary);
						targets.forEach(function(targetMethod) {
							traceJavaMethod(targetMethod,backtrace);
						});
					} else {
						traceJavaMethod(pattern,backtrace);
					}					
				});
			}
		}
	},

	changereturnvalue: function(pattern, type, typeret, newret)	{
		if(ObjC.available) {
			changeReturnValueIOS(pattern, type, typeret, newret);
		} else if(Java.available) {
			Java.perform(function() {
				changeReturnValueAndroid(pattern, type, typeret, newret);
			});
		} else {
			changeReturnValueGeneric(pattern, type, typeret, newret);
		}
	},

	getplatform: function() {

		if(Java.available) {
			return 0;
		} else if(ObjC.available){
			return 1;
		} else {
			return 2;
		}

	}	
	
}

// 2 - AUXILIARY FUNCTIONS

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a ASCII string to a hex string
function stringToHex(str) {
    return str.split("").map(function(c) {
        return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join("");
}

// Convert a hex string to a ASCII string
function hexToString(hexStr) {
    var hex = hexStr.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

// Convert a byte array to a hex string
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

// remove duplicates from array
function uniqBy(array, key) {
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

/*
This method is used to get Java methods with arguments in bytecode syntex. By simply calling the getDeclaredMethods of a Java Class object
and then calling toString on each Method object we do not get types in bytecode format. For example we get 'byte[]' instead of
'[B'. This function uses overload object of frida to get types in correct bytecode form.
*/
function getJavaMethodArgumentTypes(classname) {	
	if(Java.available) {	
		var results = {};
		Java.perform(function() {
			var hook = Java.use(classname);
			var res = hook.class.getDeclaredMethods();			
			res.forEach(function(s) { 
				//console.log("s " + s);
				var targetClassMethod = parseJavaMethod(s.toString());
				//console.log("targetClassMethod " + targetClassMethod);
				var delim = targetClassMethod.lastIndexOf(".");
				if (delim === -1) return;
				var targetClass = targetClassMethod.slice(0, delim)
				var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
				//console.log("targetClass " + targetClass);
				//console.log("targetMethod " + targetMethod);
				var hookClass = Java.use(targetClass);
				var classMethodOverloads = hookClass[targetMethod].overloads;
				classMethodOverloads.forEach(function(cmo) {
					// overload.argumentTypes is an array of objects representing the arguments. In the "className" field of each object there 
					// is the bytecode form of the class of the current argument 
					var argumentTypes = cmo.argumentTypes;
					var argumentTypesArray = []
					argumentTypes.forEach(function(cmo) {
						argumentTypesArray.push(cmo.className);
					});
					var argumentTypesString = argumentTypesArray.toString();
					// overload.returnType.className contain the bytecode form of the class of the return value
					var currentReturnType = cmo.returnType.className;
					var newPattern = currentReturnType + " " + targetClassMethod + "(" + argumentTypesString + ")";
					//console.log(newPattern);
					results[newPattern] = 0;
				});
				hookClass.$dispose;
			});				
			hook.$dispose;			
		});
		return results;
	}
}

function changeReturnValueIOS(pattern, type, typeret, newret) {
	var res;
	if(type === "objc_method") {
		res = new ApiResolver("objc");
	} else {
		// SINGLE EXPORT
		res = new ApiResolver("module");
		pattern = "exports:" + pattern;
	}
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);
	targets.forEach(function(target) {
		Interceptor.attach(target.address, {
			onEnter: function(args) {
			},
			onLeave: function(retval) {
				if(typeret === "String") {
					var a1 = ObjC.classes.NSString.stringWithString_(newret);
					try {
						console.log("*** " + pattern + " Replacing " + ObjC.Object(retval) + " with " + a1);						
					} catch(err) {
						console.log("*** " + pattern + " Replacing " + retval + " with " + a1);
					}
					retval.replace(a1);
				} else if(typeret === "Ptr") {
					console.log("*** " + pattern + " Replacing " + ptr(retval) + " with " + ptr(newret));
					retval.replace(ptr(newret));
				} else if(typeret === "Boolean") {
					if(newret === "true") {
						var toRet = 1;
					} else {
						var toRet = 0;
					}
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				} else {
					console.log("*** " + pattern + " Replacing " + retval + " with " + newret);
					retval.replace(newret);
				}
			}
		});
	});	
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

function changeReturnValueGeneric(pattern, type, typeret, newret) {
	var res = new ApiResolver("module");
	pattern = "exports:" + pattern;
	var matches = res.enumerateMatchesSync(pattern);
	var targets = uniqBy(matches, JSON.stringify);
	targets.forEach(function(target) {
		Interceptor.attach(target.address, {
			onEnter: function(args) {
			},
			onLeave: function(retval) {
				if(typeret === "Ptr") {
					console.log("*** " + pattern + " Replacing " + ptr(retval) + " with " + ptr(newret));
					retval.replace(ptr(newret));
				} else if(typeret === "Boolean") {
					if(newret === "true") {
						var toRet = 1;
					} else {
						var toRet = 0;
					}
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				} else {
					console.log("*** " + pattern + " Replacing " + retval + " with " + newret);
					retval.replace(newret);
				}
			}
		});
	});	
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

function changeReturnValueAndroid(pattern, type, typeret, newret) {
	if(type === "java_method") {
		var targetClassMethod = parseJavaMethod(pattern);
		//console.log(targetClassMethod);
		var argsTargetClassMethod = getJavaMethodArguments(pattern);
		//console.log(argsTargetClassMethod);
		var delim = targetClassMethod.lastIndexOf(".");
		if (delim === -1) return;
		var targetClass = targetClassMethod.slice(0, delim)
		var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
		//console.log(targetClass);
		//console.log(targetMethod);
		var hook = Java.use(targetClass);
		hook[targetMethod].overload.apply(this,argsTargetClassMethod).implementation = function() {
			var retval = this[targetMethod].apply(this, arguments);
			var toRet = newret;
			if(typeret === "String") {
				var stringClass = Java.use("java.lang.String");
				toRet = stringClass.$new(newret);
			} else if(typeret === "Ptr") {
				toRet = ptr(newret);
			} else if(typeret === "Boolean") {
				if(newret === "true") {
					toRet = true;
				} else {
					toRet = false;
				}
			}			
			console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
			return toRet;
		}
	// SINGLE EXPORT
	} else {
		var res = new ApiResolver("module");
		var pattern = "exports:" + pattern;
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			Interceptor.attach(target.address, {
				onEnter: function(args) {
				},
				onLeave: function(retval) {
					var toRet = newret;
					if(typeret === "String") {
						var stringClass = Java.use("java.lang.String");
						var toRet = stringClass.$new(newret);
					} else if(typeret === "ptr") {
						toRet = ptr(newret);
					} else if(typeret === "Boolean") {
						if(newret === "true") {
							var toRet = 1;
						} else {
							var toRet = 0;
						}
						console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
						retval.replace(toRet);
					}				
					console.log("*** " + pattern + " Replacing " + retval + " with " + toRet);
					retval.replace(toRet);
				}
			});
		});	
	}
	console.log("*** Replacing return value of " + pattern + " with " + newret);
}

// trace ObjC methods
function traceObjC(impl, name, backtrace) {
	console.log("*** Tracing " + name);
	Interceptor.attach(impl, {
		onEnter: function(args) {
			console.log("*** entered " + name);
			console.log("Caller: " + DebugSymbol.fromAddress(this.returnAddress));
			// print args
			if (name.indexOf(":") !== -1) {
				console.log("Parameters:");
				var par = name.split(":");
				par[0] = par[0].split(" ")[1];
				for (var i = 0; i < par.length - 1; i++) {
					printArg(par[i] + ": ", args[i + 2]);
				}
			}
			if(backtrace === "true") {
				console.log("Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n\t"));
			}			
		},
		onLeave: function(retval) {
			console.log("*** exiting " + name);
			console.log("Return value:");
			printArg("retval: ", retval);			
		}
	});
}

/*
INPUT LIKE: public boolean a.b.functionName(java.lang.String)
OUTPUT LIKE: a.b.functionName
*/
function parseJavaMethod(method) {
	var parSplit = method.split("(");
	var spaceSplit = parSplit[0].split(" ");
	return spaceSplit[spaceSplit.length - 1];
}

//INPUT LIKE: public boolean a.b.functionName(java.lang.String,java.lang.String)
//OUTPUT LIKE: ["java.lang.String","java.lang.String"]
function getJavaMethodArguments(method) {
	var m = method.match(/.*\((.*)\).*/);
	if(m[1] !== "") {
		return m[1].split(",");
	} else {
		return [];
	}
}

// trace a specific Java Method
function traceJavaMethod(pattern,backtrace) {
	var targetClassMethod = parseJavaMethod(pattern);
	//console.log(targetClassMethod);
	var argsTargetClassMethod = getJavaMethodArguments(pattern);
	//console.log(argsTargetClassMethod);
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;
	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
	var hook = Java.use(targetClass);
	//var overloadCount = hook[targetMethod].overloads.length;
	console.log("*** Tracing " + pattern);
	hook[targetMethod].overload.apply(this,argsTargetClassMethod).implementation = function() {		
		console.log("*** entered " + targetClassMethod);
		// print args
		if (arguments.length) console.log("Parameters:");
		for (var j = 0; j < arguments.length; j++) {
			console.log("\targ[" + j + "]: " + arguments[j]);
		}
		// print backtrace
		if(backtrace === "true") {
			Java.perform(function() {
				var threadClass = Java.use("java.lang.Thread");
				var currentThread = threadClass.currentThread();
				var currentStackTrace = currentThread.getStackTrace();
				console.log("Backtrace:");
				currentStackTrace.forEach(function(st) {
					console.log("\t" + st.toString());
				});
			});
		}
		// print retval
		var retval = this[targetMethod].apply(this, arguments);		
		console.log("*** exiting " + targetClassMethod);
		console.log("Return value:");
		console.log("\tretval: " + retval);
		return retval;
	}
}

// trace Module functions
function traceModule(impl, name, backtrace) {
	console.log("*** Tracing " + name);
	Interceptor.attach(impl, {
		onEnter: function(args) {
			console.log("*** entered " + name);
			if(backtrace === "true") {
				console.log("Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"));
			}			
		},
		onLeave: function(retval) {
			console.log("*** exiting " + name);
			console.log("Return value:");
			if(ObjC.available) {
				printArg("retval: ", retval);			
			} else {
				console.log("\tretval: ", retval);
			}			
		}
	});
}

// print helper
function printArg(desc, arg) {
	if(arg != 0x0) {
		try {
			var objectArg = ObjC.Object(arg);				
			console.log("\t(" + objectArg.$className + ") " + desc + objectArg.toString());
		} catch(err2) {
			console.log("\t" + desc + arg);
		}
	} else {
		console.log("\t" + desc + "0x0");
	}
}

function auxiliary_android_pinning_hooks() {

    // okhttp3 (double bypass)
    try {
        var okhttp3_Activity = Java.use('okhttp3.CertificatePinner');
        okhttp3_Activity.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
            console.log('[+] Intercepted OkHTTP3 {1}: ' + str);
            return true;
        };
        // This method of CertificatePinner.check could be found in some old Android app
        okhttp3_Activity.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str) {
            console.log('[+] Intercepted OkHTTP3 {2}: ' + str);
            return true;
        };

        console.log('[+] Setup OkHTTP3 pinning')
    } catch (err) {
        console.log('[-] OkHTTP3 pinner not found')
    }

    // Trustkit (triple bypass)
    try {
        var trustkit_Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        trustkit_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
            console.log('[+] Intercepted Trustkit {1}: ' + str);
            return true;
        };
        trustkit_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
            console.log('[+] Intercepted Trustkit {2}: ' + str);
            return true;
        };
        var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
            console.log('[+] Intercepted Trustkit {3}');
        }

        console.log('[+] Setup Trustkit pinning')
    } catch (err) {
        console.log('[-] Trustkit pinner not found')
    }

    // TrustManagerImpl (Android > 7)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Intercepted TrustManagerImpl (Android > 7): ' + host);
            return untrustedChain;
        }

        console.log('[+] Setup TrustManagerImpl (Android > 7) pinning')
    } catch (err) {
        console.log('[-] TrustManagerImpl (Android > 7) pinner not found')
    }   

    // Appcelerator Titanium
    try {
        var appcelerator_PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
            console.log('[+] Intercepted Appcelerator');
        }

        console.log('[+] Setup Appcelerator pinning')
    } catch (err) {
        console.log('[-] Appcelerator pinner not found')
    }

    // OpenSSLSocketImpl
    try {
        var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
            console.log('[+] Intercepted OpenSSLSocketImpl');
        }

        console.log('[+] Setup OpenSSLSocketImpl pinning')
    } catch (err) {
        console.log('[-] OpenSSLSocketImpl pinner not found');

    }

    // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/)
    try {
        var phonegap_Activity = Java.use('nl.xservices.plugins.sslCertificateChecker');
        phonegap_Activity.execute.overload('java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext').implementation = function (str) {
            console.log('[+] Intercepted PhoneGap sslCertificateChecker: ' + str);
            return true;
        };

        console.log('[+] Setup PhoneGap sslCertificateChecker pinning')
    } catch (err) {
        console.log('[-] PhoneGap sslCertificateChecker pinner not found')
    }

    // IBM MobileFirst pinTrustedCertificatePublicKey
    try {
        var WLClient = Java.use('com.worklight.wlclient.api.WLClient');
        // if above does not works try with this
        //var WLClient = Java.use('com.worklight.wlclient.api.WLClient.getInstance()');
        WLClient.pinTrustedCertificatePublicKey.implementation = function (cert) {
            console.log('[+] Intercepted IBM MobileFirst pinTrustedCertificatePublicKey');
            return;
        }

        console.log('[+] Setup IBM MobileFirst pinTrustedCertificatePublicKey pinning')
    } catch (err) {
        console.log('[-] IBM MobileFirst pinTrustedCertificatePublicKey pinner not found')
    }
    
    // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
    try {
        var worklight_Activity = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
        worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (str) {
            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + str);
            return;
        };
        worklight_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str) {
            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + str);
            return;
        };
        worklight_Activity.verify.overload('java.lang.String', 'java.util.List', 'java.util.List').implementation = function (str) {
            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + str);
            return;
        };
        worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str) {
            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + str);
            return true;
        };

        console.log('[+] Setup IBM WorkLight HostNameVerifierWithCertificatePinning pinning')
    } catch (err) {
        console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning pinner not found')
    }

}

// 3 - FRIDA HOOKS (if needed)
//if(ObjC.available) {
//if(Java.available) {
	
	// Insert here Frida interception methods, if needed 

//}