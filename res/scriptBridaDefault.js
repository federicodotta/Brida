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

	ios10pinning: function() {

		var tls_helper_create_peer_trust = new NativeFunction(
			Module.findExportByName(null, "tls_helper_create_peer_trust"),
			'int', ['pointer', 'bool', 'pointer']
			);

		var errSecSuccess = 0;

		Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
		    return errSecSuccess;
		}, 'int', ['pointer', 'bool', 'pointer']));
		console.log("SSL certificate validation bypass active");

	},

	ios11pinning: function() {

		/* OSStatus nw_tls_create_peer_trust(tls_handshake_t hdsk, bool server, SecTrustRef *trustRef); */
		var tls_helper_create_peer_trust = new NativeFunction(
			Module.findExportByName(null, "nw_tls_create_peer_trust"),
			'int', ['pointer', 'bool', 'pointer']
			);

		var errSecSuccess = 0;

		Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
		    return errSecSuccess;
		}, 'int', ['pointer', 'bool', 'pointer']));
		console.log("SSL certificate validation bypass active");

	},

	ios12pinning: function() {

		var SSL_VERIFY_NONE = 0;
		var ssl_ctx_set_custom_verify;
		var ssl_get_psk_identity;

		/* Create SSL_CTX_set_custom_verify NativeFunction 
		*  Function signature https://github.com/google/boringssl/blob/7540cc2ec0a5c29306ed852483f833c61eddf133/include/openssl/ssl.h#L2294
		*/
		ssl_ctx_set_custom_verify = new NativeFunction(
			Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify"),
			'void', ['pointer', 'int', 'pointer']
		);

		/* Create SSL_get_psk_identity NativeFunction 
		* Function signature https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get_psk_identity
		*/
		ssl_get_psk_identity = new NativeFunction(
			Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"),
			'pointer', ['pointer']
		);

		/** Custom callback passed to SSL_CTX_set_custom_verify */
		function custom_verify_callback_that_does_not_validate(ssl, out_alert){
			return SSL_VERIFY_NONE;
		}

		/** Wrap callback in NativeCallback for frida */
		var ssl_verify_result_t = new NativeCallback(function (ssl, out_alert){
			custom_verify_callback_that_does_not_validate(ssl, out_alert);
		},'int',['pointer','pointer']);

		Interceptor.replace(ssl_ctx_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
			//  |callback| performs the certificate verification. Replace this with our custom callback
			ssl_ctx_set_custom_verify(ssl, mode, ssl_verify_result_t);
		}, 'void', ['pointer', 'int', 'pointer']));

		Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
			return "notarealPSKidentity";
		}, 'pointer', ['pointer']));
			
		console.log("[+] Bypass successfully loaded ");		

	},

	iosbypasstouchid: function() {

		var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
	    Interceptor.attach(hook.implementation, {
	        onEnter: function(args) {
	            send("Hooking Touch Id..")
	            var block = new ObjC.Block(args[4]);
	            const appCallback = block.implementation;
	            block.implementation = function (error, value)  {
	                const result = appCallback(1, null);
	                return result;
	            };
	        },
	    });

	}, 

	iosjailbreak: function() {

		const paths = [ '/Applications/Cydia.app',
		'/Applications/FakeCarrier.app',
		'/Applications/Icy.app',
		'/Applications/IntelliScreen.app',
		'/Applications/MxTube.app',
		'/Applications/RockApp.app',
		'/Applications/SBSettings.app',
		'/Applications/WinterBoard.app',
		'/Applications/blackra1n.app',
		'/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist',
		'/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
		'/Library/MobileSubstrate/MobileSubstrate.dylib',
		'/System/Library/LaunchDaemons/com.ikey.bbot.plist',
		'/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist',
		'/bin/bash',
		'/bin/sh',
		'/etc/apt',
		'/etc/ssh/sshd_config',
		'/private/var/lib/apt',
		'/private/var/lib/cydia',
		'/private/var/mobile/Library/SBSettings/Themes',
		'/private/var/stash',
		'/private/var/tmp/cydia.log',
		'/usr/bin/sshd',
		'/usr/libexec/sftp-server',
		'/usr/libexec/ssh-keysign',
		'/usr/sbin/sshd',
		'/var/cache/apt',
		'/var/lib/apt',
		'/private/jailbreak.txt',
		'/var/lib/cydia' ];

		const subject = 'jailbreak'

		if(ObjC.available) {
		//function bypassJailbreak() {
		  /* eslint no-param-reassign: 0, camelcase: 0, prefer-destructuring: 0 */
		  Interceptor.attach(Module.findExportByName(null, 'open'), {
		    onEnter(args) {
		      if (!args[0])
		        return

		      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; }).join("\n\t\t");
		      //e => e.name)

		      //const path = Memory.readUtf8String(args[0])
		      const path = args[0].readUtf8String()

		      if (paths.indexOf(path) > -1) {

		        var newPath = "/QZQZ" + path.substring(5)
		        //console.log(newPath)

		        console.log("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
		        console.log("\tMethod: open");
		        console.log("\tPath: " + path);
		        console.log("\tTime: " + new Date().getTime());
		        console.log("\tBacktrace: " + backtrace);
		        console.log("*** END Jailbrek check detected")
		        
		        //args[0] = NULL
		        args[0].writeUtf8String(newPath)


		      }
		    }
		  })

		  const statHandler = {
		    onEnter(args) {
		      if (!args[0])
		        return

		      //const path = Memory.readUtf8String(args[0])
		      const path = args[0].readUtf8String()
		      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t");
		      // e => e.name

		      if (paths.indexOf(path) > -1) {    

		        var newPath = "/QZQZ" + path.substring(5)
		        
		        console.log("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
		        console.log("\tMethod: stat");
		        console.log("\tPath: " + path);
		        console.log("\tTime: " + new Date().getTime());
		        console.log("\tBacktrace: " + backtrace);
		        console.log("*** END Jailbrek check detected")

		        args[0].writeUtf8String(newPath)
		        //args[0] = NULL
		      }
		    }
		  }
		  Interceptor.attach(Module.findExportByName(null, 'stat'), statHandler)
		  Interceptor.attach(Module.findExportByName(null, 'stat64'), statHandler)

		  Interceptor.attach(Module.findExportByName(null, 'getenv'), {
		    onEnter(args) {
		      //const key = Memory.readUtf8String(args[0])
		      const key = args[0].readUtf8String()
		      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t");
		      // e => e.name

		      this.print_ret = false

		      if (key === 'DYLD_INSERT_LIBRARIES') {

		        this.print_ret = true

		        console.log("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
		        console.log("\tenv: DYLD_INSERT_LIBRARIES");
		        console.log("\tTime: " + new Date().getTime());
		        console.log("\tBacktrace: " + backtrace);
		        console.log("*** END Jailbrek check detected")

		        //args[0] = NULL

		      }
		    },
		    onLeave(retVal) {

		      if(this.print_ret == true) {
		        //send(retVal);
		        retVal.replace(ptr(0));
		      }
		    }
		  })

		  Interceptor.attach(Module.findExportByName(null, '_dyld_get_image_name'), {
		    onLeave(retVal) {
		      if (Memory.readUtf8String(retVal).indexOf('MobileSubstrate') > -1)
		        retVal.replace(ptr(0x00))
		    }
		  })

		  Interceptor.attach(Module.findExportByName(null, 'fork'), {
		    onLeave(retVal) {
		      retVal.replace(ptr(-1))
		      // todo: send
		    }
		  })

		  //const { UIApplication, NSURL, NSFileManager } = ObjC.classes
		  const UIApplication = ObjC.classes.UIApplication
		  const NSURL = ObjC.classes.NSURL
		  const NSFileManager = ObjC.classes.NSFileManager

		  const canOpenURL_publicURLsOnly_ = UIApplication['- _canOpenURL:publicURLsOnly:']
		  Interceptor.attach(canOpenURL_publicURLsOnly_.implementation, {
		    onEnter(args) {
		      if (args[2].isNull())
		        return

		      const url = ObjC.Object(args[2]).toString()
		      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t")
		      // e => e.name

		      if (/^cydia:\/\//i.exec(url)) {
		        args[2] = NSURL.URLWithString_('invalid://')
		        this.shouldOverride = true

		        console.log("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
		        console.log("\turl: " + url);
		        console.log("\tTime: " + new Date().getTime());
		        console.log("\tBacktrace: " + backtrace);
		        console.log("*** END Jailbrek check detected")

		        
		      }
		    },
		    onLeave(retVal) {
		      if (this.shouldOverride)
		        retVal.replace(ptr(0))
		    }
		  })

		  Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
		    onEnter(args) {
		      if (args[2].isNull())
		        return

		      const path = new ObjC.Object(args[2]).toString()
		      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).filter( function(e) { return e.name; } ).join("\n\t\t")
		      // e => e.name

		      if (paths.indexOf(path) > -1) {

		        console.log("*** Jailbrek check detected - trying to elude check (if it does not work, use backtrace to elude main function)");
		        console.log("\tpath: " + path);
		        console.log("\tTime: " + new Date().getTime());
		        console.log("\tBacktrace: " + backtrace);
		        console.log("*** END Jailbrek check detected")

		        this.shouldOverride = true
		      }
		    },
		    onLeave(retVal) {
		      if (this.shouldOverride)
		        retVal.replace(ptr('0x00'))
		    }
		  })
		}

	}, 

	iosdumpkeychain: function() {

		function constantLookup(v) {
		  if(v in kSecConstantReverse) {
		    return kSecConstantReverse[v];
		  } else {
		    return v;
		  }
		}

		function odas(raw) {
		  try {
		    const data = new ObjC.Object(raw)
		    return Memory.readUtf8String(data.bytes(), data.length())
		  } catch (_) {
		    try {
		      return raw.toString()
		    } catch (__) {
		      return ''
		    }
		  }
		}

		function decodeOd(item, flags) {
		  const constraints = item
		  const constraintEnumerator = constraints.keyEnumerator()

		  var constraintKey;

		  for (constraintKey = 0; constraintKey !== null; constraintEnumerator.nextObject()) {
		    switch (odas(constraintKey)) {
		      case 'cpo':
		        flags.push('kSecAccessControlUserPresence')
		        break

		      case 'cup':
		        flags.push('kSecAccessControlDevicePasscode')
		        break

		      case 'pkofn':
		        flags.push(constraints.objectForKey_('pkofn') === 1 ? 'Or' : 'And')
		        break

		      case 'cbio':
		        flags.push(constraints.objectForKey_('cbio').count() === 1
		          ? 'kSecAccessControlTouchIDAny'
		          : 'kSecAccessControlTouchIDCurrentSet')
		        break

		      default:
		        break
		    }
		  }
		}

		function decodeAcl(entry,SecAccessControlGetConstraints) {
		  // No access control? Move along.
		  if (!entry.containsKey_(kSecAttrAccessControl))
		    return []

		  const constraints = SecAccessControlGetConstraints(entry.objectForKey_(kSecAttrAccessControl))
		  if (constraints.isNull())
		    return []

		  const accessControls = ObjC.Object(constraints)
		  const flags = []
		  const enumerator = accessControls.keyEnumerator()

		  var key;

		  for (key = enumerator.nextObject(); key !== null; key = enumerator.nextObject()) {
		    const item = accessControls.objectForKey_(key)
		    switch (odas(key)) {
		      case 'dacl':
		        break
		      case 'osgn':
		        flags.push('PrivateKeyUsage')
		      case 'od':
		        decodeOd(item, flags)
		        break
		      case 'prp':
		        flags.push('ApplicationPassword')
		        break

		      default:
		        break
		    }
		  }
		  return flags
		}

		const kSecReturnAttributes = 'r_Attributes',
		  kSecReturnData = 'r_Data',
		  kSecReturnRef = 'r_Ref',
		  kSecMatchLimit = 'm_Limit',
		  kSecMatchLimitAll = 'm_LimitAll',
		  kSecClass = 'class',
		  kSecClassKey = 'keys',
		  kSecClassIdentity = 'idnt',
		  kSecClassCertificate = 'cert',
		  kSecClassGenericPassword = 'genp',
		  kSecClassInternetPassword = 'inet',
		  kSecAttrService = 'svce',
		  kSecAttrAccount = 'acct',
		  kSecAttrAccessGroup = 'agrp',
		  kSecAttrLabel = 'labl',
		  kSecAttrCreationDate = 'cdat',
		  kSecAttrAccessControl = 'accc',
		  kSecAttrGeneric = 'gena',
		  kSecAttrSynchronizable = 'sync',
		  kSecAttrModificationDate = 'mdat',
		  kSecAttrServer = 'srvr',
		  kSecAttrDescription = 'desc',
		  kSecAttrComment = 'icmt',
		  kSecAttrCreator = 'crtr',
		  kSecAttrType = 'type',
		  kSecAttrScriptCode = 'scrp',
		  kSecAttrAlias = 'alis',
		  kSecAttrIsInvisible = 'invi',
		  kSecAttrIsNegative = 'nega',
		  kSecAttrHasCustomIcon = 'cusi',
		  kSecProtectedDataItemAttr = 'prot',
		  kSecAttrAccessible = 'pdmn',
		  kSecAttrAccessibleWhenUnlocked = 'ak',
		  kSecAttrAccessibleAfterFirstUnlock = 'ck',
		  kSecAttrAccessibleAlways = 'dk',
		  kSecAttrAccessibleWhenUnlockedThisDeviceOnly = 'aku',
		  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = 'cku',
		  kSecAttrAccessibleAlwaysThisDeviceOnly = 'dku'

		const kSecConstantReverse = {
		  r_Attributes: 'kSecReturnAttributes',
		  r_Data: 'kSecReturnData',
		  r_Ref: 'kSecReturnRef',
		  m_Limit: 'kSecMatchLimit',
		  m_LimitAll: 'kSecMatchLimitAll',
		  class: 'kSecClass',
		  keys: 'kSecClassKey',
		  idnt: 'kSecClassIdentity',
		  cert: 'kSecClassCertificate',
		  genp: 'kSecClassGenericPassword',
		  inet: 'kSecClassInternetPassword',
		  svce: 'kSecAttrService',
		  acct: 'kSecAttrAccount',
		  agrp: 'kSecAttrAccessGroup',
		  labl: 'kSecAttrLabel',
		  srvr: 'kSecAttrServer',
		  cdat: 'kSecAttrCreationDate',
		  accc: 'kSecAttrAccessControl',
		  gena: 'kSecAttrGeneric',
		  sync: 'kSecAttrSynchronizable',
		  mdat: 'kSecAttrModificationDate',
		  desc: 'kSecAttrDescription',
		  icmt: 'kSecAttrComment',
		  crtr: 'kSecAttrCreator',
		  type: 'kSecAttrType',
		  scrp: 'kSecAttrScriptCode',
		  alis: 'kSecAttrAlias',
		  invi: 'kSecAttrIsInvisible',
		  nega: 'kSecAttrIsNegative',
		  cusi: 'kSecAttrHasCustomIcon',
		  prot: 'kSecProtectedDataItemAttr',
		  pdmn: 'kSecAttrAccessible',
		  ak: 'kSecAttrAccessibleWhenUnlocked',
		  ck: 'kSecAttrAccessibleAfterFirstUnlock',
		  dk: 'kSecAttrAccessibleAlways',
		  aku: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
		  cku: 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
		  dku: 'kSecAttrAccessibleAlwaysThisDeviceOnly'
		}

		const kSecClasses = [  kSecClassKey,kSecClassIdentity,kSecClassCertificate, kSecClassGenericPassword,kSecClassInternetPassword ];



		const NSMutableDictionary = ObjC.classes.NSMutableDictionary

		const SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName('Security', 'SecItemCopyMatching')), 'pointer', ['pointer', 'pointer'])
		const SecItemDelete = new NativeFunction(ptr(Module.findExportByName('Security', 'SecItemDelete')), 'pointer', ['pointer'])
		const SecAccessControlGetConstraints = new NativeFunction(
		ptr(Module.findExportByName('Security', 'SecAccessControlGetConstraints')),
		'pointer', ['pointer']
		)

		const NSCFBoolean = ObjC.classes.__NSCFBoolean
		const kCFBooleanTrue = NSCFBoolean.numberWithBool_(true)

		const result = []

		const query = NSMutableDictionary.alloc().init()
		query.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes)
		query.setObject_forKey_(kCFBooleanTrue, kSecReturnData)
		query.setObject_forKey_(kCFBooleanTrue, kSecReturnRef)
		query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit)

		kSecClasses.forEach(function(clazz) {
		query.setObject_forKey_(clazz, kSecClass)

		const p = Memory.alloc(Process.pointerSize)
		const status = SecItemCopyMatching(query, p)
		/* eslint eqeqeq: 0 */
		if (status != 0x00)
		  return

		const arr = new ObjC.Object(Memory.readPointer(p))
		var i,size;
		for (i = 0, size = arr.count(); i < size; i++) {
		  const item = arr.objectAtIndex_(i)
		  result.push({
		    clazz: constantLookup(clazz),
		    creation: odas(item.objectForKey_(kSecAttrCreationDate)),
		    modification: odas(item.objectForKey_(kSecAttrModificationDate)),
		    description: odas(item.objectForKey_(kSecAttrDescription)),
		    comment: odas(item.objectForKey_(kSecAttrComment)),
		    creator: odas(item.objectForKey_(kSecAttrCreator)),
		    type: odas(item.objectForKey_(kSecAttrType)),
		    scriptCode: odas(item.objectForKey_(kSecAttrScriptCode)),
		    alias: odas(item.objectForKey_(kSecAttrAlias)),
		    invisible: odas(item.objectForKey_(kSecAttrIsInvisible)),
		    negative: odas(item.objectForKey_(kSecAttrIsNegative)),
		    customIcon: odas(item.objectForKey_(kSecAttrHasCustomIcon)),
		    protected: odas(item.objectForKey_(kSecProtectedDataItemAttr)),
		    accessControl: decodeAcl(item,SecAccessControlGetConstraints).join(' '),
		    accessibleAttribute: constantLookup(odas(item.objectForKey_(kSecAttrAccessible))),
		    entitlementGroup: odas(item.objectForKey_(kSecAttrAccessGroup)),
		    generic: odas(item.objectForKey_(kSecAttrGeneric)),
		    service: odas(item.objectForKey_(kSecAttrService)),
		    account: odas(item.objectForKey_(kSecAttrAccount)),
		    label: odas(item.objectForKey_(kSecAttrLabel)),
		    data: odas(item.objectForKey_('v_Data'))
		  })
		}
		});

		console.log("**** KEYCHAIN DUMP ****");
		var j,k,currentEntry;
		for(k in result) {
		console.log("\tEntry " + k);
		currentEntry = result[k];
		for(j in currentEntry) {
		  if(currentEntry[j]) {
		    console.log("\t\t" + j + ": " + currentEntry[j]);
		  }
		}    
		}
		console.log("**** END KEYCHAIN DUMP ****");
	
	},

	iosdataprotectionkeys: function() {

		function listDirectoryContentsAtPath(path) {
		  var fileManager = ObjC.classes.NSFileManager.defaultManager();
		  var enumerator = fileManager.enumeratorAtPath_(path);
		  var file;
		  var paths = [];

		  while ((file = enumerator.nextObject()) !== null){
		    paths.push(path + '/' + file);
		  }

		  return paths;
		}

		function listHomeDirectoryContents() {
		  var homePath = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
		  var paths = listDirectoryContentsAtPath(homePath);
		  return paths;
		}

		function getDataProtectionKeyForPath(path) {
		  var fileManager = ObjC.classes.NSFileManager.defaultManager();
		  var urlPath = ObjC.classes.NSURL.fileURLWithPath_(path);
		  var attributeDict = dictFromNSDictionary(fileManager.attributesOfItemAtPath_error_(urlPath.path(), NULL));
		  return attributeDict.NSFileProtectionKey;
		}

		// helper function available at https://codeshare.frida.re/@dki/ios-app-info/
		function dictFromNSDictionary(nsDict) {
		    var jsDict = {};
		    var keys = nsDict.allKeys();
		    var count = keys.count();

		    for (var i = 0; i < count; i++) {
		        var key = keys.objectAtIndex_(i);
		        var value = nsDict.objectForKey_(key);
		        jsDict[key.toString()] = value.toString();
		    }

		    return jsDict;
		}	

		var fileManager = ObjC.classes.NSFileManager.defaultManager();
		var dict = [];
		var paths = listHomeDirectoryContents();

		var isDir = Memory.alloc(Process.pointerSize);
		Memory.writePointer(isDir,NULL);

		for (var i = 0; i < paths.length; i++) {
			fileManager.fileExistsAtPath_isDirectory_(paths[i], isDir);

			if (Memory.readPointer(isDir) == 0) {
			  dict.push({
			    path: paths[i],
			    fileProtectionKey: getDataProtectionKeyForPath(paths[i])
			  });
			}
		}

		console.log("**** Files with Data Protection ****");
		var k;
		for(k in dict) {
		console.log("\tFile " + k);
		console.log("\tPath: " + dict[k]['path']);
		console.log("\tFile protection key: " + dict[k]['fileProtectionKey']);
		console.log("");
		}
		console.log("**** END Files with Data Protection ****");

	},

	iosdumpcurrentencryptedapp: function() {

		var O_RDONLY = 0;
		var O_WRONLY = 1;
		var O_RDWR = 2;
		var O_CREAT = 512;

		var SEEK_SET = 0;
		var SEEK_CUR = 1;
		var SEEK_END = 2;

		var NSString = ObjC.classes.NSString;
		var NSFileManager = ObjC.classes.NSFileManager;

		function allocStr(str) {
		    return Memory.allocUtf8String(str);
		}

		function getNSString(str) {
		    return NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
		}

		function getStr(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readUtf8String(addr);
		}

		function getStrSize(addr, size) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readUtf8String(addr, size);
		}

		function putStr(addr, str) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.writeUtf8String(addr, str);
		}

		function getByteArr(addr, l) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readByteArray(addr, l);
		}

		function getU8(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readU8(addr);
		}

		function putU8(addr, n) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.writeU8(addr, n);
		}

		function getU16(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readU16(addr);
		}

		function putU16(addr, n) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.writeU16(addr, n);
		}

		function getU32(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readU32(addr);
		}

		function putU32(addr, n) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.writeU32(addr, n);
		}

		function getU64(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readU64(addr);
		}

		function putU64(addr, n) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.writeU64(addr, n);
		}

		function getPt(addr) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    return Memory.readPointer(addr);
		}

		function putPt(addr, n) {
		    if (typeof addr == "number") {
		        addr = ptr(addr);
		    }
		    if (typeof n == "number") {
		        n = ptr(n);
		    }
		    return Memory.writePointer(addr, n);
		}

		function malloc(size) {
		    return Memory.alloc(size);
		}

		function getExportFunction(type, name, ret, args) {
		    var nptr;
		    nptr = Module.findExportByName(null, name);
		    if (nptr === null) {
		        console.log("cannot find " + name);
		        return null;
		    } else {
		        if (type === "f") {
		            var funclet = new NativeFunction(nptr, ret, args);
		            if (typeof funclet === "undefined") {
		                console.log("parse error " + name);
		                return null;
		            }
		            return funclet;
		        } else if (type === "d") {
		            var datalet = Memory.readPointer(nptr);
		            if (typeof datalet === "undefined") {
		                console.log("parse error " + name);
		                return null;
		            }
		            return datalet;
		        }
		    }
		}

		function dumpMemory(addr, length) {
		    console.log(hexdump(Memory.readByteArray(addr, length), {
		        offset: 0,
		        length: length,
		        header: true,
		        ansi: true
		    }));
		}

		var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
		var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
		var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
		var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
		var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
		var close = getExportFunction("f", "close", "int", ["int"]);

		function getCacheDir(index) {
			var NSUserDomainMask = 1;
			var npdirs = NSSearchPathForDirectoriesInDomains(index, NSUserDomainMask, 1);
			var len = ObjC.Object(npdirs).count();
			if (len == 0) {
				return '';
			}
			return ObjC.Object(npdirs).objectAtIndex_(0).toString();
		}

		function open(pathname, flags, mode) {
		    if (typeof pathname == "string") {
		        pathname = allocStr(pathname);
		    }
		    return wrapper_open(pathname, flags, mode);
		}

		// Export function
		var modules = null;
		function getAllAppModules() {
			if (modules == null) {
				modules = new Array();
				var tmpmods = Process.enumerateModulesSync();
				for (var i = 0; i < tmpmods.length; i++) {
					if (tmpmods[i].path.indexOf(".app") != -1) {
						modules.push(tmpmods[i]);
					}
				}
			}
			return modules;
		}

		var MH_MAGIC = 0xfeedface;
		var MH_CIGAM = 0xcefaedfe;
		var MH_MAGIC_64 = 0xfeedfacf;
		var MH_CIGAM_64 = 0xcffaedfe;
		var LC_SEGMENT = 0x1;
		var LC_SEGMENT_64 = 0x19;
		var LC_ENCRYPTION_INFO = 0x21;
		var LC_ENCRYPTION_INFO_64 = 0x2C;

		// You can dump .app or dylib (Encrypt/No Encrypt)
		function dumpModule(name) {
			if (modules == null) {
				modules = getAllAppModules();
			}
			var targetmod = null;
			for (var i = 0; i < modules.length; i++) {
				if (modules[i].path.indexOf(name) != -1) {
					targetmod = modules[i];
					break;
				}
			}
			if (targetmod == null) {
				console.log("Cannot find module");
			}
			var modbase = modules[i].base;
			var modsize = modules[i].size;
			var newmodname = modules[i].name + ".decrypted";
			var finddir = false;
			var newmodpath = "";
			var fmodule = -1;
			var index = 1;
			while (!finddir) {
				try {
					var base = getCacheDir(index);
					if (base != null) {
						newmodpath = getCacheDir(index) + "/" + newmodname;
						fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
						if (fmodule != -1) {
							break;
						};
					}
				}
				catch(e) {
				}
				index++;
			}
			
			var oldmodpath = modules[i].path;
			var foldmodule = open(oldmodpath, O_RDONLY, 0);
			if (fmodule == -1 || foldmodule == -1) {
				console.log("Cannot open file" + newmodpath);
				return;
			}

			var BUFSIZE = 4096;
			var buffer = malloc(BUFSIZE);
			while (read(foldmodule, buffer, BUFSIZE)) {
				write(fmodule, buffer, BUFSIZE);
			}
			
			// Find crypt info and recover
			var is64bit = false;
			var size_of_mach_header = 0;
			var magic = getU32(modbase);
			if (magic == MH_MAGIC || magic == MH_CIGAM) {
				is64bit = false;
				size_of_mach_header = 28;
			}
			else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
				is64bit = true;
				size_of_mach_header = 32;
			}
			var ncmds = getU32(modbase.add(16));
			var off = size_of_mach_header;
			var offset_cryptoff = -1;
			var crypt_off = 0;
			var crypt_size = 0;
			var segments = [];
			for (var i = 0; i < ncmds; i++) {
				var cmd = getU32(modbase.add(off));
				var cmdsize = getU32(modbase.add(off + 4)); 
				if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
					offset_cryptoff = off + 8;
					crypt_off = getU32(modbase.add(off + 8));
					crypt_size = getU32(modbase.add(off + 12));
				}
				off += cmdsize;
			}

			if (offset_cryptoff != -1) {
				var tpbuf = malloc(8);
				console.log("Fix decrypted at:" + offset_cryptoff.toString(16));
				putU64(tpbuf, 0);
				lseek(fmodule, offset_cryptoff, SEEK_SET);
				write(fmodule, tpbuf, 8);
				console.log("Fix decrypted at:" + crypt_off.toString(16));
				lseek(fmodule, crypt_off, SEEK_SET);
				write(fmodule, modbase.add(crypt_off), crypt_size);
			}
			console.log("Decrypted file at:" + newmodpath + " 0x" + modsize.toString(16));
			close(fmodule);
			close(foldmodule);
		}

		dumpModule(".app");

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