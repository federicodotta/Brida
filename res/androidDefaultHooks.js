module.exports = {
	androidpinningwithca1, androidpinningwithoutca1, androidrooting1, 
    androidfingerprintbypass1, androidfingerprintbypass2hook, 
    androidfingerprintbypass2function, tracekeystore, listaliasesstatic, 
    listaliasesruntime, dumpcryptostuff
}

function androidpinningwithca1() {

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
}

function androidpinningwithoutca1() {

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
}

function androidrooting1() {

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
	    
	    console.log("Loaded " + loaded_classes.length + " classes!");

	    var useKeyInfo = false;

	    var useProcessManager = false;

	    console.log("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

	    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
	        try {
	            //useProcessManager = true;
	            //var ProcessManager = Java.use('java.lang.ProcessManager');
	        } catch (err) {
	            console.log("ProcessManager Hook failed: " + err);
	        }
	    } else {
	        console.log("ProcessManager hook not loaded");
	    }

	    var KeyInfo = null;

	    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
	        try {
	            //useKeyInfo = true;
	            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
	        } catch (err) {
	            console.log("KeyInfo Hook failed: " + err);
	        }
	    } else {
	        console.log("KeyInfo hook not loaded");
	    }

	    PackageManager.getPackageInfo.implementation = function(pname, flags) {
	        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
	        if (shouldFakePackage) {
	            console.log("Bypass root check for package: " + pname);
	            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
	        }
	        return this.getPackageInfo.call(this, pname, flags);
	    };

	    NativeFile.exists.implementation = function() {
	        var name = NativeFile.getName.call(this);
	        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
	        if (shouldFakeReturn) {
	            console.log("Bypass return value for binary: " + name);
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
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        if (cmd == "su") {
	            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        return exec5.call(this, cmd, env, dir);
	    };

	    exec4.implementation = function(cmdarr, env, file) {
	        for (var i = 0; i < cmdarr.length; i = i + 1) {
	            var tmp_cmd = cmdarr[i];
	            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
	                var fakeCmd = "grep";
	                console.log("Bypass " + cmdarr + " command");
	                return exec1.call(this, fakeCmd);
	            }

	            if (tmp_cmd == "su") {
	                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	                console.log("Bypass " + cmdarr + " command");
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
	                console.log("Bypass " + cmdarr + " command");
	                return exec1.call(this, fakeCmd);
	            }

	            if (tmp_cmd == "su") {
	                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	                console.log("Bypass " + cmdarr + " command");
	                return exec1.call(this, fakeCmd);
	            }
	        }
	        return exec3.call(this, cmdarr, envp);
	    };

	    exec2.implementation = function(cmd, env) {
	        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
	            var fakeCmd = "grep";
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        if (cmd == "su") {
	            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        return exec2.call(this, cmd, env);
	    };

	    exec.implementation = function(cmd) {
	        for (var i = 0; i < cmd.length; i = i + 1) {
	            var tmp_cmd = cmd[i];
	            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
	                var fakeCmd = "grep";
	                console.log("Bypass " + cmd + " command");
	                return exec1.call(this, fakeCmd);
	            }

	            if (tmp_cmd == "su") {
	                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	                console.log("Bypass " + cmd + " command");
	                return exec1.call(this, fakeCmd);
	            }
	        }

	        return exec.call(this, cmd);
	    };

	    exec1.implementation = function(cmd) {
	        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
	            var fakeCmd = "grep";
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        if (cmd == "su") {
	            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
	            console.log("Bypass " + cmd + " command");
	            return exec1.call(this, fakeCmd);
	        }
	        return exec1.call(this, cmd);
	    };

	    String.contains.implementation = function(name) {
	        if (name == "test-keys") {
	            console.log("Bypass test-keys check");
	            return false;
	        }
	        return this.contains.call(this, name);
	    };

	    var get = SystemProperties.get.overload('java.lang.String');

	    get.implementation = function(name) {
	        if (RootPropertiesKeys.indexOf(name) != -1) {
	            console.log("Bypass " + name);
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
	                console.log("Bypass native fopen");
	            }
	        },
	        onLeave: function(retval) {

	        }
	    });

	    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
	        onEnter: function(args) {
	            var cmd = Memory.readCString(args[0]);
	            console.log("SYSTEM CMD: " + cmd);
	            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
	                console.log("Bypass native system: " + cmd);
	                Memory.writeUtf8String(args[0], "grep");
	            }
	            if (cmd == "su") {
	                console.log("Bypass native system: " + cmd);
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
	                console.log("Bypass build.prop file read");
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
	            console.log("Bypass ProcessBuilder " + cmd);
	            this.command.call(this, ["grep"]);
	            return this.start.call(this);
	        }
	        if (cmd.indexOf("su") != -1) {
	            console.log("Bypass ProcessBuilder " + cmd);
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
	                    console.log("Bypass " + cmdarr + " command");
	                }

	                if (tmp_cmd == "su") {
	                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
	                    console.log("Bypass " + cmdarr + " command");
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
	                    console.log("Bypass " + cmdarr + " command");
	                }

	                if (tmp_cmd == "su") {
	                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
	                    console.log("Bypass " + cmdarr + " command");
	                }
	            }
	            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
	        };
	    }

	    if (useKeyInfo) {
	        KeyInfo.isInsideSecureHardware.implementation = function() {
	            console.log("Bypass isInsideSecureHardware");
	            return true;
	        }
	    }

	});

}

// By FSecureLABS
// https://raw.githubusercontent.com/FSecureLABS/android-keystore-audit/master/frida-scripts/fingerprint-bypass.js
function androidfingerprintbypass1() {

	console.log("Fingerprint hooks loaded!");

	Java.perform(function () {
	    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
	    try { hookBiometricPrompt_authenticate(); }
	    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
	    try { hookBiometricPrompt_authenticate2(); }
	    catch (error) { console.log("hookBiometricPrompt_authenticate not supported on this android version") }
	    try { hookFingerprintManagerCompat_authenticate(); }
	    catch (error) { console.log("hookFingerprintManagerCompat_authenticate failed"); }
	    try { hookFingerprintManager_authenticate(); }
	    catch (error) { console.log("hookFingerprintManager_authenticate failed"); }
	});



	var cipherList = [];
	var StringCls = null;
	Java.perform(function () {
	    StringCls = Java.use('java.lang.String');

	});

	function getAuthResult(resultObj, cryptoInst) {
	    try {
	        var authenticationResultInst = resultObj.$new(cryptoInst, null, 0);
	    } catch (error) {
	        try {
	            var authenticationResultInst = resultObj.$new(cryptoInst, null);
	        }
	        catch (error) {
	            var authenticationResultInst = resultObj.$new(cryptoInst);
	        }
	    }
	    console.log("cryptoInst:, " + cryptoInst + " class: " + cryptoInst.$className);
	    return authenticationResultInst;
	}

	function getBiometricPromptAuthResult() {
	    var sweet_cipher = null;
	    var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
	    var cryptoInst = cryptoObj.$new(sweet_cipher);
	    var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
	    var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
	    return authenticationResultInst
	}

	function hookBiometricPrompt_authenticate() {
	    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
	    console.log("Hooking BiometricPrompt.authenticate()...");
	    biometricPrompt.implementation = function (cancellationSignal, executor, callback) {
	        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
	        var authenticationResultInst = getBiometricPromptAuthResult();
	        callback.onAuthenticationSucceeded(authenticationResultInst);
	    }
	}

	function hookBiometricPrompt_authenticate2() {
	    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
	    console.log("Hooking BiometricPrompt.authenticate2()...");
	    biometricPrompt.implementation = function (crypto, cancellationSignal, executor, callback) {
	        console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto + ", cancellationSignal: " + cancellationSignal + ", executor: " + ", callback: " + callback);
	        var authenticationResultInst = getBiometricPromptAuthResult();
	        callback.onAuthenticationSucceeded(authenticationResultInst);
	    }
	}

	function hookFingerprintManagerCompat_authenticate() {

	    var fingerprintManagerCompat = null;
	    var cryptoObj = null;
	    var authenticationResultObj = null;
	    try {
	        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
	        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
	        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
	    } catch (error) {
	        try {
	            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
	            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
	            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
	        }
	        catch (error) {
	            console.log("FingerprintManagerCompat class not found!");
	            return
	        }
	    }
	    console.log("Hooking FingerprintManagerCompat.authenticate()...");
	    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
	    fingerprintManagerCompat_authenticate.implementation = function (crypto, flags, cancel, callback, handler) {
	        console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
	        //console.log(enumMethods(callback.$className));
	        callback['onAuthenticationFailed'].implementation = function () {
	            console.log("[onAuthenticationFailed()]:");
	            var sweet_cipher = null;
	            var cryptoInst = cryptoObj.$new(sweet_cipher);
	            var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
	            callback.onAuthenticationSucceeded(authenticationResultInst);
	        }
	        return this.authenticate(crypto, flags, cancel, callback, handler);
	    }
	}

	function hookFingerprintManager_authenticate() {

	    var fingerprintManager = null;
	    var cryptoObj = null;
	    var authenticationResultObj = null;
	    try {
	        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
	        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
	        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
	    } catch (error) {
	        try {
	            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
	            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
	            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
	        }
	        catch (error) {
	            console.log("FingerprintManager class not found!");
	            return
	        }
	    }
	    console.log("Hooking FingerprintManager.authenticate()...");

	    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
	    fingerprintManager_authenticate.implementation = function (crypto, cancel, flags, callback, handler) {
	        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: " + flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: " + handler);
	        var sweet_cipher = null;
	        var cryptoInst = cryptoObj.$new(sweet_cipher);
	        var authenticationResultInst = getAuthResult(authenticationResultObj, cryptoInst);
	        callback.onAuthenticationSucceeded(authenticationResultInst);
	        return this.authenticate(crypto, cancel, flags, callback, handler);
	    }
	}


	function enumMethods(targetClass) {
	    var hook = Java.use(targetClass);
	    var ownMethods = hook.class.getDeclaredMethods();

	    return ownMethods;
	}

}

// By FSecureLABS
// https://raw.githubusercontent.com/FSecureLABS/android-keystore-audit/master/frida-scripts/fingerprint-bypass-via-exception-handling.js

function androidfingerprintbypass2hook() {


	/*
	    Fingerprint bypass via Exception Handling.
	    We assume that application use CryptoObject to perform some crypto stuff in the onAuthenticationSucceeded only to confirm that fingerprint authentication (e.g. all data is encrypted using key other than this from fingerprint ).

	    How to use:
	    1. Attach script to application.
	    1. Trigger fingerprint screen (frida should log that authenticate() method was called)
	    3. run bypass() function.

	*/

	console.log("Fingerprint hooks loaded!");

	Java.perform(function () {

	    //Call in try catch as Biometric prompt is supported since api 28 (Android 9)
	    try {hookBiometricPrompt_authenticate();} catch (error){console.log("hookBiometricPrompt_authenticate not supported on this android version")}
	    try {hookBiometricPrompt_authenticate2();} catch (error){console.log("hookBiometricPrompt_authenticate not supported on this android version")}
	    
	    //hookFingerprintManagerCompat_authenticate();
	    hookFingerprintManager_authenticate();


	    hookDoFinal();
	    hookDoFinal2();
	    hookDoFinal3();
	    hookDoFinal4();
	    hookDoFinal5();
	    hookDoFinal6();
	    hookDoFinal7();
	    hookUpdate();
	    hookUpdate2();
	    hookUpdate3();
	    hookUpdate4();
	    hookUpdate5();
	 
	});



	var cipherList = [];
	
	
	var StringCls = null;
	Java.perform(function () {
	    StringCls = Java.use('java.lang.String');


	});


	function hookBiometricPrompt_authenticate()
	{
	    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
	    console.log("Hooking BiometricPrompt.authenticate()...");
	    biometricPrompt.implementation = function(cancellationSignal,executor,callback) {
	        console.log("[BiometricPrompt.BiometricPrompt()]: cancellationSignal: " + cancellationSignal +", executor: "+ ", callback: "+ callback);

	        var sweet_cipher=null;
	        var cryptoObj = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
	        var cryptoInst = cryptoObj.$new(sweet_cipher);
	        
	        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
	        global.authenticationResultInst = authenticationResultObj.$new(cryptoInst,null,0);
	        console.log("cryptoInst:, " + cryptoInst + " class: "+ cryptoInst.$className);

	        callback.onAuthenticationSucceeded(authenticationResultInst);  
	        //return this.authenticate(cancellationSignal,executor,callback);
	    }   

	}

	function hookBiometricPrompt_authenticate2()
	{
	    var biometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt')['authenticate'].overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
	    console.log("Hooking BiometricPrompt.authenticate2()...");
	    biometricPrompt.implementation = function(crypto,cancellationSignal,executor,callback) {
	       console.log("[BiometricPrompt.BiometricPrompt2()]: crypto:" + crypto+ ", cancellationSignal: " + cancellationSignal +", executor: "+ ", callback: "+ callback);


	        
	        var authenticationResultObj = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
	        global.authenticationResultInst = authenticationResultObj.$new(crypto,null,0);
	        global.callbackG = callback; 

	        //callback.onAuthenticationSucceeded(authenticationResultInst);

	        return this.authenticate(crypto,cancellationSignal,executor,callback);
	    }   

	}

	function hookFingerprintManagerCompat_authenticate()
	{
	    var fingerprintManagerCompat=null;
	    var cryptoObj=null;
	    var authenticationResultObj=null;
	    try{
	        fingerprintManagerCompat = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat');
	        cryptoObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
	        authenticationResultObj = Java.use('android.support.v4.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
	    }catch(error){}
	    if(fingerprintManagerCompat == null)
	    {
	        try{
	            fingerprintManagerCompat = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat');
	            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$CryptoObject');
	            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManagerCompat$AuthenticationResult');
	        }catch(error){}
	    }
	    if(fingerprintManagerCompat == null)
	    {
	        console.log("FingerprintManagerCompat class not found!");
	        return;
	    }
	    console.log("Hooking FingerprintManagerCompat.authenticate()...");
	    var fingerprintManagerCompat_authenticate = fingerprintManagerCompat['authenticate'];
	    fingerprintManagerCompat_authenticate.implementation = function(crypto,flags, cancel, callback, handler) {
	        console.log("[FingerprintManagerCompat.authenticate()]: crypto: " + crypto + ", flags: "+ flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: "+ handler );
	        //console.log(enumMethods(callback.$className));
	        // Hook onAuthenticationFailed
	        callback['onAuthenticationFailed'].implementation = function() {
	            console.log("[onAuthenticationFailed()]:" );


	           
	        }   
	        
	        global.authenticationResultInst = authenticationResultObj.$new(crypto,null,0);
	        global.callbackG = callback; 

	        return this.authenticate(crypto,flags, cancel, callback, handler);
	    }   
	}

	function hookFingerprintManager_authenticate()
	{
	    var fingerprintManager=null;
	    var cryptoObj=null;
	    var authenticationResultObj=null;
	    try{
	        fingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
	        cryptoObj = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
	        authenticationResultObj = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
	    }catch(error){}
	    if(fingerprintManager == null)
	    {
	        try{
	            fingerprintManager = Java.use('androidx.core.hardware.fingerprint.FingerprintManager');
	            cryptoObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$CryptoObject');
	            authenticationResultObj = Java.use('androidx.core.hardware.fingerprint.FingerprintManager$AuthenticationResult');
	        }catch(error){}
	    }
	    if(fingerprintManager == null)
	    {
	        console.log("FingerprintManager class not found!");
	        return;
	    }
	    console.log("Hooking FingerprintManager.authenticate()...");

	    var fingerprintManager_authenticate = fingerprintManager['authenticate'].overload('android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler');
	    fingerprintManager_authenticate.implementation = function(crypto,cancel, flags, callback, handler) {
	        console.log("[FingerprintManager.authenticate()]: crypto: " + crypto + ", flags: "+ flags + ", cancel:" + cancel + ", callback: " + callback + ", handler: "+ handler );
	        
	        global.authenticationResultInst = authenticationResultObj.$new(crypto,null,0);
	        global.callbackG = callback;

	        return this.authenticate(crypto, cancel,flags, callback, handler);
	    }   
	}


	function enumMethods(targetClass)
	{
	    var hook = Java.use(targetClass);
	    var ownMethods = hook.class.getDeclaredMethods();

	    return ownMethods;
	}

	function hookDoFinal()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload() ;
	    var tmp = null;
	    cipherInit.implementation = function() {
	        console.log("[Cipher.doFinal()]: "+ "  cipherObj: "+this);
	        
	        try{  
	            tmp = this.doFinal();
	        }
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return null;
	            }
	        }
	        return tmp;
	    } 
	}

	function hookDoFinal2()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr) {
	        console.log("[Cipher.doFinal2()]: "+ "  cipherObj: "+this);
	        try{  
	            tmp = this.doFinal(byteArr);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return byteArr;
	            }
	        }
	        return tmp;
	    } 
	}

	function hookDoFinal3()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1) {
	        console.log("[Cipher.doFinal3()]: "+ "  cipherObj: "+this);
	        try{ 
	            tmp = this.doFinal(byteArr, a1);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }
	        }
	        return tmp;
	    } 
	}

	function hookDoFinal4()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer') ;
	    var tmp = null;
	    cipherInit.implementation = function(a1, a2) {
	        console.log("[Cipher.doFinal4()]: "+ "  cipherObj: "+this);
	        try{          
	            tmp = this.doFinal(a1, a2);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }

	        }
	        return tmp;
	    } 
	}

	function hookDoFinal5()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2) {
	        console.log("[Cipher.doFinal5()]: "+ "  cipherObj: "+this);
	        try{ 
	            tmp = this.doFinal(byteArr, a1, a2);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return byteArr;
	            }
	        }
	        return tmp;
	    } 
	}

	function hookDoFinal6()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2, outputArr) {
	        console.log("[Cipher.doFinal6()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.doFinal(byteArr, a1, a2, outputArr);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }
	        }
	        
	        return tmp;
	    } 
	}

	function hookDoFinal7()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2, outputArr, a4) {
	        console.log("[Cipher.doFinal7()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }
	        }

	        return tmp;
	    } 
	}

	function hookUpdate()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr) {
	        console.log("[Cipher.update()]: "+ "  cipherObj: "+this);
	        try{        
	            tmp = this.update(byteArr);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return byteArr;
	            }            
	        }
	        return tmp;
	    } 
	}

	function hookUpdate2()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, outputArr) {
	        console.log("[Cipher.update2()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.update(byteArr, outputArr);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }              
	        }
	        return tmp;
	    } 
	}

	function hookUpdate3()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2) {
	        console.log("[Cipher.update3()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.update(byteArr, a1, a2);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return byteArr;
	            }              
	        }
	        return tmp;
	    } 
	}

	function hookUpdate4()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2, outputArr) {
	        console.log("[Cipher.update4()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.update(byteArr, a1, a2, outputArr );
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }  
	        }
	        return tmp;
	    } 
	}

	function hookUpdate5()
	{
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int') ;
	    var tmp = null;
	    cipherInit.implementation = function(byteArr, a1, a2, outputArr, a4) {
	        console.log("[Cipher.update5()]: "+ "  cipherObj: "+this);
	        try{
	            tmp = this.update(byteArr, a1, a2, outputArr, a4);
	        } 
	        catch (error)
	        {
	            console.log("exception catched! " + error  ); 
	            if((error+"").indexOf("javax.crypto.IllegalBlockSizeException")==-1) 
	                throw error;
	            else
	            {
	                return 1;
	            }  
	        }    
	        return tmp;
	    } 
	}


}

// By FSecureLABS
// https://raw.githubusercontent.com/FSecureLABS/android-keystore-audit/master/frida-scripts/fingerprint-bypass-via-exception-handling.js
function androidfingerprintbypass2function() {

    Java.perform(function () {

        try {
            var Runnable = Java.use('java.lang.Runnable');
            var Runner = Java.registerClass({
                name: 'com.MWR.Runner',
                implements: [Runnable],
                methods: {
                    run: function () 
                        {
                            try
                            { 
                                callbackG.onAuthenticationSucceeded(authenticationResultInst); // we just need to call this single line (other code is needed to call this on UI thread)
                            } 
                            catch (error)
                            {
                                console.log("exception catched!" + error  ); 
                            }
                        }
                }
            });

            var Handler = Java.use('android.os.Handler');
            var Looper = Java.use('android.os.Looper'); 
            var loop = Looper.getMainLooper();
            var handler = Handler.$new(loop);
            handler.post(Runner.$new());

        } catch (e) {
            console.log("registerClass error3 >>>>>>>> " + e);
        }

    });
	
}

// FSecureLABS
// https://raw.githubusercontent.com/FSecureLABS/android-keystore-audit/master/frida-scripts/tracer-keystore.js
function tracekeystore() {

	Java.perform(function () {
		hookKeystoreGetInstance();
		hookKeystoreGetInstance_Provider();
		hookKeystoreGetInstance_Provider2();
		hookKeystoreConstructor();
		hookKeystoreLoad(false);
		hookKeystoreLoadStream(false);
		hookKeystoreGetKey();
		hookKeystoreSetKeyEntry();
		//hookKeystoreGetCertificate();
		hookKeystoreGetCertificateChain();
		hookKeystoreGetEntry();
		hookKeystoreSetEntry();
		hookKeystoreSetKeyEntry();
		hookKeystoreSetKeyEntry2();
		hookKeystoreStore();
		hookKeystoreStoreStream()


	});
	console.log("KeyStore hooks loaded!");

	global.keystoreList = [];
	var StringCls = null;
	Java.perform(function () {
		StringCls = Java.use('java.lang.String');


	});

	function hookKeystoreConstructor() {
		var keyStoreConstructor = Java.use('java.security.KeyStore').$init.overload("java.security.KeyStoreSpi", "java.security.Provider", "java.lang.String");
		keyStoreConstructor.implementation = function (keyStoreSpi, provider, type) {
			//console.log("[Call] Keystore(java.security.KeyStoreSpi, java.security.Provider, java.lang.String )")
			console.log("[Keystore()]: KeyStoreSpi: " + keyStoreSpi + ", Provider: " + provider + ", type: " + type);
			return this.$init(keyStoreSpi, provider, type);

		}
	}

	function hookKeystoreGetInstance() {
		var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String");
		keyStoreGetInstance.implementation = function (type) {
			//console.log("[Call] Keystore.getInstance(java.lang.String )")
			console.log("[Keystore.getInstance()]: type: " + type);
			var tmp = this.getInstance(type);
			global.keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
			return tmp;
		}
	}

	function hookKeystoreGetInstance_Provider() {
		var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.lang.String");
		keyStoreGetInstance.implementation = function (type, provider) {
			//console.log("[Call] Keystore.getInstance(java.lang.String, java.lang.String )")
			console.log("[Keystore.getInstance2()]: type: " + type + ", provider: " + provider);
			var tmp = this.getInstance(type, proivder);
			global.keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
			return tmp;
		}
	}

	function hookKeystoreGetInstance_Provider2() {
		var keyStoreGetInstance = Java.use('java.security.KeyStore')['getInstance'].overload("java.lang.String", "java.security.Provider");
		keyStoreGetInstance.implementation = function (type, provider) {
			//console.log("[Call] Keystore.getInstance(java.lang.String, java.security.Provider )")
			console.log("[Keystore.getInstance2()]: type: " + type + ", provider: " + provider);
			var tmp = this.getInstance(type, proivder);
			global.keystoreList.push(tmp); // Collect keystore objects to allow dump them later using ListAliasesRuntime()
			return tmp;
		}
	}

	/*
	* Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.	
	*/
	function hookKeystoreLoad(dump) {
		var keyStoreLoad = Java.use('java.security.KeyStore')['load'].overload('java.security.KeyStore$LoadStoreParameter');
		/* following function hooks to a Keystore.load(java.security.KeyStore.LoadStoreParameter) */
		keyStoreLoad.implementation = function (param) {
			//console.log("[Call] Keystore.load(java.security.KeyStore.LoadStoreParameter)")
			console.log("[Keystore.load(LoadStoreParameter)]: keystoreType: " + this.getType() + ", param: " + param);
			this.load(param);
			if (dump) console.log(" Keystore loaded aliases: " + ListAliasesObj(this));
		}
	}

	/*
	* Hook Keystore.load( ... ), set dump to true if you want to perform dump of available Aliases automatically.	
	*/
	function hookKeystoreLoadStream(dump) {
		var keyStoreLoadStream = Java.use('java.security.KeyStore')['load'].overload('java.io.InputStream', '[C');
		/* following function hooks to a Keystore.load(InputStream stream, char[] password) */
		keyStoreLoadStream.implementation = function (stream, charArray) {
			//console.log("[Call] Keystore.load(InputStream stream, char[] password)")
			//var hexString = readStreamToHex (stream);
			console.log("[Keystore.load(InputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', inputSteam: " + stream);
			this.load(stream, charArray);
			if (dump) console.log(" Keystore loaded aliases: " + ListAliasesObj(this));
		}
	}

	function hookKeystoreStore() {
		var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.security.KeyStore$LoadStoreParameter');
		/* following function hooks to a Keystore.store(java.security.KeyStore$LoadStoreParameter) */
		keyStoreStoreStream.implementation = function (param) {
			console.log("[Keystore.store()]: keystoreType: " + this.getType() + ", param: '" + param);
			this.store(stream, charArray);
		}
	}

	function hookKeystoreStoreStream() {
		var keyStoreStoreStream = Java.use('java.security.KeyStore')['store'].overload('java.io.OutputStream', '[C');
		/* following function hooks to a Keystore.store(OutputStream stream, char[] password) */
		keyStoreStoreStream.implementation = function (stream, charArray) {
			console.log("[Keystore.store(OutputStream, char[])]: keystoreType: " + this.getType() + ", password: '" + charArrayToString(charArray) + "', outputSteam: " + stream);
			this.store(stream, charArray);
		}
	}

	function hookKeystoreGetKey() {
		var keyStoreGetKey = Java.use('java.security.KeyStore')['getKey'].overload("java.lang.String", "[C");
		keyStoreGetKey.implementation = function (alias, charArray) {
			//console.log("[Call] Keystore.getKey(java.lang.String, [C )")
			console.log("[Keystore.getKey()]: alias: " + alias + ", password: '" + charArrayToString(charArray) + "'");
			return this.getKey(alias, charArray);
		}
	}

	function hookKeystoreSetEntry() {
		var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setEntry'].overload("java.lang.String", "java.security.KeyStore$Entry", "java.security.KeyStore$ProtectionParameter");
		keyStoreSetKeyEntry.implementation = function (alias, entry, protection) {
			//console.log("[Call] Keystore.setEntry(java.lang.String, java.security.KeyStore$Entry, java.security.KeyStore$ProtectionParameter )")
			console.log("[Keystore.setEntry()]: alias: " + alias + ", entry: " + dumpKeyStoreEntry(entry) + "', protection: " + dumpProtectionParameter(protection));
			return this.setEntry(alias, entry, protection);
		}
	}

	function hookKeystoreSetKeyEntry() {
		var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;");
		keyStoreSetKeyEntry.implementation = function (alias, key, charArray, certs) {
			//console.log("[Call] Keystore.setKeyEntry(java.lang.String, java.security.Key, [C, [Ljava.security.cert.Certificate; )
			console.log("[Keystore.setKeyEntry()]: alias: " + alias + ", key: " + key + ", password: '" + charArrayToString(charArray) + "', certs: " + certs);
			return this.setKeyEntry(alias, key, charArray, certs);
		}
	}

	function hookKeystoreSetKeyEntry2() {
		var keyStoreSetKeyEntry = Java.use('java.security.KeyStore')['setKeyEntry'].overload("java.lang.String", "[B", "[Ljava.security.cert.Certificate;");
		keyStoreSetKeyEntry.implementation = function (alias, key, certs) {
			//console.log("[Call] Keystore.setKeyEntry(java.lang.String, [B, [Ljava.security.cert.Certificate; )")
			console.log("[Keystore.setKeyEntry2()]: alias: " + alias + ", key: " + key + "', certs: " + certs);
			return this.setKeyEntry(alias, key, certs);
		}
	}

	/*
	* Usually used to load certs for cert pinning.
	*/
	function hookKeystoreGetCertificate() {
		var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificate'].overload("java.lang.String");
		keyStoreGetCertificate.implementation = function (alias) {
			//console.log("[Call] Keystore.getCertificate(java.lang.String )")
			console.log("[Keystore.getCertificate()]: alias: " + alias);
			return this.getCertificate(alias);
		}
	}

	/*
	* Usually used to load certs for cert pinning.
	*/
	function hookKeystoreGetCertificateChain() {
		var keyStoreGetCertificate = Java.use('java.security.KeyStore')['getCertificateChain'].overload("java.lang.String");
		keyStoreGetCertificate.implementation = function (alias) {
			//console.log("[Call] Keystore.getCertificateChain(java.lang.String )")
			console.log("[Keystore.getCertificateChain()]: alias: " + alias);
			return this.getCertificate(alias);
		}
	}

	function hookKeystoreGetEntry() {
		var keyStoreGetEntry = Java.use('java.security.KeyStore')['getEntry'].overload("java.lang.String", "java.security.KeyStore$ProtectionParameter");
		keyStoreGetEntry.implementation = function (alias, protection) {
			//console.log("[Call] Keystore.getEntry(java.lang.String, java.security.KeyStore$ProtectionParameter )")
			console.log("[Keystore.getEntry()]: alias: " + alias + ", protection: '" + dumpProtectionParameter(protection) + "'");
			var entry = this.getEntry(alias, protection);
			console.log("[getEntry()]: Entry: " + dumpKeyStoreEntry(entry));
			return entry;
		}
	}

}

/*
* Dump all aliasses in keystores of all types(predefined in keystoreTypes)	
*/
function listaliasesstatic() {
	// BCPKCS12/PKCS12-DEF - exceptions
	var keystoreTypes = ["AndroidKeyStore", "AndroidCAStore", /*"BCPKCS12",*/ "BKS", "BouncyCastle", "PKCS12", /*"PKCS12-DEF"*/];
	keystoreTypes.forEach(function (entry) {
		console.log("[ListAliasesStatic] keystoreType: " + entry + " \nAliases: " + ListAliasesType(entry));
	});
	return "[done]";
}

/*
* Dump all aliasses in keystores of all instances obtained during app runtime. 
* Instances that will be dumped are collected via hijacking Keystre.getInstance() -> hookKeystoreGetInstance()
*/
function listaliasesruntime() {
	Java.perform(function () {
		console.log("[ListAliasesRuntime] Instances: " + keystoreList);
		keystoreList.forEach(function (entry) {
			console.log("[ListAliasesRuntime] keystoreObj: " + entry + " type: " + entry.getType() + " \n" + ListAliasesObj(entry));
		});
	});
	return "[done]";
}


// FSecureLABS
// https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/tracer-cipher.js
// https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/tracer-secretkeyfactory.js
function dumpcryptostuff() {
	
	console.log("Cipher hooks loaded!");

	Java.perform(function () {
	    hookCipherGetInstance();
	    hookCipherGetInstance2();
	    hookCipherGetInstance3();
	    hookCipherInit();
	    hookCipherInit2();
	    hookCipherInit3();
	    hookCipherInit4();
	    hookCipherInit5();
	    hookCipherInit6();
	    hookCipherInit7();
	    hookCipherInit8();
	    hookDoFinal();
	    hookDoFinal2();
	    hookDoFinal3();
	    hookDoFinal4();
	    hookDoFinal5();
	    hookDoFinal6();
	    hookDoFinal7();
	    hookUpdate();
	    hookUpdate2();
	    hookUpdate3();
	    hookUpdate4();
	    hookUpdate5();


	});



	var cipherList = [];
	var StringCls = null;
	Java.perform(function () {
	    StringCls = Java.use('java.lang.String');


	});

	/*
	    .overload('java.lang.String')
	    .overload('java.lang.String', 'java.security.Provider')
	    .overload('java.lang.String', 'java.lang.String')
	*/
	function hookCipherGetInstance() {
	    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload("java.lang.String");
	    cipherGetInstance.implementation = function (type) {
	        console.log("[Cipher.getInstance()]: type: " + type);
	        var tmp = this.getInstance(type);
	        console.log("[Cipher.getInstance()]:  cipherObj: " + tmp);
	        cipherList.push(tmp);
	        return tmp;
	    }
	}


	function hookCipherGetInstance2() {
	    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.security.Provider');
	    cipherGetInstance.implementation = function (transforamtion, provider) {
	        console.log("[Cipher.getInstance2()]: transforamtion: " + transforamtion + ",  provider: " + provider);
	        var tmp = this.getInstance(transforamtion, provider);
	        console.log("[Cipher.getInstance2()]:  cipherObj: " + tmp);
	        cipherList.push(tmp);
	        return tmp;
	    }
	}

	function hookCipherGetInstance3() {
	    var cipherGetInstance = Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String', 'java.lang.String');
	    cipherGetInstance.implementation = function (transforamtion, provider) {
	        console.log("[Cipher.getInstance3()]: transforamtion: " + transforamtion + ",  provider: " + provider);
	        var tmp = this.getInstance(transforamtion, provider);
	        console.log("[Cipher.getInstance3()]:  cipherObj: " + tmp);
	        cipherList.push(tmp);
	        return tmp;
	    }
	}


	/*

	    .overload('int', 'java.security.cert.Certificate')
	    .overload('int', 'java.security.Key')
	    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters')
	    //.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')
	    .overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom')
	    .overload('int', 'java.security.Key', 'java.security.SecureRandom')
	    .overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom')
	    .overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom')
	*/
	function hookCipherInit() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate');
	    cipherInit.implementation = function (mode, cert) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " , cipherObj: " + this);
	        var tmp = this.init(mode, cert);
	    }
	}

	function hookCipherInit2() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key');
	    cipherInit.implementation = function (mode, secretKey) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey);
	    }
	}

	function hookCipherInit3() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters');
	    cipherInit.implementation = function (mode, secretKey, alParam) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey, alParam);
	    }
	}

	function hookCipherInit4() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec');
	    cipherInit.implementation = function (mode, secretKey, spec) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey, spec);
	    }
	}

	function hookCipherInit5() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom');
	    cipherInit.implementation = function (mode, cert, secureRandom) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", cert: " + cert + " secureRandom:" + secureRandom + " , cipherObj: " + this);
	        var tmp = this.init(mode, cert, secureRandom);
	    }
	}

	function hookCipherInit6() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.SecureRandom');
	    cipherInit.implementation = function (mode, secretKey, secureRandom) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " secureRandom:" + secureRandom + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey, secureRandom);
	    }
	}

	function hookCipherInit7() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom');
	    cipherInit.implementation = function (mode, secretKey, spec, secureRandom) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " spec:" + spec + " secureRandom: " + secureRandom + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey, spec, secureRandom);
	    }
	}

	function hookCipherInit8() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['init'].overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom');
	    cipherInit.implementation = function (mode, secretKey, alParam, secureRandom) {
	        console.log("[Cipher.init()]: mode: " + decodeMode(mode) + ", secretKey: " + secretKey.$className + " alParam:" + alParam + " secureRandom: " + secureRandom + " , cipherObj: " + this);
	        var tmp = this.init(mode, secretKey, alParam, secureRandom);
	    }
	}

	/*
	    .overload()
	    .overload('[B')
	    .overload('[B', 'int')
	    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
	    .overload('[B', 'int', 'int')
	    .overload('[B', 'int', 'int', '[B')
	    .overload('[B', 'int', 'int', '[B', 'int')
	*/

	function hookDoFinal() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload();
	    cipherInit.implementation = function () {
	        console.log("[Cipher.doFinal()]: " + "  cipherObj: " + this);
	        var tmp = this.doFinal();
	        dumpByteArray('Result', tmp);
	        return tmp;
	    }
	}

	function hookDoFinal2() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B');
	    cipherInit.implementation = function (byteArr) {
	        console.log("[Cipher.doFinal2()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.doFinal(byteArr);
	        dumpByteArray('Result', tmp);
	        return tmp;
	    }
	}

	function hookDoFinal3() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int');
	    cipherInit.implementation = function (byteArr, a1) {
	        console.log("[Cipher.doFinal3()]: " + "  cipherObj: " + this);
	        dumpByteArray('Out buffer', byteArr);
	        var tmp = this.doFinal(byteArr, a1);
	        dumpByteArray('Out buffer', byteArr);
	        return tmp;
	    }
	}

	function hookDoFinal4() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
	    cipherInit.implementation = function (a1, a2) {
	        console.log("[Cipher.doFinal4()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', a1.array());
	        var tmp = this.doFinal(a1, a2);
	        dumpByteArray('Out buffer', a2.array());
	        return tmp;
	    }
	}

	function hookDoFinal5() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int');
	    cipherInit.implementation = function (byteArr, a1, a2) {
	        console.log("[Cipher.doFinal5()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.doFinal(byteArr, a1, a2);
	        dumpByteArray('Out buffer', tmp);
	        return tmp;
	    }
	}

	function hookDoFinal6() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B');
	    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
	        console.log("[Cipher.doFinal6()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.doFinal(byteArr, a1, a2, outputArr);
	        dumpByteArray('Out buffer', outputArr);

	        return tmp;
	    }
	}

	function hookDoFinal7() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B', 'int', 'int', '[B', 'int');
	    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
	        console.log("[Cipher.doFinal7()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.doFinal(byteArr, a1, a2, outputArr, a4);
	        dumpByteArray('Out buffer', outputArr);
	        return tmp;
	    }
	}

	/*
	    .overload('[B')
	    .overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer')
	    .overload('[B', 'int', 'int')
	    .overload('[B', 'int', 'int', '[B')
	    .overload('[B', 'int', 'int', '[B', 'int')
	*/
	function hookUpdate() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B');
	    cipherInit.implementation = function (byteArr) {
	        console.log("[Cipher.update()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.update(byteArr);
	        dumpByteArray('Out buffer', tmp);
	        return tmp;
	    }
	}

	function hookUpdate2() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer');
	    cipherInit.implementation = function (byteArr, outputArr) {
	        console.log("[Cipher.update2()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr.array());
	        var tmp = this.update(byteArr, outputArr);
	        dumpByteArray('Out buffer', outputArr.array());
	        return tmp;
	    }
	}

	function hookUpdate3() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int');
	    cipherInit.implementation = function (byteArr, a1, a2) {
	        console.log("[Cipher.update3()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.update(byteArr, a1, a2);
	        dumpByteArray('Out buffer', tmp);
	        return tmp;
	    }
	}

	function hookUpdate4() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B');
	    cipherInit.implementation = function (byteArr, a1, a2, outputArr) {
	        console.log("[Cipher.update4()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.update(byteArr, a1, a2, outputArr);
	        dumpByteArray('Out buffer', outputArr);
	        return tmp;
	    }
	}

	function hookUpdate5() {
	    var cipherInit = Java.use('javax.crypto.Cipher')['update'].overload('[B', 'int', 'int', '[B', 'int');
	    cipherInit.implementation = function (byteArr, a1, a2, outputArr, a4) {
	        console.log("[Cipher.update5()]: " + "  cipherObj: " + this);
	        dumpByteArray('In buffer', byteArr);
	        var tmp = this.update(byteArr, a1, a2, outputArr, a4);
	        dumpByteArray('Out buffer', outputArr);
	        return tmp;
	    }
	}

	function decodeMode(mode) {
	    if (mode == 1)
	        return "Encrypt mode";
	    else if (mode == 2)
	        return "Decrypt mode";
	    else if (mode == 3)
	        return "Wrap mode";
	    else if (mode == 4)
	        return "Unwrap mode";
	}

	/* All below is hexdump implementation, changed in order to encode in Base64 */
	function dumpByteArray(title, byteArr) {
	    if (byteArr != null) {
	        try {
	            var buff = new ArrayBuffer(byteArr.length)
	            var dtv = new DataView(buff)
	            for (var i = 0; i < byteArr.length; i++) {
	                dtv.setUint8(i, byteArr[i]); // Frida sucks sometimes and returns different byteArr.length between ArrayBuffer(byteArr.length) and for(..; i < byteArr.length;..). It occured even when Array.copyOf was done to work on copy.
	            }
	            console.log(title + ":\n");
	            //console.log(hexdumpJS(dtv.buffer, 0, byteArr.length))
	            console.log(base64ArrayBuffer(dtv.buffer));
	        } catch (error) { console.log("Exception has occured in hexdump") }
	    }
	    else {
	        console.log("byteArr is null!");
	    }
	}


	function base64ArrayBuffer(arrayBuffer) {
	  var base64    = ''
	  var encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

	  var bytes         = new Uint8Array(arrayBuffer)
	  var byteLength    = bytes.byteLength
	  var byteRemainder = byteLength % 3
	  var mainLength    = byteLength - byteRemainder

	  var a, b, c, d
	  var chunk

	  // Main loop deals with bytes in chunks of 3
	  for (var i = 0; i < mainLength; i = i + 3) {
	    // Combine the three bytes into a single integer
	    chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]

	    // Use bitmasks to extract 6-bit segments from the triplet
	    a = (chunk & 16515072) >> 18 // 16515072 = (2^6 - 1) << 18
	    b = (chunk & 258048)   >> 12 // 258048   = (2^6 - 1) << 12
	    c = (chunk & 4032)     >>  6 // 4032     = (2^6 - 1) << 6
	    d = chunk & 63               // 63       = 2^6 - 1

	    // Convert the raw binary segments to the appropriate ASCII encoding
	    base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d]
	  }

	  // Deal with the remaining bytes and padding
	  if (byteRemainder == 1) {
	    chunk = bytes[mainLength]

	    a = (chunk & 252) >> 2 // 252 = (2^6 - 1) << 2

	    // Set the 4 least significant bits to zero
	    b = (chunk & 3)   << 4 // 3   = 2^2 - 1

	    base64 += encodings[a] + encodings[b] + '=='
	  } else if (byteRemainder == 2) {
	    chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1]

	    a = (chunk & 64512) >> 10 // 64512 = (2^6 - 1) << 10
	    b = (chunk & 1008)  >>  4 // 1008  = (2^6 - 1) << 4

	    // Set the 2 least significant bits to zero
	    c = (chunk & 15)    <<  2 // 15    = 2^4 - 1

	    base64 += encodings[a] + encodings[b] + encodings[c] + '='
	  }
	  
	  return base64
	}



	/* 
	    PBEKeySpec tracer allows to see parameters (including password) from which PBKDF keys are generated  
	*/

	Java.perform(function () {
	    //hookSecretKeyFactory_getInstance();
	    hookPBEKeySpec();
	    hookPBEKeySpec2();
	    hookPBEKeySpec3();    
	});

	console.log("SecretKeyFactory hooks loaded!");


	var cipherList = [];
	var StringCls = null;
	Java.perform(function () {
	    StringCls = Java.use('java.lang.String');
	});

	function hookSecretKeyFactory_getInstance()
	{
	    var func = Java.use('javax.crypto.SecretKeyFactory')['getInstance'];
	    func.implementation = function(flag) {
	        console.log("[SecretKeyFactory.getInstance()]: flag: " + flag );
	        return this.getInstance(flag);
	    }   
	}

	/*
	    .overload('[C')
	    .overload('[C', '[B', 'int')
	    .overload('[C', '[B', 'int', 'int')
	*/
	function hookPBEKeySpec()
	{
	    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C');
	    PBEKeySpec.implementation = function(pass) {
	        console.log("[PBEKeySpec.PBEKeySpec()]: pass: " + charArrayToString(pass) );
	        return this.$init(pass);
	    }   
	}

	function hookPBEKeySpec2()
	{
	    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int');
	    PBEKeySpec.implementation = function(pass, salt, iter) {
	        console.log("[PBEKeySpec.PBEKeySpec2()]: pass: " + charArrayToString(pass)  +  " iter: "+iter);
	        dumpByteArray("salt",salt)
	        return this.$init(pass,salt,iter);
	    }   
	}

	function hookPBEKeySpec3()
	{
	    var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec')['$init'].overload('[C', '[B', 'int', 'int');
	    PBEKeySpec.implementation = function(pass, salt, iter, keyLength) {
	        console.log("[PBEKeySpec.PBEKeySpec3()]: pass: " + charArrayToString(pass)  +  " iter: "+iter + " keyLength: "+keyLength);
	        dumpByteArray("salt",salt)
	        return this.$init(pass,salt,iter,keyLength);
	    }   
	}

	function charArrayToString(charArray)
	{
	    if(charArray == null)
	        return '(null)';
	    else
	        return StringCls.$new(charArray); 
	}

}



function auxiliary_android_pinning_hooks() {

	var okhttp3_CertificatePinner_class = null;
	try {
        okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');    
    } catch (err) {
        console.log('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
        okhttp3_CertificatePinner_class = null;
    }

    if(okhttp3_CertificatePinner_class != null) {

        try{
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str,list) {
                console.log('[+] Bypassing OkHTTPv3 1: ' + str);
                return true;
            };
            console.log('[+] Loaded OkHTTPv3 hook 1');
        } catch(err) {
        	console.log('[-] Skipping OkHTTPv3 hook 1');
        }

        try{
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str,cert) {
                console.log('[+] Bypassing OkHTTPv3 2: ' + str);
                return true;
            };
            console.log('[+] Loaded OkHTTPv3 hook 2');
        } catch(err) {
        	console.log('[-] Skipping OkHTTPv3 hook 2');
        }

        try {
            okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str,cert_array) {
                console.log('[+] Bypassing OkHTTPv3 3: ' + str);
                return true;
            };
            console.log('[+] Loaded OkHTTPv3 hook 3');
        } catch(err) {
        	console.log('[-] Skipping OkHTTPv3 hook 3');
        }

        try {
            okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str,obj) {
	            console.log('[+] Bypassing OkHTTPv3 4 (4.2+): ' + str);
	        };
	        console.log('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
	    } catch(err) {
        	console.log('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
        }

	}

    // Trustkit (triple bypass)
    var trustkit_Activity = null;
    try {
        trustkit_Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        console.log('[+] Setup Trustkit pinning (first class)')
    } catch (err) {
        console.log('[-] Trustkit first class not found. Skipping.');
        trustkit_Activity = null;
    }

    if(trustkit_Activity != null) {

	    try {
	        trustkit_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str,b) {
	            console.log('[+] Intercepted Trustkit {1}: ' + str);
	            return true;
	        };
	    } catch(err) {
	    	console.log('[-] Skipping Trustkit {1}');
	    }

	    try {
	        trustkit_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str,b) {
	            console.log('[+] Intercepted Trustkit {2}: ' + str);
	            return true;
	        };
	    } catch(err) {
	    	console.log('[-] Skipping Trustkit {2}');
	    }

	}

    try {  
        var trustkit_PinningTrustManager = Java.use('com.datatheorem.android.trustkit.pinning.PinningTrustManager');
        trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
            console.log('[+] Intercepted Trustkit {3}');
        }
        console.log('[+] Setup Trustkit pinning (second class)')
    } catch (err) {
        console.log('[-] Trustkit second class not found. Skipping.');
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
    var worklight_Activity = null;
    try {
        worklight_Activity = Java.use('com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning');
    } catch (err) {
        console.log('[-] IBM WorkLight HostNameVerifierWithCertificatePinning class not found. Skipping.');
        worklight_Activity = null;
    }

    if(worklight_Activity != null) {

    	try {
	        worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSocket').implementation = function (str,b) {
	            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + str);
	            return;
	        };
		} catch(err) {
        	console.log('[-] Skipping IBM WorkLight hook 1');
        }

        try {
	        worklight_Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function (str,b) {
	            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {2}: ' + str);
	            return;
	        };
		} catch(err) {
        	console.log('[-] Skipping IBM WorkLight hook 2');
        }	       

        try {
	        worklight_Activity.verify.overload('java.lang.String', 'java.util.List', 'java.util.List').implementation = function (str,b,c) {
	            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {3}: ' + str);
	            return;
	        };
		} catch(err) {
        	console.log('[-] Skipping IBM WorkLight hook 3');
        }		        

        try {
	        worklight_Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (str,b) {
	            console.log('[+] Intercepted IBM WorkLight HostNameVerifierWithCertificatePinning {4}: ' + str);
	            return true;
	        };
		} catch(err) {
        	console.log('[-] Skipping IBM WorkLight hook 4');
        }

        console.log('[+] Setup IBM WorkLight HostNameVerifierWithCertificatePinning pinning')

	}

}


// Auxiliary functions for keystore hooks/functions
function dumpProtectionParameter(protection) {
	if (protection != null) {
		// android.security.keystore.KeyProtection, java.security.KeyStore.CallbackHandlerProtection, java.security.KeyStore.PasswordProtection, android.security.KeyStoreParameter 
		var protectionCls = protection.$className;
		if (protectionCls.localeCompare("android.security.keystore.KeyProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.CallbackHandlerProtection") == 0) {
			return "" + protectionCls + " [implement dumping if needed]";
		}
		else if (protectionCls.localeCompare("java.security.KeyStore.PasswordProtection") == 0) {
			getPasswordMethod = Java.use('java.security.KeyStore.PasswordProtection')['getPassword'];
			password = getPasswordMethod.call(protection);
			return "password: " + charArrayToString(password);
		}
		else if (protectionCls.localeCompare("android.security.KeyStoreParameter") == 0) {
			isEncryptionRequiredMethod = Java.use('android.security.KeyStoreParameter')['isEncryptionRequired'];
			result = isEncryptionRequiredMethod.call(protection);
			return "isEncryptionRequired: " + result;
		}
		else
			return "Unknown protection parameter type: " + protectionCls;
	}
	else
		return "null";

}

function dumpKeyStoreEntry(entry) {
	// java.security.KeyStore$PrivateKeyEntry, java.security.KeyStore$SecretKeyEntry, java.security.KeyStore$TrustedCertificateEntry, android.security.WrappedKeyEntry 
	if (entry != null) {
		var entryCls = entry.$className;
		var castedEntry = Java.cast(entry, Java.use(entryCls));
		if (entryCls.localeCompare("java.security.KeyStore$PrivateKeyEntry") == 0) {
			var getPrivateKeyEntryMethod = Java.use('java.security.KeyStore$PrivateKeyEntry')['getPrivateKey'];
			var key = getPrivateKeyEntryMethod.call(castedEntry);

			return "" + entryCls + " [implement key dumping if needed] " + key.$className;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$SecretKeyEntry") == 0) {
			var getSecretKeyMethod = Java.use('java.security.KeyStore$SecretKeyEntry')['getSecretKey'];
			var key = getSecretKeyMethod.call(castedEntry);
			var keyGetFormatMethod = Java.use(key.$className)['getFormat'];
			var keyGetEncodedMethod = Java.use(key.$className)['getEncoded'];
			//console.log(""+key.$className);
			if (key.$className.localeCompare("android.security.keystore.AndroidKeyStoreSecretKey") == 0)
				return "keyClass: android.security.keystore.AndroidKeyStoreSecretKey can't dump";
			return "keyFormat: " + keyGetFormatMethod.call(key) + ", encodedKey: '" + keyGetEncodedMethod.call(key) + "', key: " + key;
		}
		else if (entryCls.localeCompare("java.security.KeyStore$TrustedCertificateEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else if (entryCls.localeCompare("android.security.WrappedKeyEntry") == 0) {
			return "" + entryCls + " [implement key dumping if needed]";
		}
		else
			return "Unknown key entry type: " + entryCls;
	}
	else
		return "null";
}



/*
* Dump all aliasses in keystore of given 'type'. 
* Example: ListAliasesType('AndroidKeyStore');
*/
function ListAliasesType(type) {
	var result = [];
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyStoreObj = keyStoreCls.getInstance(type);
		keyStoreObj.load(null);
		var aliases = keyStoreObj.aliases();
		//console.log("aliases: " + aliases.getClass());
		while (aliases.hasMoreElements()) {
			result.push("'" + aliases.nextElement() + "'");
		}
	});
	return result;
}

/*
* Dump all aliasses for a given keystore object. 
* Example: ListAliasesObj(keystoreObj);
*/
function ListAliasesObj(obj) {
	var result = [];
	Java.perform(function () {
		var aliases = obj.aliases();
		while (aliases.hasMoreElements()) {
			result.push(aliases.nextElement() + "");
		}
	});
	return result;
}

/*
* Retrieve keystore instance from keystoreList
* Example: GetKeyStore("KeyStore...@af102a");
*/
function GetKeyStore(keystoreName) {
	var result = null;
	Java.perform(function () {
		for (var i = 0; i < keystoreList.length; i++) {
			if (keystoreName.localeCompare("" + keystoreList[i]) == 0)
				result = keystoreList[i];
		}
	});
	return result;
}

/*
* Dump keystore key properties in JSON object
* Example: AliasInfo('secret');
*/
function AliasInfo(keyAlias) {
	var result = {};
	Java.perform(function () {
		var keyStoreCls = Java.use('java.security.KeyStore');
		var keyFactoryCls = Java.use('java.security.KeyFactory');
		var keyInfoCls = Java.use('android.security.keystore.KeyInfo');
		var keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
		var keyFactoryObj = null;

		var keyStoreObj = keyStoreCls.getInstance('AndroidKeyStore');
		keyStoreObj.load(null);
		var key = keyStoreObj.getKey(keyAlias, null);
		if (key == null) {
			console.log('key does not exist');
			return null;
		}
		try {
			keyFactoryObj = keyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		} catch (err) {
			keyFactoryObj = keySecretKeyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
		}
		var keyInfo = keyFactoryObj.getKeySpec(key, keyInfoCls.class);
		result.keyAlgorithm = key.getAlgorithm();
		result.keySize = keyInfoCls['getKeySize'].call(keyInfo);
		result.blockModes = keyInfoCls['getBlockModes'].call(keyInfo);
		result.digests = keyInfoCls['getDigests'].call(keyInfo);
		result.encryptionPaddings = keyInfoCls['getEncryptionPaddings'].call(keyInfo);
		result.keyValidityForConsumptionEnd = keyInfoCls['getKeyValidityForConsumptionEnd'].call(keyInfo);
		if (result.keyValidityForConsumptionEnd != null) result.keyValidityForConsumptionEnd = result.keyValidityForConsumptionEnd.toString();
		result.keyValidityForOriginationEnd = keyInfoCls['getKeyValidityForOriginationEnd'].call(keyInfo);
		if (result.keyValidityForOriginationEnd != null) result.keyValidityForOriginationEnd = result.keyValidityForOriginationEnd.toString();
		result.keyValidityStart = keyInfoCls['getKeyValidityStart'].call(keyInfo);
		if (result.keyValidityStart != null) result.keyValidityStart = result.keyValidityStart.toString();
		result.keystoreAlias = keyInfoCls['getKeystoreAlias'].call(keyInfo);
		result.origin = keyInfoCls['getOrigin'].call(keyInfo);
		result.purposes = keyInfoCls['getPurposes'].call(keyInfo);
		result.signaturePaddings = keyInfoCls['getSignaturePaddings'].call(keyInfo);
		result.userAuthenticationValidityDurationSeconds = keyInfoCls['getUserAuthenticationValidityDurationSeconds'].call(keyInfo);
		result.isInsideSecureHardware = keyInfoCls['isInsideSecureHardware'].call(keyInfo);
		result.isInvalidatedByBiometricEnrollment = keyInfoCls['isInvalidatedByBiometricEnrollment'].call(keyInfo);
		try { result.isTrustedUserPresenceRequired = keyInfoCls['isTrustedUserPresenceRequired'].call(keyInfo); } catch (err) { }
		result.isUserAuthenticationRequired = keyInfoCls['isUserAuthenticationRequired'].call(keyInfo);
		result.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfoCls['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keyInfo);
		result.isUserAuthenticationValidWhileOnBody = keyInfoCls['isUserAuthenticationValidWhileOnBody'].call(keyInfo);
		try { result.isUserConfirmationRequired = keyInfoCls['isUserConfirmationRequired'].call(keyInfo); } catch (err) { }
		//console.log(" result: " + JSON.stringify(result));

		//console.log("aliases: " + aliases.getClass());


	});
	return result;
}

/* following function reads an InputStream and returns an ASCII char representation of it */
function readStreamToHex(stream) {
	var data = [];
	var byteRead = stream.read();
	while (byteRead != -1) {
		data.push(('0' + (byteRead & 0xFF).toString(16)).slice(-2));
		/* <---------------- binary to hex ---------------> */
		byteRead = stream.read();
	}
	stream.close();
	return data.join('');
}

function charArrayToString(charArray) {
	if (charArray == null)
		return '(null)';
	else
		return StringCls.$new(charArray);
}


