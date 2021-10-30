export function demangle(name) {

	var _swift_demangle = null
	var _free = null

	if(ObjC.available) {

		// Is Swift available?
		var tmp = Module.findBaseAddress("libswiftCore.dylib");

	    if (tmp != null) {
	        var addr_swift_demangle = Module.getExportByName("libswiftCore.dylib", "swift_demangle");
	        var size_t = Process.pointerSize === 8 ? 'uint64' : Process.pointerSize === 4 ? 'uint32' : "unsupported platform";
	        _swift_demangle = new NativeFunction(addr_swift_demangle, "pointer", ["pointer", size_t, "pointer", "pointer", 'int32']);
	        var addr_free = Module.getExportByName("libsystem_malloc.dylib", "free");
	        _free = new NativeFunction(addr_free, "void", ["pointer"]);
	    
	    } 

	}

    if (_swift_demangle != null) {            

        var fixname = name;

        var cStr = Memory.allocUtf8String(fixname);

        var demangled = _swift_demangle(cStr, fixname.length, ptr(0), ptr(0), 0);

        var res = null;

        if (demangled) {
            res = demangled.readUtf8String();

            _free(demangled);
        }

        if (res && res != fixname) {
            return res;
        } else {
        	return "Requested resource cannot be demangled";
        }

    } else {

        return "Cant' demangle. Swift native function not found.";

    }

}

export function ios10pinning() {

	var tls_helper_create_peer_trust = new NativeFunction(
		Module.findExportByName(null, "tls_helper_create_peer_trust"),
		'int', ['pointer', 'bool', 'pointer']
		);

	var errSecSuccess = 0;

	Interceptor.replace(tls_helper_create_peer_trust, new NativeCallback(function(hdsk, server, trustRef) {
	    return errSecSuccess;
	}, 'int', ['pointer', 'bool', 'pointer']));
	console.log("SSL certificate validation bypass active");

}

export function ios11pinning() {

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

}

export function ios12pinning() {

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

}

export function ios13pinning() {

	try {
		Module.ensureInitialized("libboringssl.dylib");
	} catch(err) {
		console.log("libboringssl.dylib module not loaded. Trying to manually load it.")
		Module.load("libboringssl.dylib");	
	}

	var SSL_VERIFY_NONE = 0;
	var ssl_set_custom_verify;
	var ssl_get_psk_identity;	

	ssl_set_custom_verify = new NativeFunction(
		Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
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

	Interceptor.replace(ssl_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
		//  |callback| performs the certificate verification. Replace this with our custom callback
		ssl_set_custom_verify(ssl, mode, ssl_verify_result_t);
	}, 'void', ['pointer', 'int', 'pointer']));

	Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
		return "notarealPSKidentity";
	}, 'pointer', ['pointer']));
		
	console.log("[+] Bypass successfully loaded ");		

}

export function iosbypasstouchid() {

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

}

export function iosjailbreak() {

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

} 

export function iosdumpkeychain() {

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

}

export function iosdataprotectionkeys() {

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

}

export function iosdumpcurrentencryptedapp() {

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

}


export function dumpcryptostuffios() {

	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCrypt"),
	  {
	    onEnter: function(args) {

	        console.log("*** ENTER CCCrypt ****");
	        console.log("CCOperation: " + parseInt(args[0]));
	        console.log("CCAlgorithm: " + parseInt(args[1]));
	        console.log("CCOptions: " + parseInt(args[2]));
	        
	        if(ptr(args[3]) != 0 ) {
	        	console.log("Key:");
	        	console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))));
		    } else {
		    	console.log("Key: 0");
		    }

		    if(ptr(args[5]) != 0 ) {
	        	console.log("IV:");
	        	console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)));
		    } else {
		    	console.log("IV: 0");
		    }

	        this.dataInLength = parseInt(args[7]);

	        if(ptr(args[6]) != 0 ) {

	        	console.log("Data in ****:");
	        	console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[6]),this.dataInLength)));

		    } else {
		    	console.log("Data in: null");
		    }

	        this.dataOut = args[8];
	        this.dataOutLength = args[10];

	    },

	    onLeave: function(retval) {

	        if(ptr(this.dataOut) != 0 ) {
		        console.log("Data out");
		        console.log(base64ArrayBuffer(Memory.readByteArray(this.dataOut,parseInt(ptr(Memory.readU32(ptr(this.dataOutLength),4))))));

		    } else {
		    	console.log("Data out: null");
		    }

		    console.log("*** EXIT CCCrypt ****");
	        
	    }

	});

	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorCreate"),
	  {
	    onEnter: function(args) {

	        console.log("*** CCCryptorCreate ENTER ****");
	        console.log("CCOperation: " + parseInt(args[0]));
	        console.log("CCAlgorithm: " + parseInt(args[1]));
	        console.log("CCOptions: " + parseInt(args[2]));

	        if(ptr(args[3]) != 0 ) {
	        	console.log("Key:");
	        	console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[3]),parseInt(args[4]))));

		    } else {
		    	console.log("Key: 0");
		    }

		    if(ptr(args[5]) != 0 ) {
	        	console.log("IV:");
		        console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[5]),16)));
		    } else {
		    	console.log("IV: 0");
		    }

	    },
	    onLeave: function(retval) {
	    	console.log("*** CCCryptorCreate EXIT ****");
	    }

	});

	
	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorUpdate"),
	  {
	    onEnter: function(args) {
	    	console.log("*** CCCryptorUpdate ENTER ****");
	    	if(ptr(args[1]) != 0) {
		        console.log("Data in:");
		        console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));

		    } else {
		    	console.log("Data in: null");
		    }

	        //this.len = args[4];
	        this.len = args[5];
	        this.out = args[3];

	    },

	    onLeave: function(retval) {

	    	if(ptr(this.out) != 0) {
		    	console.log("Data out CCUpdate:");
		    	console.log(base64ArrayBuffer(Memory.readByteArray(this.out,parseInt(ptr(Memory.readU32(ptr(this.len),4))))));

		    } else {
		    	console.log("Data out: null");
		    }
		    console.log("*** CCCryptorUpdate EXIT ****");
	    }

	});

	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CCCryptorFinal"),
	  {
	    onEnter: function(args) {
	    	console.log("*** CCCryptorFinal ENTER ****");
	        //this.len2 = args[2];
	        this.len2 = args[3];
	        this.out2 = args[1];
	    },
	    onLeave: function(retval) {
	    	if(ptr(this.out2) != 0) {
		    	console.log("Data out CCCryptorFinal:");
		    	console.log(base64ArrayBuffer(Memory.readByteArray(this.out2,parseInt(ptr(Memory.readU32(ptr(this.len2),4))))));

		    } else {
		    	console.log("Data out: null")
		    }
		    console.log("*** CCCryptorFinal EXIT ****");
	    }

	});

	//CC_SHA1_Init(CC_SHA1_CTX *c);
	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Init"),
	{
	  onEnter: function(args) {
	  	console.log("*** CC_SHA1_Init ENTER ****");	  	
	  	console.log("Context address: " + args[0]);	   
	  }
	});

	//CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len);
	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Update"),
	{
	  onEnter: function(args) {
	  	console.log("*** CC_SHA1_Update ENTER ****");
	  	console.log("Context address: " + args[0]);
	  	if(ptr(args[1]) != 0) {
		  	console.log("data:");
			console.log(base64ArrayBuffer(Memory.readByteArray(ptr(args[1]),parseInt(args[2]))));
		} else {
			console.log("data: null");
		}
	  }
	});

	//CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c);
	Interceptor.attach(Module.findExportByName("libSystem.B.dylib","CC_SHA1_Final"),
	{
	  onEnter: function(args) {
	  	this.mdSha = args[0];
	  	this.ctxSha = args[1];
	  },
	  onLeave: function(retval) {
	  	console.log("*** CC_SHA1_Final ENTER ****");
	  	console.log("Context address: " + this.ctxSha);
	  	if(ptr(this.mdSha) != 0) {
		  	console.log("Hash:");
		  	console.log(base64ArrayBuffer(Memory.readByteArray(ptr(this.mdSha),20)));

		} else {
			console.log("Hash: null");
		}	
	  }
	});

	// Native ArrayBuffer to Base64
	// https://gist.github.com/jonleighton/958841
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

}
