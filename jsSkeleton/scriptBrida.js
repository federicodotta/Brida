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
		var resolver = new ApiResolver("objc");
		var matches = resolver.enumerateMatches("*[" + classname + " *]", {
			onMatch: function (match) {
				results[match['name']] = match['address'];
			},
			onComplete: function () {
			}
		});
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
	trace: function (pattern,type,backtrace)	{

		var res;
		if(type === "objc_class") {

			res = new ApiResolver("objc");
			pattern = "*[" + pattern + " *]";

		} else if(type === "objc_method") {

			res = new ApiResolver("objc");

		} else {
			// SINGLE EXPORT
			res = new ApiResolver("module");
			pattern = "exports:" + pattern;

		}

		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);

		targets.forEach(function(target) {
			if (type.startsWith("objc"))
				traceObjC(target.address, target.name,backtrace);
			else if (type === "ios_export")
				traceModule(target.address, target.name,backtrace);
		});

	},

	changereturnvalue: function(pattern, type, typeret, newret)	{

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

					} else {

						console.log("*** " + pattern + " Replacing " + retval + " with " + newret);
						retval.replace(newret);

					}

				}

			});

		});			
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
function uniqBy(array, key) 
{
	var seen = {};
	return array.filter(function(item) {
		var k = key(item);
		return seen.hasOwnProperty(k) ? false : (seen[k] = true);
	});
}

// trace ObjC methods
function traceObjC(impl, name, backtrace)
{
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
			console.log("Return value:");
			printArg("retval:" + retval);
			console.log("*** exiting " + name + "\n");

		}

	});
}

// trace Module functions
function traceModule(impl, name, backtrace)
{
	console.log("*** Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			console.log("*** entered " + name);

			if(backtrace === "true") {
				console.log("Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t"));
			}
			
		},

		onLeave: function(retval) {

			console.log("Return value:");
			printArg("retval:" + retval);
			console.log("*** exiting " + name + "\n");
			
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

// 3 - FRIDA HOOKS (if needed)

if(ObjC.available) {
	
	// Insert here Frida interception methods, if needed 
	// (es. Bypass Pinning, save values, etc.)

}
