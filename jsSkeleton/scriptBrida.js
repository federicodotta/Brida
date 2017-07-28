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

// 3 - FRIDA HOOKS (if needed)

if(ObjC.available) {
	
	// Insert here Frida interception methods, if needed 
	// (es. Bypass Pinning, save values, etc.)

}
