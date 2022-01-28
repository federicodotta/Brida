const androidpinningwithca1 = require("./androidDefaultHooks.js").androidpinningwithca1
const androidpinningwithoutca1 = require("./androidDefaultHooks.js").androidpinningwithoutca1
const androidrooting1 = require("./androidDefaultHooks.js").androidrooting1
const androidfingerprintbypass1 = require("./androidDefaultHooks.js").androidfingerprintbypass1
const androidfingerprintbypass2hook = require("./androidDefaultHooks.js").androidfingerprintbypass2hook
const androidfingerprintbypass2function = require("./androidDefaultHooks.js").androidfingerprintbypass2function
const tracekeystore = require("./androidDefaultHooks.js").tracekeystore
const listaliasesstatic = require("./androidDefaultHooks.js").listaliasesstatic
const listaliasesruntime = require("./androidDefaultHooks.js").listaliasesruntime
const dumpcryptostuff = require("./androidDefaultHooks.js").dumpcryptostuff
const ios10pinning = require("./iosDefaultHooks.js").ios10pinning
const ios11pinning = require("./iosDefaultHooks.js").ios11pinning
const ios12pinning = require("./iosDefaultHooks.js").ios12pinning
const ios13pinning = require("./iosDefaultHooks.js").ios13pinning
const iosbypasstouchid = require("./iosDefaultHooks.js").iosbypasstouchid
const iosjailbreak = require("./iosDefaultHooks.js").iosjailbreak
const iosdumpkeychain = require("./iosDefaultHooks.js").iosdumpkeychain
const iosdataprotectionkeys = require("./iosDefaultHooks.js").iosdataprotectionkeys
const iosdumpcurrentencryptedapp = require("./iosDefaultHooks.js").iosdumpcurrentencryptedapp
const dumpcryptostuffios = require("./iosDefaultHooks.js").dumpcryptostuffios
const demangle = require("./iosDefaultHooks.js").demangle
const getallclasses = require("./bridaFunctions").getallclasses
const getallmodules = require("./bridaFunctions").getallmodules
const getmoduleimports = require("./bridaFunctions").getmoduleimports
const getmoduleexports = require("./bridaFunctions").getmoduleexports
const getclassmethods = require("./bridaFunctions").getclassmethods
const findobjcmethods = require("./bridaFunctions").findobjcmethods
const findjavamethods = require("./bridaFunctions").findjavamethods
const findimports = require("./bridaFunctions").findimports
const findexports = require("./bridaFunctions").findexports
const detachall = require("./bridaFunctions").detachall
const trace = require("./bridaFunctions").trace
const changereturnvalue = require("./bridaFunctions").changereturnvalue
const getplatform = require("./bridaFunctions").getplatform

// Brida User file: use this file to insert your Frida exports/hooks/functions.
// Do not remove existing code (it is necessary for Brida)

rpc.exports = {
	androidpinningwithca1, androidpinningwithoutca1, androidrooting1, 
    androidfingerprintbypass1, androidfingerprintbypass2hook, 
    androidfingerprintbypass2function, tracekeystore, listaliasesstatic, 
    listaliasesruntime, dumpcryptostuff,
	ios10pinning, ios11pinning, ios12pinning, ios13pinning, 
    iosbypasstouchid, iosjailbreak, iosdumpkeychain, iosdataprotectionkeys, 
    iosdumpcurrentencryptedapp, dumpcryptostuffios, demangle,
	getallclasses, getallmodules, getmoduleimports, getmoduleexports, 
    getclassmethods, findobjcmethods, findjavamethods, findimports, 
    findexports, detachall, trace, changereturnvalue, getplatform,

	// BE CAREFUL: Do not use uppercase characters in exported function name (automatically converted lowercase by Pyro)
	exportedfunction: function() {

		// Do stuff...	
		// This functions can be called from custom plugins

	}

	// Put here the exported functions called by your custom plugins

}

// Put here you Frida hooks!

//if(ObjC.available) {
//if(Java.available) {
	
	// ...

//}



// Auxiliary functions - You can remove them if you don't need them!

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
