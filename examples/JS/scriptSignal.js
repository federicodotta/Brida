'use strict';

var destNum;

// 1 - FRIDA EXPORTS

rpc.exports = {
	
	// Function that generate a new Signal encrypted message.
	// Input: message -> the message to encrypt
	// Output: the encrypted message
	changemessage: function(message) {
	
		var env = ObjC.classes.Environment.getCurrent();
		
		var messageSender = env.messageSender();
		var signalRecipient = ObjC.classes.SignalRecipient.alloc().initWithTextSecureIdentifier_relay_(destNum,null);
		var contactThread = ObjC.classes.TSContactThread.alloc().initWithContactId_(destNum);
	
		var mex = ObjC.classes.TSOutgoingMessage.alloc().initWithTimestamp_inThread_messageBody_(Math.round(+new Date()/1000),null,message);
		
		var retVal = messageSender.deviceMessages_forRecipient_inThread_(mex,signalRecipient,contactThread);				
	
		var retValMessage = retVal.objectAtIndex_(0);

		return retValMessage.toString();

	},
	
	// Function executed when executed Brida contextual menu option 1. It transforms a string in lower case.
	// Input: input string ENCODED IN ASCII HEX
	// Output: lowercase string ENCODED IN ASCII HEX
	contextcustom1: function(message) {
        var a1 = ObjC.classes.NSString.stringWithString_(hexToString(message));
        var a2 = a1.lowercaseString();
        return stringToHex(a2.toString());
    },
	
	// Function executed when executed Brida contextual menu option 2. It encodes input in Base64.
	// Input: input data ENCODED IN ASCII HEX
	// Output: output Base64 string ENCODED IN ASCII HEX
    contextcustom2: function(message) {
		var inputByte = hexToBytes(message);
        var ptrMessage = Memory.alloc(inputByte.length);
		Memory.writeByteArray(ptrMessage,inputByte);
		var objMessage = ObjC.classes.NSData.alloc().initWithBytes_length_(ptrMessage,inputByte.length);
		var encodedMessage = objMessage.base64EncodedString();
		return stringToHex(encodedMessage.toString());
    },
	
	// Function executed when executed Brida contextual menu option 3. It transforms a string in upper case.
	// Input: input string ENCODED IN ASCII HEX
	// Output: uppercase string
	contextcustom3: function(message) {		
		var a1 = ObjC.classes.NSString.stringWithString_(hexToString(message));
        var a2 = a1.uppercaseString();
        return stringToHex(a2.toString());
	},
	
	// Function executed when executed Brida contextual menu option 4. It decodes an input string from Base64.
	// Input: input Base64 string ENCODED IN ASCII HEX
	// Output: output decoded data ENCODED IN ASCII HEX
	contextcustom4: function(message) {
		var a2 = ObjC.classes.NSString.stringWithString_(hexToString(message));
		var encodedString = ObjC.classes.NSData.dataFromBase64String_(a2);
		var ptrBytesReturned = encodedString.bytes();
		var ptrBytesLength = encodedString.length();		
		var bytesReturneded = Memory.readByteArray(ptrBytesReturned, ptrBytesLength);
		return bytesToHex(bytesReturneded);
	},
	
	// Function that transforms a string in upper case.
	// Input: input string
	// Output: uppercase string
	touppercase: function(message) {		
		var a1 = ObjC.classes.NSString.stringWithString_(message);
        var a2 = a1.uppercaseString();
        return a2.toString();
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
};

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

// 3 - FRIDA HOOKS

if(ObjC.available) {
	
	// SAVE MESSAGE RECIPIENT
	var hooksendMessage = ObjC.classes.OWSMessageSender["- sendMessage:recipient:thread:attempts:success:failure:"];
	Interceptor.attach(hooksendMessage.implementation, {
		    onEnter: function(args) {
	
		    	var obj2 = ObjC.Object(args[3]);
				destNum = obj2.recipientId().toString();
				

		    },
		    onLeave: function(retval) {
		    }
	});


	// BYPASS PINNING
	var hookevaluateServerTrust = ObjC.classes.OWSHTTPSecurityPolicy["- evaluateServerTrust:forDomain:"];
	Interceptor.attach(hookevaluateServerTrust.implementation, {
		    onEnter: function(args) {

		    },
		    onLeave: function(retval) {
		    	
				retval.replace(ptr(1));
		    }
	});
	


}