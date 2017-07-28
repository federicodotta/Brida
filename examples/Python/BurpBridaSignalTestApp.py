from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
import json
import Pyro4
import re
import array

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self,callbacks):
        
        #Set the name of the extension
        callbacks.setExtensionName("Signal Interceptor")
        
        # Save references to useful objects
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Register ourselves as an HttpListener, in this way all requests and responses will be forwarded to us
        callbacks.registerHttpListener(self)    
    

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
                    
        
        if messageIsRequest:
            
            # Get request bytes                
            request = messageInfo.getRequest()
            
            # Get a IRequestInfo object, useful to work with the request
            analyzedRequest = self.helpers.analyzeRequest(request)

            headers = list(analyzedRequest.getHeaders())

            bodyOffset = int(analyzedRequest.getBodyOffset())

            body = request[bodyOffset:]
            bodyString = "".join(map(chr,body))

            if "destinationRegistrationId" in bodyString:

                jsonBody = json.loads(bodyString)

                uri = 'PYRO:BridaServicePyro@localhost:9999'
                pp = Pyro4.Proxy(uri)
                args = []
                args.append("pwned")
                newMessage = pp.callexportfunction('changemessage',args)
                pp._pyroRelease()

                m = re.search(".*content = \"(.*?)\".*", newMessage)
                if m:
                    newMessage = m.group(1)
                    jsonBody["messages"][0]["content"] = newMessage
                    newBodyString = json.dumps(jsonBody)
                    newBodyString = newBodyString.replace("/", "\\/")

                    newRequest = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(newBodyString))

                    messageInfo.setRequest(newRequest)


