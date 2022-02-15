# Android Demo

In this folder there is the Android demo application used to show Brida features during **Hack In Paris 2021** conference. 

The backend is a simple Flask Python application.

The application implements **TLS Pinning** and **Hostname validation**, that can be bypassed using Brida scripts. TLS Pinning can be bypassed using the two pinning bypass scripts that can be enabled in the "Hooks and functions" tab. Hostname validation script has been directly included in the Brida code supplied with the demo (it can also be enabled in the "Hooks and functions" tab present in the last Git Brida code).

## Run the Flask backend

1. Install dependencies (pycypto should be installed **before** pycryptodome, otherwise exceptions can occur)

	```
	pip install flask
	pip install pycrypto
	pip install pycryptodome
	```

2. Run the server

	```
	export FLASK_APP=server
	export FLASK_ENV=development
	flask run --cert=certs/server-cert.pem --key=certs/server-key.pem -h <IP_ADDRESS_TO_BIND> -p <PORT_TO_BIND>
	```

## Run the application

1. Install APK
2. Run the application
3. Set the URL of the backend in the upper part

**Note**: it is necessary to bypass pinning and hostname validation in order to be able to use the application. If you want to try the application without Burp Suite in the middle and without bypassing the pinning read the paragraph "Make the application work without bypassing the pinning and without Burp Suite in the middle" (**not** necessary to use the demo).

## Load Brida plugins

1. Configure Brida (refer to the [documentation](https://github.com/federicodotta/Brida/wiki/Start) for details). The application ID of the demo is **com.dombroks.android_flask**
2. Click on the "Select folder" button of the "Frida JS files folder" and select the supplied "DemoAndroidFridaJS" folder
3. Enable **one of** the Brida pinning bypass in the "Hooks and functions" -> "Android" section
4. Load the plugins, by clicking on the button "Import plugins" in the "Custom plugins" tab and choosing the supplied "exportedPluginsDemoAndroid.csv" file
5. Enable the plugin(s) you want to try using the corresponding "Enable" button in the same tab
6. Spawn/attach the application

## Supplied Brida plugins

1. **Decrypt_context**: it adds an entry to the context menu that decrypts the higlighted value using Brida, replacing it with its decrypted form, if possible. If the highlighted value is in a non-editable pane, a pop-up appears
2. **Encrypt_context**: it adds an entry to the context menu that encrypts the higlighted value using Brida, replacing it with its encrypted form, if possible. If the highlighted value is in a non-editable pane, a pop-up appears
3. **Decrypt_messageEditorTab**: it adds a message editor tab to HTTP requests and responses, that shows the decrypted form of the body of the current HTTP message. If the tab is editable and the decrypted value is modified, Brida replace the original body with a new one containing the encrypted modified body
4. **EncryptRequest_IHttpListener**: when it is enabled, it encrypts transparently the bodies of all requests generated from the Scanner and the Intruder Burp Suite tools (but it can be edited to add other Burp Suite tools). It can be used by sending a request to the Intruder/Scanner **with the body already decrypted**. In this way Burp Suite can adds his payloads and the body will be transparently encrypted by Brida before the transmission to the backend
5. **DecryptResponse_IHttpListener**: when it is enabled, it decrypts transparently the bodies of all responses received by the Scanner and the Intruder Burp Suite tools (but it can be edited to add other Burp Suite tools). It can be used in conjunction with the previous plugin to have the body of the HTTP responses decrypted in the Scanner and in the Intruder tools, allowing Burp Suite or the pentester to understand if the attack vector succeeded in an easy way
6. **Decrypt_button**: it adds a button to the "Hooks and functions" -> "Android" section that decrypt the supplied input
7. **Encrypt_button**: it adds a button to the "Hooks and functions" -> "Android" section that encrypt the supplied input

## Make the application work without bypassing the pinning and without Burp Suite in the middle

If you really want to try the demo application without bypassing the pinning (and consequently also without Burp Suite in the middle), you can install the CA we used to sign the server certificate and add "demo.hnsecfakedomain.it" to the /etc/hosts file of the device (because otherwise TLS hostname check will fail). 

**Note**: it is **not** necessary to execute this procedure to run the demo. Simply run the application and use Brida or something else to bypass TLS checks! ;)

1. Install the supplied CA certificate (*certs/9e487db2.0* is the DER convertion of *certs/ca-cert.pem* with the correct name for installing in Android with the following procedure) in your device (**PAY ATTENTION: remove that CA certificate after using the demo**)

	This procedure can be executed in many ways. One is the following one. **Pay attention if you don't understand what you are doing because you may damage your device!**

	```
	adb push 9e487db2.0 /data/local/tmp
	adb shell
	```

	From the device:

	```
	su
	mount -o rw,remount /system
	cp /data/local/tmp/9e487db2.0 /system/etc/security/cacerts/
	chmod 644 /system/etc/security/cacerts/9e487db2.0
	chown root:root /system/etc/security/cacerts/9e487db2.0
	sync
	mount -o ro,remount /system
	reboot
	```

2. Add demo.hnsecfakedomain.it to the /etc/hosts file of your Android device (necessary, otherwise hostname TLS checks will fail)

	```
	su
	mount -o rw,remount /system
	cat >> /system/etc/hosts
	```
	
	Now type and entry of the hosts that points to demo.hnsecfakedomain.it (es. 192.168.12.1 demo.hnsecfakedomain.it) and then exit with CTRL+D. Then:

	```
	sync
	mount -o ro,remount /system
	```

3. Set the URL of the backend in the upper part of the application, using the hostname demo.hnsecfakedomain.it, that now points to your backend server, and the port in which the server is listening

4. 	After you used the demo, the certificate can be removed **from the device** as follows:

	```
	su
	mount -o rw,remount /system
	rm /system/etc/security/cacerts/9e487db2.0
	sync
	mount -o ro,remount /system
	reboot
	```

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.