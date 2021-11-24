# Android Demo

In this folder there is the Android demo application used to show Brida features during **Hack In Paris 2021** conference. 

The backend is a simple Flask Python application.

The application implements **SSL Pinning**, that can be bypassed using Brida scripts.

## Run the Flask backend

1. Install dependencies

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

**Note**: it is necessary to bypass pinning in order to be able to use the application. If you want to try the application without Burp Suite in the middle and without bypassing the pinning read the next paragraph.

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