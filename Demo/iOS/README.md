# iOS Demo

In this folder there is the iOS demo application used to show Brida features during **Hack In The Box 2018 Amsterdam** and **Hack In Paris 2021** conferences. 

I published both the versions but it is the same applications with different logos.

The backend is a Spring Boot application that communicates with a MySQL database on localhost (default port 3306). The application logs in in the database using username root with empty password (I know, very very bad), so maybe run it on a firewalled system/VM ;)

The code of the demo applications and of the backend have been developed very fast and can include tons of errors/vulnerabilities/etc. Consider it before letting them run in a publicly exposed server! Forgive us, it is a demo! ;)

## Run the demo

1. Install one of the two demo applications on the device. If the device is not jailbroken the application must be resigned in order to work.
2. Start MySQL/MariaDB database and import the supplied "dbBackendBridaDemo.db" file

	```mysql -u root -p < dbBackendBridaDemo.db```

3. Run the Spring Boot server application (it may not work with last versions of Java. It works well with Java 8)

	```java -jar BridaTestAppBackend-0.0.1-SNAPSHOT.jar --server.port=8081```

4. Run the demo application. 
5. Set the IP address and port of the server application in the "Settings" tab and click on "Save settings"
6. Now the demo should work correctly

## Load Brida plugins

1. Configure Brida (refer to the [documentation](https://github.com/federicodotta/Brida/wiki/Start) for details). The application ID of the demo is **org.hitb.BridaDemo**
2. Click on the "Select folder" button of the "Frida JS files folder" and select the supplied "DemoIOSFridaJS" folder
3. Load the plugins, by clicking on the button "Import plugins" in the "Custom plugins" tab and choosing the supplied "exportedPluginsDemoIOS.csv" file
4. Enable the plugin(s) you want to try using the corresponding "Enable" button in the same tab
5. Spawn/attach the application

## Supplied Brida plugins

The following Brida plugin can be used to handle the encryption in the **Search** tab of the demo iOS application. Encryption is also used in the **Login** tab of the demo and the Frida exported function to handle it is present in the supplied JS Brida files. Plugins for the Login functionality can be created using the same approach of the Search ones (by clicking on "Edit" on a plugin it is possible to see all the plugin configurations).

1. **Search_DecryptContext**: adds an entry to the context menu that decrypts the higlighted value using Brida, replacing it with its decrypted form, if possible. If the highlighted value is in a non-editable pane, a pop-up appears
2. **Search_EncryptContext**: adds an entry to the context menu that encrypts the higlighted value using Brida, replacing it with its encrypted form, if possible. If the highlighted value is in a non-editable pane, a pop-up appears
3. **Search_TrasparentEncryption**: when it is enabled, it encrypts transparently the bodies of all requests generated from the Scanner, the Repeater and the Intruder Burp Suite tools (but it can be edited to add other Burp Suite tools). It can be used by sending a request to the Intruder/Scanner/Repeater **with the body already decrypted**. In this way Burp Suite/the pentester can adds his payloads and the body will be transparently encrypted by Brida before the transmission to the backend
4. **Search_TrasparentDecryption**: when it is enabled, it decrypts transparently the bodies of all responses received by the Scanner, the Repeater and the Intruder Burp Suite tools (but it can be edited to add other Burp Suite tools). It can be used in conjunction with the previous plugin to have the body of the HTTP responses decrypted in the Scanner, in the Repeater and in the Intruder tools, allowing Burp Suite or the pentester to understand if the attack vector succeeded in an easy way
5. **Search_MessageEditorTabRequests**: it adds a message editor tab to HTTP requests, that shows the decrypted form of the body of the current HTTP message. If the tab is editable and the decrypted value is modified, Brida replace the original body with a new one containing the encrypted modified body
6. **Search_MessageEditorTabResponses**: it adds a message editor tab to HTTP responses, that shows the decrypted form of the body of the current HTTP message. If the tab is editable and the decrypted value is modified, Brida replace the original body with a new one containing the encrypted modified body

## Old Brida plugins

In the **OldCompiledPlugins** folder a compiled version of a couple plugins has been supplied (both source code and builds). Brida from version **0.4** has the **Custom plugins** tab that can be used to create Brida plugins directly from the Brida graphical interfaces, without the need to code. In the previous versions of Brida it was necessary to code Brida plugins (in Java or Python). It is still possible to code Brida plugins, feature that can be useful in complex scenarios in which we need to code specific behaviours.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.