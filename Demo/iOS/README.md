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


## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.