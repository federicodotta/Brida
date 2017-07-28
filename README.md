<p align="center">
  <img src="https://raw.githubusercontent.com/federicodotta/Brida/master/BridaLogo.png" alt="Brida Logo"/>
</p>

# Brida
Brida is a Burp Suite Extension that, working as a bridge between [Burp Suite](https://portswigger.net/burp/) and [Frida](https://www.frida.re/), lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers.

# Authors
- Piergiovanni Cipolloni, Security Advisor at @ Mediaservice.net
- Federico Dotta, Security Advisor at @ Mediaservice.net

# Contributors
- Maurizio Agazzini, Senior Security Advisory at @ Mediaservice.net

# Brida Idea
This idea is a need that is born during the analysis of some mobile application that use strong symmetric cryptography using random keys, without knowing the correct secret all data was not modifiable via Burp neither with a custom plugin. More generally, applications' logic could be based on cryptographic tokens, it could use a complex challenge-response algorithm as well, and so on. How can we tamper the messages? Most of the times the only viable approach is to decompile/disassemble the application, identify the functions or methods we’re interested in AND re-implement them. This approach is obviously time consuming and not always really viable: i.e. the generation of tokens and/or the encryption routines could be based on cryptographic material strictly tied to the device (state) or stored inside protected areas and thus not directly accessible... That’s when Brida comes in handy: instead of trying to extract keys/certificates and re-writing the routines we’re interested in, why don’t we let the application do the dirty work for us?

# Installation
1.	Install Python 2.7 and Pyro4 (pip install pyro4)
2.	Download Burp Suite: http://portswigger.net/burp/download.html
3.	Install Brida from the BApp Store (not available yet) or follow these steps:
4.	Download the last release of Brida
5.	Open Burp -> Extender -> Extensions -> Add -> Choose BridaXX.jar file
6.	Use Brida to generate stubs for your custom extensions or use Brida directly to call Frida exported functions

# Usage and examples
A brief article containing details on usage and various examples can be found at:  
https://techblog.mediaservice.net/2017/07/brida-advanced-mobile-application-penetration-testing-with-frida/

# Screenshot
![Brida Screenshot](https://raw.githubusercontent.com/federicodotta/Brida/master/BridaScreen1.PNG)

# MIT License

Copyright (c) 2017 Brida  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.




