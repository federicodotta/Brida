<p align="center">
  <img src="https://raw.githubusercontent.com/federicodotta/Brida/master/BridaLogo.png" alt="Brida Logo"/>
</p>

# Brida
Brida is a Burp Suite Extension that, working as a bridge between [Burp Suite](https://portswigger.net/burp/) and [Frida](https://www.frida.re/), lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX).

# Authors
- Piergiovanni Cipolloni, Security Advisor at @Mediaservice.net
- Federico Dotta, Security Advisor at @Mediaservice.net

# Contributors
- Maurizio Agazzini, Senior Security Advisor at @Mediaservice.net

# Frida Scripts
The 0.2 version of Brida uses a lot of Frida code for dynamic hooking and for binary inspection, based on the work of:
- Marco Ivaldi
- Maurizio Agazzini
- Luca Baggio

# Brida Idea
This idea is a need that is born during the analysis of some mobile application that use strong symmetric cryptography using random keys, without knowing the correct secret all data was not modifiable via Burp neither with a custom plugin. More generally, applications' logic could be based on cryptographic tokens, it could use a complex challenge-response algorithm as well, and so on. How can we tamper the messages? Most of the times the only viable approach is to decompile/disassemble the application, identify the functions or methods we’re interested in AND re-implement them. This approach is obviously time consuming and not always really viable: i.e. the generation of tokens and/or the encryption routines could be based on cryptographic material strictly tied to the device (state) or stored inside protected areas and thus not directly accessible... That’s when Brida comes in handy: instead of trying to extract keys/certificates and re-writing the routines we’re interested in, why don’t we let the application do the dirty work for us?

# Brida 0.2
Brida 0.2 was presented at Hack In The Box 2018 Amsterdam and includes some new features that speed up dynamical analysis of mobile applications, including:
- An integrated console in which output from all Frida and Brida hooks are printed
- An integrated JS editor with Javascript syntax highlighting, in order to be able to add your own Frida exports and Frida hooks directly from Burp Suite. The JS editor is based on the great [RSyntaxTextArea](https://github.com/bobbylight/RSyntaxTextArea) of bobbylight
- An analysis tab, in which you have a tree rapresentation of the binary (Java/OBJC classes and methods, inports/exports) and from which you can graphically add inspection hoooks (that print arguments and return value every time that the hooked function is executed) and tamper hooks (that dinamically change the return value of the hooked function every time that it is executed)

# Requirements
In order to be able to use Brida, you need:
1.	Burp Suite
2.	Frida client
3.	Pyro4
4.	A jailbroken iOS device/rooted Android device with frida-server running on it
5.	An application to analyze! :D

Brida can be used also with Frida gadget on a non-jailbroken iOS device. We will soon explain better how to configure the tool in a step-by-step guide also in this particular situation!

# Installation
1.	Install Python 2.7 and Pyro4 (pip install pyro4)
2.	Download Burp Suite: http://portswigger.net/burp/download.html
3.	Download the last release of Brida: https://github.com/federicodotta/Brida/releases
4.	Open Burp -> Extender -> Extensions -> Add -> Choose BridaXX.jar file
5.	Use Brida to generate stubs for your custom extensions or use Brida directly to call Frida exported functions

# Build
You can build Brida using Maven. Brida uses a modified version of RSyntaxTextArea, that you can find in this [fork](https://github.com/federicodotta/RSyntaxTextArea). In order to be ablet to build Brida you have to download the [last release](https://github.com/federicodotta/RSyntaxTextArea/releases) of the modified version of RSyntaxTextArea or build it and then install it locally with Maven using the following parameters:

- groupId: com.fifesoft
- artifactId: rsyntaxtextarea
- version: 2.6.1.edited

# Usage and tutorial
A step-by-step tutorial that explain how to use Brida can be found at:  
- https://techblog.mediaservice.net/2018/04/brida-a-step-by-step-user-guide/

The slides and the video of our conference presented at Hack In The Box 2018 Amsterdam that describes the new features of the version 0.2 can be found at:
- https://conference.hitb.org/hitbsecconf2018ams/materials/D1T1%20-%20Federico%20Dotta%20and%20Piergiovanni%20Cipolloni%20-%20Brida%20When%20Burp%20Suite%20Meets%20Frida.pdf
- https://www.youtube.com/watch?v=wPepicuHDzs&t=18s

# Screenshot
![Brida Screenshot](https://raw.githubusercontent.com/federicodotta/Brida/master/BridaScreen1.PNG)

# MIT License

Copyright (c) 2018 Brida  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.




