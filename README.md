<p align="center">
  <img src="https://raw.githubusercontent.com/federicodotta/Brida/master/BridaLogo.png" alt="Brida Logo"/>
</p>

# Brida
Brida is a Burp Suite Extension that, working as a bridge between [Burp Suite](https://portswigger.net/burp/) and [Frida](https://www.frida.re/), lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX).

# Authors
- Federico Dotta, Security Advisor at @Mediaservice.net
- Piergiovanni Cipolloni, Security Advisor at @Mediaservice.net

# Contributors
- Maurizio Agazzini, Senior Security Advisor at @Mediaservice.net

# Frida Scripts
Brida uses a lot of Frida code for dynamic hooking and for binary inspection, based on the work of:
- Marco Ivaldi
- Maurizio Agazzini
- Luca Baggio
- Federico Dotta

Furthermore, Brida 0.4 integrates many Frida hooks developed by various authors to inspect/bypass many security features. A list of projects (I hope quite exhaustive) from which I took Frida code for the "Hooks and functions" section of Brida is (random order):
- Piergiovanni Cipolloni - [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- Mattia Vinci and Maurizio Agazzini - [Universal Android SSL Pinning Bypass 2](https://codeshare.frida.re/@sowdust/universal-android-ssl-pinning-bypass-2/)
- Maurizio Siddu - [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/)
- dzonerzy - [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/)
- F-Secure Labs - [Android KeyStore Audit](https://github.com/FSecureLABS/android-keystore-audit)
- F-Secure Labs - [needle](https://github.com/FSecureLABS/android-keystore-audit)
- Alban Diquet - [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2/)
- dki - [ios10-ssl-bypass](https://codeshare.frida.re/@dki/ios10-ssl-bypass/)
- macho_reverser - [iOS 12 SSL Bypass](https://github.com/machoreverser/Frida-Scripts/blob/master/ssl_bypass.js)
- Chaitin Tech - [Passionfruit](https://github.com/chaitin/passionfruit)
- lich0 - [dump ios](https://codeshare.frida.re/@lichao890427/dump-ios/)
- ay-kay - [iOS DataProtection](https://codeshare.frida.re/@ay-kay/ios-dataprotection/)

# Brida Idea
This idea is a need that is born during the analysis of some mobile application that use strong symmetric cryptography using random keys, without knowing the correct secret all data was not modifiable via Burp neither with a custom plugin. More generally, applications' logic could be based on cryptographic tokens, it could use a complex challenge-response algorithm as well, and so on. How can we tamper the messages? Most of the times the only viable approach is to decompile/disassemble the application, identify the functions or methods we’re interested in AND re-implement them. This approach is obviously time consuming and not always really viable: i.e. the generation of tokens and/or the encryption routines could be based on cryptographic material strictly tied to the device (state) or stored inside protected areas and thus not directly accessible... That’s when Brida comes in handy: instead of trying to extract keys/certificates and re-writing the routines we’re interested in, why don’t we let the application do the dirty work for us?

# Brida 0.2
Brida 0.2 was presented at Hack In The Box 2018 Amsterdam and includes some new features that speed up dynamical analysis of mobile applications, including:
- An integrated console in which output from all Frida and Brida hooks are printed
- An integrated JS editor with JavaScript syntax highlighting, in order to be able to add your own Frida exports and Frida hooks directly from Burp Suite. The JS editor is based on the great [RSyntaxTextArea](https://github.com/bobbylight/RSyntaxTextArea) of bobbylight
- An analysis tab, in which you have a tree representation of the binary (Java/OBJC classes and methods, inports/exports) and from which you can graphically add inspection hoooks (that print arguments and return value every time that the hooked function is executed) and tamper hooks (that dinamically change the return value of the hooked function every time that it is executed)

# Brida 0.4
Brida 0.4 should have been presented at Hack In Paris 2020 but, due to the postponement of the conference for the COVID-19 global situation, the tool has been released before the conference (but we will still present it to Hack In Paris 2020 in February 2021). Brida 0.4 speeds up further the dynamic analysis process with the introduction of the following features:
- Many Frida hooks for common tasks have been included, directly callable from the GUI of the tool with a click of the mouse! These scripts include the most recent hooks for Android and iOS platforms to bypass and inspect security features
- A new highly-customizable engine will allow to graphically create custom plugins to: 
	* Process requests/responses that pass through every Burp Suite tool, in order to be able to encrypt/decrypt/resign elements of requests and responses using Frida exported functions
	* Add custom tab to Burp Suite request/response pane, in order to be able to decrypt/decode/process requests/responses (or portion of them) using Frida exported functions (and then encrypt/encode/process modifications and replacing the original request/response, if any)
	* Add custom context menu options to invoke Frida exported functions on requests and responses
	* Add buttons that invoke/enable Frida exported functions
- Fully compatible with Burp 2.X and Python 3, with options to attach/detach and to inspect local processes
- Support to frida-compile, in order to move Brida JS inner functions outside from the Frida JS file edited by the pentester/hacker/user
- Graphical hooks are now persistent across spawns and can be manually enabled/disabled/removed
- Yes, we finally added the [documentation](https://github.com/federicodotta/Brida/wiki)... :D

# Requirements
In order to be able to use Brida, you need:
1.	Burp Suite (1.X or 2.X)
2.	Frida client
3.	Pyro4
4.	A jailbroken iOS device/rooted Android device with frida-server running on it (or an application patched with the frida-gadget)
5.	An application to analyze! :D

# Installation from GitHub
1.	Install Python 2.7 or Python 3 and Pyro4 (pip install pyro4)
2.	Download Burp Suite: http://portswigger.net/burp/download.html
3.	Download the last release of Brida: https://github.com/federicodotta/Brida/releases
4.	Open Burp -> Extender -> Extensions -> Add -> Choose BridaXX.jar file

# Installation from Burp Suite BApp Store
1.	Install Python 2.7 or Python 3 and Pyro4 (pip install pyro4)
2.	Download Burp Suite: http://portswigger.net/burp/download.html
3.	Open Burp -> Extender -> BApp Store -> Brida, Burp to Frida bridge -> Install

# Build
You can build Brida using Maven. Brida uses a modified version of RSyntaxTextArea, that you can find in this [fork](https://github.com/federicodotta/RSyntaxTextArea). In order to be able to build Brida you have to download the [last release](https://github.com/federicodotta/RSyntaxTextArea/releases) of the modified version of RSyntaxTextArea or build it and then install it locally with Maven using the following parameters:

- groupId: com.fifesoft
- artifactId: rsyntaxtextarea
- version: 2.6.1.edited

# Usage and tutorial
Installation and usage notes can be found in the [Wiki page](https://github.com/federicodotta/Brida/wiki).

The slides and the video of our conference presented at Hack In The Box 2018 Amsterdam that describes the new features of the version 0.2 can be found at:
- https://conference.hitb.org/hitbsecconf2018ams/materials/D1T1%20-%20Federico%20Dotta%20and%20Piergiovanni%20Cipolloni%20-%20Brida%20When%20Burp%20Suite%20Meets%20Frida.pdf
- https://www.youtube.com/watch?v=wPepicuHDzs&t=18s

We will present Brida at Hack In Paris 2020. After the conference we will add here the links to the slides and to the video!

# Screenshot
![Brida Screenshot](https://raw.githubusercontent.com/federicodotta/Brida/master/BridaScreen1.PNG)

# MIT License
Copyright (c) 2020 Brida  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.