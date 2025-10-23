<p align="center">
  <img src="https://raw.githubusercontent.com/federicodotta/Brida/master/BridaLogo.png" alt="Brida Logo"/>
</p>

# Brida

[![](https://img.shields.io/github/stars/federicodotta/brida.svg?color=yellow)](https://github.com/federicodotta/brida)
[![](https://img.shields.io/github/forks/federicodotta/brida.svg?color=green)](https://github.com/federicodotta/brida)
[![](https://img.shields.io/github/issues-raw/federicodotta/brida.svg?color=red)](https://github.com/federicodotta/brida/issues)
[![](https://img.shields.io/badge/license-MIT%20License-red.svg?color=lightgray)](https://opensource.org/licenses/MIT) 
[![](https://img.shields.io/badge/twitter-apps3c-blue.svg)](https://twitter.com/apps3c)

Brida is a Burp Suite Extension that, working as a bridge between [Burp Suite](https://portswigger.net/burp/) and [Frida](https://www.frida.re/), lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX).

# Brida Idea
This idea is a need that is born during the analysis of some mobile application that use strong symmetric cryptography using random keys, without knowing the correct secret all data was not modifiable via Burp neither with a custom plugin. More generally, applications' logic could be based on cryptographic tokens, it could use a complex challenge-response algorithm as well, and so on. How can we tamper the messages? Most of the times the only viable approach is to decompile/disassemble the application, identify the functions or methods we’re interested in AND re-implement them. This approach is obviously time consuming and not always really viable: i.e. the generation of tokens and/or the encryption routines could be based on cryptographic material strictly tied to the device (state) or stored inside protected areas and thus not directly accessible... That’s when Brida comes in handy: instead of trying to extract keys/certificates and re-writing the routines we’re interested in, why don’t we let the application do the dirty work for us? 

# Who should use Brida?

Short answer is **everyone**!

Long answer is that Brida is a **collection of tools**, some of them created to speed-up everyday mobile assessments and to help new Frida users, while others aimed at addressing very complex situations, in which Brida can really make the difference.

Tools that can be valuable to handle and speed-up everyday mobile assessments are the following ones:
- Many Frida hooks for common tasks, directly callable from the GUI of the tool. These scripts include the most recent hooks for Android and iOS platforms to bypass and inspect security features
- An analysis tab, in which you have a tree representation of the binary (Java/OBJC classes and methods, imports/exports) and from which you can graphically add inspection hooks (that print arguments and return value every time that the hooked function is executed) and tamper hooks (that dynamically change the return value of the hooked function every time that it is executed)
- An integrated JS editor with JavaScript syntax highlighting, in order to be able to add your own Frida exports and Frida hooks directly from Burp Suite

However, **the idea that led to Brida creation was to help pentesters/reversers/hackers to analyze the webservices of target mobile applications where complex security features are in place to protect the confidentiality and integrity of the HTTP requests and responses**. Encryption, obfuscation, signatures routines executed on requests and responses can make the work on testers very difficult and time-consuming, because usually it is necessary to reverse the security mechanisms and to implement a Burp Suite plugin or an external tool that first decrypt/de-obfuscate the HTTP messages and then eventually encrypt/obfuscate/sign edited messages. The same applies also to some non-security scenarios, like for example if a custom binary protocol is used to format the body of HTTP requests/responses for interoperability or performance purposes. 

Brida tries to speed-up those procedures as much as possible, by limiting the reversing effort and by completely removing (in most situations) the developing one, by offering an engine that allows to graphically create custom plugins that inspect and edit HTTP requests and responses **using the same mobile functions used by the mobile application itself**, thanks to Frida. Taking as an example a mobile application that encrypt/decrypt all the requests and responses with a custom/unknown encryption algorithm, Brida allows to **graphically** create a simple custom plugin that decrypt the encrypted HTTP messages using directly the mobile code used by the mobile application to do the job. Another example can be a custom plugin that transparently update signatures of signed HTTP requests when are sent to the backend using the same mobile functionality used by the application itself. 

More in detail, Brida allows to graphically create the plugins that:
- Process requests/responses that pass through every Burp Suite tool, in order to be able to encrypt/decrypt/resign elements of requests and responses using Frida exported functions
- Add custom tab to Burp Suite request/response pane, in order to be able to decrypt/decode/process requests/responses (or portion of them) using Frida exported functions (and then encrypt/encode/process modifications and replacing the original request/response, if any)
- Add custom context menu options to invoke Frida exported functions on requests and responses
- Add buttons that invoke/enable Frida exported functions

And if Brida custom plugin engine is not enough for our super-complex situations, it is also possible to write external Python/Java Burp Suite extensions that leave to Brida the task of executing the functions of the target mobile application on the data of the extension. Brida "Generate Stubs" tool generates the Java or Python code that can be pasted in external Python or Java extensions to use the Brida bridge.

# Brida >= 0.6 - Requirements and installation (frida >= 17)

Frida 17 brings major updates in the tool itself and in its JavaScript APIs. A major refactor of JS code was necessary, that broke compatibility with previous frida versions. Consequently last versions of Brida require a version of frida greater or equals to 17. If you need to use an older version of Frida, you can download version 0.6pre from the GitHub releases.

**Requirements:**

1.	Install Burp Suite (Community or Pro)
2.	Install NodeJS and npm and add them to the system path (in MacOS this can be challenging; refer to [this link](https://github.com/ersiner/osx-env-sync/issues/1#issuecomment-230053839) if you have issues with this point)
3.	Install frida and pyro4 python packages, in the system or in a virtual environment (`pip install frida frida-tools pyro4`)
4.	A jailbroken iOS device/rooted Android device with frida-server running on it (or an application patched with the frida-gadget)

**Installation from GitHub:**

1.	Download the last release of Brida: https://github.com/federicodotta/Brida/releases
2.	Open Burp -> Extender -> Extensions -> Add -> Choose BridaXX.jar file

**Installation from Burp Suite BApp Store:**

1.	Open Burp -> Extender -> BApp Store -> Brida, Burp to Frida bridge -> Install

*Updates in BApp Store require time. Checks on GitHub for latest version.*

# Brida <= 0.6pre - Requirements and installation (frida < 17)

**Requirements:**

1.  Install Burp Suite (Community or Pro)
2.  Install Node.js, npm and frida-compile 10.2.5 (npm install frida-compile@10.2.5). 
3.  Install frida and pyro4 python packages, in the system or in a virtual environment (`pip install frida frida-tools pyro4`)
4.  A jailbroken iOS device/rooted Android device with frida-server running on it (or an application patched with the frida-gadget)

**Installation from GitHub:**

1.  Download release 0.6pre of Brida: https://github.com/federicodotta/Brida/releases
2.  Open Burp -> Extender -> Extensions -> Add -> Choose BridaXX.jar file

*Path errors on MacOS are quite common; refer to [this link](https://github.com/ersiner/osx-env-sync/issues/1#issuecomment-230053839) if you have issues with system path*.

# Build

You can build Brida using Gradle or Maven. Brida uses a modified version of RSyntaxTextArea, that you can find in this [fork](https://github.com/federicodotta/RSyntaxTextArea). 

Building with Gradle is simpler. The "jar" task will do all the job, using a compiled version of the modified RSyntaxTextArea (folder "libs").

In order to be able to build Brida with Maven you have to install the modified RSyntaxTextArea version locally with Maven using the following parameters:

- groupId: com.fifesoft
- artifactId: rsyntaxtextarea
- version: 2.6.1.edited

# Documentation
Installation and usage notes can be found in the **[Wiki page](https://github.com/federicodotta/Brida/wiki)**.

The slides of our conference presented at **HackInBo 2017 Winter Edition** that describes the **first version** can be found at:
- (ENG) https://www.hackinbo.it/slides/1508354139_HackInBo%202017%20Winter%20Edition%20-%20Federico%20Dotta%20-%20Advanced%20mobile%20penetration%20testing%20with%20Brida%20-%20141017.pdf

The slides and the video of our conference presented at **Hack In The Box 2018 Amsterdam** that describes the new features of the **version 0.2** can be found at:
- (ENG) https://conference.hitb.org/hitbsecconf2018ams/materials/D1T1%20-%20Federico%20Dotta%20and%20Piergiovanni%20Cipolloni%20-%20Brida%20When%20Burp%20Suite%20Meets%20Frida.pdf
- (ENG) https://www.youtube.com/watch?v=wPepicuHDzs&t=18s

The video of our conference presented at **Hack In Paris ~~2020~~ 2021** (postponed for the COVID-19 global situation) that describes the new features of the **version ~~0.4~~ 0.5** can be found at:
- (ENG) https://www.youtube.com/watch?v=RawqXSslsQk&list=PLaS1tu_LcHA8WE8ITALpeCX7b07rOBZcj

# Demo

Two different demo applications can be found in the **[Demo](https://github.com/federicodotta/Brida/tree/master/Demo)** folder, one Android and one iOS. 

The demo folder contains also the Brida plugins that can be used to bypass the encryption mechanisms used by the apps!

# Authors
- Federico Dotta, Principal Security Analyst at HN Security
- Piergiovanni Cipolloni, Principal Security Analyst at HN Security

# Contributors
- Maurizio Agazzini

# Frida Scripts
Brida uses a lot of Frida code for dynamic hooking and for binary inspection, based on the work of:
- Marco Ivaldi
- Maurizio Agazzini
- Luca Baggio
- Federico Dotta

Furthermore, Brida integrates many Frida hooks developed by various authors to inspect/bypass many security features. A list of projects (I hope quite exhaustive) from which I took Frida code for the "Hooks and functions" section of Brida is (random order):
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
- neil-wu - [FridaSwiftDump](https://codeshare.frida.re/@neil-wu/fridaswiftdump/)
- DevTraleski - [iOS Jailbreak Detection Bypass Palera1n](https://codeshare.frida.re/@DevTraleski/ios-jailbreak-detection-bypass-palera1n/)

# Screenshot
![Brida Screenshot](https://raw.githubusercontent.com/federicodotta/Brida/master/images/BridaScreen1.PNG)

# MIT License
Copyright (c) 2025 Brida  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
