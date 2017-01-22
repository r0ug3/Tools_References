__Hosted Tools & References__
===============

The purpose of this repository is to act as an archive of tools built on my own or forked from other repositories. 
 - Credit: (https://github.com/USCGA/tools), (https://github.com/Laxa/HackingTools)

#### Application-Security
 - Application security repositoriy consits all web & mobile security assessment checklists and cheatsheets to be used by security analysts & consultants on their client's application.
 - Credit: (https://github.com/iamthefrogy/Application-Security)

#### Web-Security 
 - Important web application secure code review assessment keywords cheatsheet
 - Web application security assessment checklist
 - Credit: (https://github.com/iamthefrogy/Application-Security)

#### Android-Security
 - Android application security assessment checklist

#### OWASP Mobile Security Testing Guide

 - This is the official Github Repository of the OWASP Mobile Security Testing Guide (MSTG). The MSTG is a comprehensive manual for testing the security of mobile apps. It describes technical processes for verifying the controls listed in the [OWASP Mobile Application Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). The MSTG is meant to provide a baseline set of test cases for black-box and white-box security tests, and to help ensure completeness and consistency of the tests.
 - Credit: (https://github.com/OWASP/owasp-mstg)

__Reference to Tools__
=========

* __Audio Files ([`.wav`][wav], [`.flac`][flac], etc..)__
    - [MATLAB] code for Least Significant Bit
    - [Sonic Visualiser]... to easily view the [spectrogram] of an audio file
* __Steganography__
     * [`stegsolve.jar`][Stegsolve]
     * [Steghide]
     * [Hipshot] ... [Python] module to get long-exposure image from a video
* __Reversing/Disassembly__
     * [IDA Pro]
     * [Hopper] __... we have this bought and downabled in [`misc`](misc/)__
     * [Easy Python Decompiler]
     * [ShowMyCode] ... to decrypt a java .class file
     * [`radare`][radare]
     * [`file`][file] ... to simply find out "what the heck is this thing?"
     * [PE Tools] ... can dump memory from a [Windows] `.exe`, determine compiler, etc. 
     * [PEiD] ... determine what packer was used for a [Windows] `.exe` 
* __Network/Packet Sniffing__
     * [Wireshark]
     * [`bro`][bro]
     * [CapLoader]
* __PDF Files__
    * pdfdetach with [XPDF] ... to extract embedded files within a PDF file
    * [PDFCrack]
* __Exploit/Shellcode__
     * [Meterpreter]/[Metasploit]
     * [`getenvaddr.c`][getenvaddr.c]
* __Web Applications__
     * [Burpsuite]
     * [`sqlmap`][sqlmap]
     * [Zed Attack Proxy][ZAP]
* __PHP__
    - [`phpdc.phpr`][phpdc.phpr] ... to decode [`bcompiler`][bcompiler] compiled [PHP] code.
* __Windows Binaries__
    - [`x64dbg`][x64dbg] ... to reverse and debug [Windows] binaries
* __Encryption__
     * [VBScript Decoder]
     * [`xortool`][xortool]
     * [quipqiup.com]
     * [factordb.com]
* __Metadata__
     * [EXIFTool]
* __Password Cracking__
     * [John the Ripper]
     * [`hashcat`][Hashcat]
     * [`fcrackzip`][fcrackzip]
* __Forensics__
     * [`scalpel`][Scalpel]
     * [`foremost`][foremost]
     * [`vinetto`][vinetto] ... for examining [Thumbs.db] files
     * [`aeskeyfind`][aeskeyfind]
     * [`rsakeyfind`][rsakeyfind]
     * [Volatility] ... for memory files like `.vmss` or `.vdi`
     * [Autopsy] ... for disk image files like `.img`
     * [`binwalk`][binwalk]
* __Host Based Forensics__
    - `ewfmount` .. encase/expert witness format
    - `mount` ... to mount a drive
    - `umount` ... to _unmount_ a drive
    - `mmls` ... Display the partition layout of a volume system (partition tables)
    - `Gpart` ... if the image is corrupt, can it be fixed? 
    - [`f-response`][f-response] ... 
* __Reconnaissance__
    * [HTTrack] ... to scrape entire websites
    * [theHarvester] ... to detect and scrape e-mail addresses
    * [Netcraft] ... to grab hosting info on a website
    * [Nikto] ... to find vulnerabilities in web applications
* __[Android][Android] [APK]__
    * [Android APK Decompiler](http://www.decompileandroid.com/)
    * [`jadx`][jadx]
* __Legend__
    * \[G]: Github/Git repository # Note, this flag automatically imply the \[O] flag
    * \[S]: Software (Imply that it's not always 100% free and that it's not open source or restrictive license)
    * \[F]: Freeware (Free software, does'nt necessarily means that it's opensource)
    * \[I]: Website
    * \[P]: Plugin for chrome
    * \[R]: Plugin for firefox
    * \[C]: CLI tool
    * \[O]: Open source
    * \[M]: Misceallenous
    * \[L]: Reverse Flag: is set only when Linux compatible
    * \[W]: Reverse Flag: is set only when Windows compatible
* __Binary__
    * \[I] https://malwr.com/: online binary analysis
    * \[I] https://retdec.com/: online decompiler for c/c++ binaries
    * \[I] http://www.javadecompilers.com/: java decompiler online
    * \[S|W] [Reflector]: assembly browser for .NET
    * \[F|O|W] [Simple Assembly Explorer]: another .NET disassembler
    * \[F|O|W] [de4dot]: .NET deobfuscator
    * \[S] [IDA]: debugger
    * \[F|O] [OllyDbg]: debugger
    * \[F|O|W] [x64dbg]: debugger
    * \[C|O|L] [gdb]: Gnu debugger for linux
    * \[M] [peda]: python plugin for gdb
    * \[C|O|L] [strace/ltrace]: system call tracers / dynamic call tracers (librairies)
    * \[G] [dex2jar]: apk unpacker (android package)
    * \[S] [dede]: delphi decompiler
    * \[S] [Pin]: dynamic binary instrumentation framework
    * \[G] [Pintool]: binary password finder for ctf using pin
    * \[O|L] [checksec]: check binary protections
    * \[F] [DiE]: binary packer detection
    * \[G] [Qira]: timeless debugger with web interface by geohot
    * \[G|C] [ROPGadget]: tool for rop chaining
    * \[G|C] [plasma]: interactive disassembler in pseudo-C with colored syntax
    * \[O|C|L] [XOCopy]: copy memory of execute only ELF binaries
    * \[G|C] [Shellsploit]: shellcode generator framework
    * \[G|C] [radare2]: analyzer, disassembler, debugger
    * \[G] [Bokken]: Python-GTK GUI for radare2
    * \[G|C] [libformatstr]: python lib to make string format exploits
    * \[G] [pwntools]: Python framework to quickly develop exploits
    * \[G] [binjitsu]: fork of pwntools
    * \[G|C] [fixenv]: Script to align stack withtout ASLR and gdb,strace,ltrace
    * \[O|W] [cheatengine]: memory scanner and other usefull things
    * \[G] [Voltron]: Great UI Debugger
    * \[G] [Z3]: Z3 is a theorem prover
    * \[G] [angr]: binary analysis, allows value-set analysis
    * \[G] [rop-tool]: another helpful tool for ROP
    * \[G] [villoc]: visualize heap chunks on linux
    * \[O|C] [valgrind]: binary analysis allowing to spot read/write errors on memory operations
    * \[S|W] [apimonitor]: inspect process calls and trace them
    * \[F|W] [PEiD]: identify which packer has been used on PE binaries
    * \[F|W] [ImpREC]: reconstruct IAT table for unpacked binaries
    * \[O|C] [Flawfinder]: static source code analyzer for C/C++ which report possible security weakness
    * \[G|C] [afl]: fuzzer
* __Forensic__
    * \[C|O] [volatility]: forensic tool to analyse memory dump from windows/linux
    * \[C|O] [Autopsy/Sleuth]: analyse hard drives and smartphones
    * \[C|O] [Foremost]: file recovery after deletion or format
    * \[G|C] [BinWalk]: find files into file
    * \[S] [dff]: complete forensic gui analyser with lots of automation
    * \[G|C] [origami]: pdf forensic analysis with optional GUI
    * \[F|W] [MFTDump]: dump/copy $MFT file on windows
    * \[G|C] [AppCompatCacheParser]: dump shimcache entries from Registry (can use offline registry)
    * \[F|W] [[RegistryExplorer]: GUI to explore registry with search options and possibility to use offline register
* __Cryptography__
    * \[C|G] [xortool]: find xor key/key length from xor text/binary
    * \[C|G] [cribdrag]: interactive crib dragging on xored text
    * \[C|G] [hash_extender]: hash extension forger
    * \[C|G] [hash-identifier]: hash identifier
    * \[C|G] [PadBuster]: break CBC encryption using an oracle
    * \[C|G] [lsb-toolkit]: extract bit from images for steganography
    * \[C|O] [john]: hash cracker (bruteforce + dico attacks)
    * \[F|O] [hashcat]: hash bruteforce cracker that support GPU
    * \[C|G] [rsatool]: calculates RSA (p, q, n, d, e) and RSA-CRT (dP, dQ, qInv) parameters given either two primes (p, q) or modulus and private exponent (n, d)
    * \[I] http://quipqiup.com/: basic cryptography solver
    * \[G|C] [python-paddingoracle]: python tool to exploit padding oracle
* __Web__
    * \[F|O] [DirBuster]: bruteforce/dictionnary attack on webserver to find hidden directories
    * \[I] http://pkav.net/XSS2.png: XSS spreadsheet
    * \[C|O] [sqlmap]: sql injection
    * \[S] [Burp suite]: request tool analysis/forge request
    * \[S|W] [fiddler]: HTTP web proxy
    * \[I] http://requestb.in/: get a temporary page to receive GET/POST request
    * \[I] http://en.42.meup.org/ : Temporary web hosting
    * \[I] https://zerobin.net/: anonymous encrypted pastebin
    * \[I] http://pastebin.com/: paste code/text with coloration
    * \[I] http://portquiz.net/: test outgoing ports
    * \[I] http://botscout.com/: check if an IP is flagged as spam/bot
    * \[P|R] [HackBar]: xss/sql tests
    * \[R] [TamperData]: modify and tamper HTTP requests
    * \[R] [Advanced Cookie Manager]: Edit cookie
    * \[R] [Modify Headers]: Edit HTTP headers
    * \[R] [HTTP Requester]: Edit HTTP requests
    * \[R] [FlagFox]: Info about current website
    * \[R] [Live HTTP Headers]: View Headers
    * \[P] [ModHeader]: edit HTTP requests
    * \[G] [Nikto2]: web server scanner
    * \[P] [EditThisCookie]: edit cookie, can lock cookie
    * \[I] https://dnsdumpster.com/: free domain research tools, find subdomains
    * \[I] https://pentest-tools.com/home: subdomain bruteforce not 100% free
    * \[G] [Hydra]: remote password cracker
* __Network__
    * \[C|O] [Netcat]: network tool, can listen or connect using TCP/UDP
    * \[C|O] [nmap]: network tool to scan ports and discover services
    * \[C|O] [Scapy]: powerful interactive packet manipulation program
    * \[C|O] [Aircrack]: wi-fi injection/monitoring/cracking
    * \[S|O] [Wireshark]: network packet analyzer
    * \[S|W] [NetworkMiner]: sniffer/pcap analyzer, pretty good for files and see what's going on with HTTP traffic
    * \[C|O] [Hexinject]: Packer injector and sniffer. Allows to modify packets on the fly
* __Steganography__
    * \[C|F] [exiftags]: linux package to check jpg tags
    * \[O|C] [ExifTool]: read/edit metadata of various file formats
    * \[F|O|W] [tweakpng]: tool to resize image for steganography
    * \[F|O] [Stegsolve]: perform quick image analysis to find hidden things
    * \[F|O] [Wbstego]: retrieve/hide messages in various container
* __Misc__
    * \[F|O|W] [Cuckoo]: interactive sandbox malware analysis
    * \[F|O|W] [Photorec]: recover erased file
    * \[C|O] [QEMU]: machine emulator and virtualizer
    * \[C|S] [metasploit]: Generate payload and browser exploits
    * \[C|O] [binutils]: tons of CLI tools
    * \[S] [vmware]: virtualization products
    * \[I] https://regex101.com/: javascript/python/php regex online
    * \[I] http://rubular.com/: ruby regex online
    * \[M|O] [kali]: hacking linux OS
    * \[I] https://www.exploit-db.com/: exploits database
    * \[G|C] [AutoLocalPrivilegeEscalation]: bash script to get root if possible
    * \[C|O] [sshpass]: pass ssh password without typing it (highly insecure)
    * \[C|O] [virt-what]: simple bash script to detect virtualization environment
    * \[W|O] [ProcessHacker]: Extended taskmanager
    * \[G]: [english-words]: simple english wordlist
* __Sec/Tools list__
    * \[W] [pax0r]: another huge list of tools
    * \[G] [SecLists]: SecLists is the security tester's companion. It is a collection of multiple types of lists used during security assessments
    * \[G] [ctf-tools]: list of tools similar to this one
    * \[I] http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/
    * \[G] https://github.com/Hack-with-Github/Awesome-Hacking: awesome list related to hacking
* __Programming__
    * \[I] http://www.tutorialspoint.com/: online programmation on most languages
    * \[I] https://gcc.godbolt.org/: check disassembly code produced with different versions of gcc

---

[DirBuster]: https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
[xortool]: https://github.com/hellman/xortool
[cribdrag]: https://github.com/SpiderLabs/cribdrag
[Cuckoo]: http://www.cuckoosandbox.org/
[Reflector]: https://www.red-gate.com/products/dotnet-development/reflector/
[Simple Assembly Explorer]: https://sites.google.com/site/simpledotnet/simple-assembly-explorer
[de4dot]: http://de4dot.com/
[IDA]: https://www.hex-rays.com/products/ida/
[OllyDbg]: http://www.ollydbg.de/
[x64dbg]: http://x64dbg.com/
[sqlmap]: http://sqlmap.org/
[Photorec]: http://www.cgsecurity.org/wiki/PhotoRec
[hash_extender]: https://github.com/iagox86/hash_extender
[hash-identifier]: https://github.com/psypanda/hashID
[lsb-toolkit]: https://github.com/luca-m/lsb-toolkit
[john]: http://www.openwall.com/john/
[volatility]: http://www.volatilityfoundation.org/
[Burp suite]: https://portswigger.net/burp/
[fiddler]: http://www.telerik.com/fiddler
[metasploit]: http://www.metasploit.com/
[exiftags]: http://johnst.org/sw/exiftags/
[hashcat]: http://hashcat.net/oclhashcat/
[HackBar]: https://chrome.google.com/webstore/detail/hackbar/ejljggkpbkchhfcplgpaegmbfhenekdc
[EditThisCookie]: https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?
[TamperData]: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
[Advanced Cookie Manager]: https://addons.mozilla.org/fr/firefox/addon/cookie-manager/
[Modify Headers]: https://addons.mozilla.org/fr/firefox/addon/modify-headers/
[HTTP Requester]: https://addons.mozilla.org/fr/firefox/addon/httprequester/
[FlagFox]: https://addons.mozilla.org/fr/firefox/addon/flagfox/
[Live HTTP Headers]: https://addons.mozilla.org/fr/firefox/addon/live-http-headers/
[ModHeader]: https://chrome.google.com/webstore/detail/modheader/idgpnmonknjnojddfkpgkljpfnnfcklj
[Netcat]: http://nc110.sourceforge.net/
[nmap]: https://nmap.org/
[binutils]: https://www.gnu.org/software/binutils/
[vmware]: http://www.vmware.com/
[dede]: http://www.softpedia.com/get/Programming/Debuggers-Decompilers-Dissasemblers/DeDe.shtml
[tweakpng]: http://entropymine.com/jason/tweakpng/
[dex2jar]: https://github.com/pxb1988/dex2jar
[kali]: https://www.kali.org/
[notepad++]: https://notepad-plus-plus.org/
[ctf-tools]: https://github.com/zardus/ctf-tools
[gdb]: https://www.gnu.org/software/gdb/
[peda]: https://github.com/longld/peda
[Stegsolve]: http://www.caesum.com/handbook/Stegsolve.jar
[Scapy]: http://www.secdev.org/projects/scapy/
[Nikto2]: https://cirt.net/Nikto2
[Autopsy/Sleuth]: http://www.sleuthkit.org/index.php
[Foremost]: https://doc.ubuntu-fr.org/foremost
[Aircrack]: http://www.aircrack-ng.org/
[Pin]: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
[Pintool]: https://github.com/wagiro/pintool
[pwntools]: https://pwntools.readthedocs.org/en/2.2/
[QEMU]: http://wiki.qemu.org/Main_Page
[rsatool]: https://github.com/ius/rsatool
[checksec]: http://www.trapkit.de/tools/checksec.html
[DiE]: http://ntinfo.biz/
[Qira]: https://github.com/BinaryAnalysisPlatform/qira
[Hydra]: https://github.com/vanhauser-thc/thc-hydra
[ROPGadget]: https://github.com/JonathanSalwan/ROPgadget
[plasma]: https://github.com/joelpx/plasma
[XOCopy]: http://reverse.lostrealm.com/tools/xocopy.html
[Shellsploit]: https://github.com/b3mb4m/shellsploit-framework
[radare2]: https://github.com/radare/radare2
[Bokken]: https://github.com/radare/bokken
[BinWalk]: https://github.com/devttys0/binwalk
[Wbstego]: http://wbstego.wbailer.com/
[dff]: http://www.arxsys.fr/discover/
[origami]: https://github.com/cogent/origami-pdf
[libformatstr]: https://github.com/hellman/libformatstr
[fixenv]: https://github.com/hellman/fixenv
[cheatengine]: http://www.cheatengine.org/
[AutoLocalPrivilegeEscalation]: https://github.com/ngalongc/AutoLocalPrivilegeEscalation
[Voltron]: https://github.com/snare/voltron
[SecLists]: https://github.com/danielmiessler/SecLists
[PadBuster]: https://github.com/GDSSecurity/PadBuster
[Z3]: https://github.com/Z3Prover/z3
[angr]: https://github.com/angr/angr
[rop-tool]: https://github.com/t00sh/rop-tool
[villoc]: https://github.com/wapiflapi/villoc
[sshpass]: https://sourceforge.net/projects/sshpass/files/sshpass/
[Wireshark]: https://www.wireshark.org/
[binjitsu]: https://github.com/binjitsu/binjitsu
[virt-what]: https://people.redhat.com/~rjones/virt-what/
[valgrind]: http://valgrind.org/
[ProcessHacker]: http://processhacker.sourceforge.net/
[apimonitor]: http://www.rohitab.com/apimonitor
[pax0r]: http://pax0r.com/staff/tools2016/
[PEiD]: https://www.aldeid.com/wiki/PEiD
[ImpREC]: http://www.woodmann.com/collaborative/tools/index.php/ImpREC
[Flawfinder]: http://www.dwheeler.com/flawfinder/
[ExifTool]: http://www.sno.phy.queensu.ca/~phil/exiftool/
[NetworkMiner]: http://www.netresec.com/?page=NetworkMiner
[english-words]: https://github.com/dwyl/english-words
[MFTDump]: http://malware-hunters.net/all-downloads/
[AppCompatCacheParser]: https://github.com/EricZimmerman/AppCompatCacheParser
[RegistryExplorer]: https://binaryforay.blogspot.fr/2015/07/registry-explorerrecmd-0710-released.html
[python-paddingoracle]: https://github.com/mwielgoszewski/python-paddingoracle
[afl]: https://github.com/mirrorer/afl
[Hexinject]: https://sourceforge.net/projects/hexinject/files/
[netcat]: https://en.wikipedia.org/wiki/Netcat
[Wikipedia]: https://www.wikipedia.org/
[Linux]: https://www.linux.com/
[man page]: https://en.wikipedia.org/wiki/Man_page
[PuTTY]: http://www.putty.org/
[ssh]: https://en.wikipedia.org/wiki/Secure_Shell
[Windows]: http://www.microsoft.com/en-us/windows
[virtual machine]: https://en.wikipedia.org/wiki/Virtual_machine
[operating system]:https://en.wikipedia.org/wiki/Operating_system
[OS]: https://en.wikipedia.org/wiki/Operating_system
[VMWare]: http://www.vmware.com/
[VirtualBox]: https://www.virtualbox.org/
[hostname]: https://en.wikipedia.org/wiki/Hostname
[port number]: https://en.wikipedia.org/wiki/Port_%28computer_networking%29
[distribution]:https://en.wikipedia.org/wiki/Linux_distribution
[Ubuntu]: http://www.ubuntu.com/
[ISO]: https://en.wikipedia.org/wiki/ISO_image
[standard streams]: https://en.wikipedia.org/wiki/Standard_streams
[standard output]: https://en.wikipedia.org/wiki/Standard_streams
[standard input]: https://en.wikipedia.org/wiki/Standard_streams
[read]: http://ss64.com/bash/read.html
[variable]: https://en.wikipedia.org/wiki/Variable_%28computer_science%29
[command substitution]: http://www.tldp.org/LDP/abs/html/commandsub.html
[permissions]: https://en.wikipedia.org/wiki/File_system_permissions
[redirection]: http://www.tldp.org/LDP/abs/html/io-redirection.html
[pipe]: http://www.tldp.org/LDP/abs/html/io-redirection.html
[piping]: http://www.tldp.org/LDP/abs/html/io-redirection.html
[tmp]: http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/tmp.html
[curl]: http://curl.haxx.se/
[cl1p.net]: https://cl1p.net/
[request]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
[POST request]: https://en.wikipedia.org/wiki/POST_%28HTTP%29
[Python]: http://python.org/
[interpreter]: https://en.wikipedia.org/wiki/List_of_command-line_interpreters
[requests]: http://docs.python-requests.org/en/latest/
[urllib]: https://docs.python.org/2/library/urllib.html
[file handling with Python]: https://docs.python.org/2/tutorial/inputoutput.html#reading-and-writing-files
[bash]: https://www.gnu.org/software/bash/
[Assembly]: https://en.wikipedia.org/wiki/Assembly_language
[the stack]:  https://en.wikipedia.org/wiki/Stack_%28abstract_data_type%29
[register]: http://www.tutorialspoint.com/assembly_programming/assembly_registers.htm
[hex]: https://en.wikipedia.org/wiki/Hexadecimal
[hexadecimal]: https://en.wikipedia.org/wiki/Hexadecimal
[archive file]: https://en.wikipedia.org/wiki/Archive_file
[zip file]: https://en.wikipedia.org/wiki/Zip_%28file_format%29
[zip files]: https://en.wikipedia.org/wiki/Zip_%28file_format%29
[.zip]: https://en.wikipedia.org/wiki/Zip_%28file_format%29
[gigabytes]: https://en.wikipedia.org/wiki/Gigabyte
[GB]: https://en.wikipedia.org/wiki/Gigabyte
[GUI]: https://en.wikipedia.org/wiki/Graphical_user_interface
[Wireshark]: https://www.wireshark.org/
[FTP]: https://en.wikipedia.org/wiki/File_Transfer_Protocol
[client and server]: https://simple.wikipedia.org/wiki/Client-server
[RETR]: http://cr.yp.to/ftp/retr.html
[FTP server]: https://help.ubuntu.com/lts/serverguide/ftp-server.html
[SFTP]: https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol
[SSL]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[encryption]: https://en.wikipedia.org/wiki/Encryption
[HTML]: https://en.wikipedia.org/wiki/HTML
[Flask]: http://flask.pocoo.org/
[SQL]: https://en.wikipedia.org/wiki/SQL
[and]: https://en.wikipedia.org/wiki/Logical_conjunction
[Cyberstakes]: https://cyberstakesonline.com/
[cat]: https://en.wikipedia.org/wiki/Cat_%28Unix%29
[symbolic link]: https://en.wikipedia.org/wiki/Symbolic_link
[ln]: https://en.wikipedia.org/wiki/Ln_%28Unix%29
[absolute path]: https://en.wikipedia.org/wiki/Path_%28computing%29
[CTF]: https://en.wikipedia.org/wiki/Capture_the_flag#Computer_security
[Cyberstakes]: https://cyberstakesonline.com/
[OverTheWire]: http://overthewire.org/
[Leviathan]: http://overthewire.org/wargames/leviathan/
[ls]: https://en.wikipedia.org/wiki/Ls
[grep]: https://en.wikipedia.org/wiki/Grep
[strings]: http://linux.die.net/man/1/strings
[ltrace]: http://linux.die.net/man/1/ltrace
[C]: https://en.wikipedia.org/wiki/C_%28programming_language%29
[strcmp]: http://linux.die.net/man/3/strcmp
[access]: http://pubs.opengroup.org/onlinepubs/009695399/functions/access.html
[system]: http://linux.die.net/man/3/system
[real user ID]: https://en.wikipedia.org/wiki/User_identifier
[effective user ID]: https://en.wikipedia.org/wiki/User_identifier
[brute force]: https://en.wikipedia.org/wiki/Brute-force_attack
[for loop]: https://en.wikipedia.org/wiki/For_loop
[bash programming]: http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
[Behemoth]: http://overthewire.org/wargames/behemoth/
[command line]: https://en.wikipedia.org/wiki/Command-line_interface
[command-line]: https://en.wikipedia.org/wiki/Command-line_interface
[cli]: https://en.wikipedia.org/wiki/Command-line_interface
[PHP]: https://php.net/
[URL]: https://en.wikipedia.org/wiki/Uniform_Resource_Locator
[TamperData]: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
[Firefox]: https://www.mozilla.org/en-US/firefox/new/?product=firefox-3.6.8&os=osx%E2%8C%A9=en-US
[Caesar Cipher]: https://en.wikipedia.org/wiki/Caesar_cipher
[Google Reverse Image Search]: https://www.google.com/imghp
[PicoCTF]: https://picoctf.com/
[PicoCTF 2014]: https://picoctf.com/
[JavaScript]: https://www.javascript.com/
[base64]: https://en.wikipedia.org/wiki/Base64
[client-side]: https://en.wikipedia.org/wiki/Client-side_scripting
[client side]: https://en.wikipedia.org/wiki/Client-side_scripting
[javascript:alert]: http://www.w3schools.com/js/js_popup.asp
[Java]: https://www.java.com/en/
[2147483647]: https://en.wikipedia.org/wiki/2147483647_%28number%29
[XOR]: https://en.wikipedia.org/wiki/Exclusive_or
[XOR cipher]: https://en.wikipedia.org/wiki/XOR_cipher
[quipqiup.com]: http://www.quipqiup.com/
[XPDF]: http://www.foolabs.com/xpdf/download.html
[pdfimages]: http://linux.die.net/man/1/pdfimages
[ampersand]: https://en.wikipedia.org/wiki/Ampersand
[URL encoding]: https://en.wikipedia.org/wiki/Percent-encoding
[Percent encoding]: https://en.wikipedia.org/wiki/Percent-encoding
[URL-encoding]: https://en.wikipedia.org/wiki/Percent-encoding
[Percent-encoding]: https://en.wikipedia.org/wiki/Percent-encoding
[endianness]: https://en.wikipedia.org/wiki/Endianness
[ASCII]: https://en.wikipedia.org/wiki/ASCII
[struct]: https://docs.python.org/2/library/struct.html
[pcap]: https://en.wikipedia.org/wiki/Pcap
[packet capture]: https://en.wikipedia.org/wiki/Packet_analyzer
[HTTP]: https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
[Wireshark filters]: https://wiki.wireshark.org/DisplayFilters
[SSL]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[Assembly]: https://en.wikipedia.org/wiki/Assembly_language
[Assembly Syntax]: https://en.wikipedia.org/wiki/X86_assembly_language#Syntax
[Intel Syntax]: https://en.wikipedia.org/wiki/X86_assembly_language
[Intel or AT&T]: http://www.imada.sdu.dk/Courses/DM18/Litteratur/IntelnATT.htm
[AT&T syntax]: https://en.wikibooks.org/wiki/X86_Assembly/GAS_Syntax
[GET request]: https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods
[GET requests]: https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods
[IP Address]: https://en.wikipedia.org/wiki/IP_address
[IP Addresses]: https://en.wikipedia.org/wiki/IP_address
[MAC Address]: https://en.wikipedia.org/wiki/MAC_address
[session]: https://en.wikipedia.org/wiki/Session_%28computer_science%29
[Cookie Manager+]: https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/
[hexedit]: http://linux.die.net/man/1/hexedit
[Google]: http://google.com/
[Scapy]: http://www.secdev.org/projects/scapy/
[ARP]: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
[UDP]: https://en.wikipedia.org/wiki/User_Datagram_Protocol
[SQL injection]: https://en.wikipedia.org/wiki/SQL_injection
[sqlmap]: http://sqlmap.org/
[sqlite]: https://www.sqlite.org/
[MD5]: https://en.wikipedia.org/wiki/MD5
[OpenSSL]: https://www.openssl.org/
[Burpsuite]:https://portswigger.net/burp/
[Burpsuite.jar]:https://portswigger.net/burp/
[Burp]:https://portswigger.net/burp/
[NULL character]: https://en.wikipedia.org/wiki/Null_character
[Format String Vulnerability]: http://www.cis.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf
[printf]: http://pubs.opengroup.org/onlinepubs/009695399/functions/fprintf.html
[argument]: https://en.wikipedia.org/wiki/Parameter_%28computer_programming%29
[arguments]: https://en.wikipedia.org/wiki/Parameter_%28computer_programming%29
[parameter]: https://en.wikipedia.org/wiki/Parameter_%28computer_programming%29
[parameters]: https://en.wikipedia.org/wiki/Parameter_%28computer_programming%29
[Vortex]: http://overthewire.org/wargames/vortex/
[socket]: https://docs.python.org/2/library/socket.html
[file descriptor]: https://en.wikipedia.org/wiki/File_descriptor
[file descriptors]: https://en.wikipedia.org/wiki/File_descriptor
[Forth]: https://en.wikipedia.org/wiki/Forth_%28programming_language%29
[github]: https://github.com/
[buffer overflow]: https://en.wikipedia.org/wiki/Buffer_overflow
[try harder]: https://www.offensive-security.com/when-things-get-tough/
[segmentation fault]: https://en.wikipedia.org/wiki/Segmentation_fault
[seg fault]: https://en.wikipedia.org/wiki/Segmentation_fault
[segfault]: https://en.wikipedia.org/wiki/Segmentation_fault
[shellcode]: https://en.wikipedia.org/wiki/Shellcode
[sploit-tools]: https://github.com/SaltwaterC/sploit-tools
[Kali]: https://www.kali.org/
[Kali Linux]: https://www.kali.org/
[gdb]: https://www.gnu.org/software/gdb/
[gdb tutorial]: http://www.unknownroad.com/rtfm/gdbtut/gdbtoc.html
[payload]: https://en.wikipedia.org/wiki/Payload_%28computing%29
[peda]: https://github.com/longld/peda
[git]: https://git-scm.com/
[home directory]: https://en.wikipedia.org/wiki/Home_directory
[NOP slide]:https://en.wikipedia.org/wiki/NOP_slide
[NOP]: https://en.wikipedia.org/wiki/NOP
[examine]: https://sourceware.org/gdb/onlinedocs/gdb/Memory.html
[stack pointer]: http://stackoverflow.com/questions/1395591/what-is-exactly-the-base-pointer-and-stack-pointer-to-what-do-they-point
[little endian]: https://en.wikipedia.org/wiki/Endianness
[big endian]: https://en.wikipedia.org/wiki/Endianness
[endianness]: https://en.wikipedia.org/wiki/Endianness
[pack]: https://docs.python.org/2/library/struct.html#struct.pack
[ash]:https://en.wikipedia.org/wiki/Almquist_shell
[dash]: https://en.wikipedia.org/wiki/Almquist_shell
[shell]: https://en.wikipedia.org/wiki/Shell_%28computing%29
[pwntools]: https://github.com/Gallopsled/pwntools
[colorama]: https://pypi.python.org/pypi/colorama
[objdump]: https://en.wikipedia.org/wiki/Objdump
[UPX]: http://upx.sourceforge.net/
[64-bit]: https://en.wikipedia.org/wiki/64-bit_computing
[breakpoint]: https://en.wikipedia.org/wiki/Breakpoint
[stack frame]: http://www.cs.umd.edu/class/sum2003/cmsc311/Notes/Mips/stack.html
[format string]: http://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html
[format specifiers]: http://web.eecs.umich.edu/~bartlett/printf.html
[format specifier]: http://web.eecs.umich.edu/~bartlett/printf.html
[variable expansion]: https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html
[base pointer]: http://stackoverflow.com/questions/1395591/what-is-exactly-the-base-pointer-and-stack-pointer-to-what-do-they-point
[dmesg]: https://en.wikipedia.org/wiki/Dmesg
[Android]: https://www.android.com/
[.apk]:https://en.wikipedia.org/wiki/Android_application_package
[apk]:https://en.wikipedia.org/wiki/Android_application_package
[decompiler]: https://en.wikipedia.org/wiki/Decompiler
[decompile Java code]: http://www.javadecompilers.com/
[jadx]: https://github.com/skylot/jadx
[.img]: https://en.wikipedia.org/wiki/IMG_%28file_format%29
[binwalk]: http://binwalk.org/
[JPEG]: https://en.wikipedia.org/wiki/JPEG
[JPG]: https://en.wikipedia.org/wiki/JPEG
[disk image]: https://en.wikipedia.org/wiki/Disk_image
[foremost]: http://foremost.sourceforge.net/
[eog]: https://wiki.gnome.org/Apps/EyeOfGnome
[function pointer]: https://en.wikipedia.org/wiki/Function_pointer
[machine code]: https://en.wikipedia.org/wiki/Machine_code
[compiled language]: https://en.wikipedia.org/wiki/Compiled_language
[compiler]: https://en.wikipedia.org/wiki/Compiler
[scripting language]: https://en.wikipedia.org/wiki/Scripting_language
[shell-storm.org]: http://shell-storm.org/
[shell-storm]:http://shell-storm.org/
[shellcode database]: http://shell-storm.org/shellcode/
[gdb-peda]: https://github.com/longld/peda
[x86]: https://en.wikipedia.org/wiki/X86
[Intel x86]: https://en.wikipedia.org/wiki/X86
[sh]: https://en.wikipedia.org/wiki/Bourne_shell
[/bin/sh]: https://en.wikipedia.org/wiki/Bourne_shell
[SANS]: https://www.sans.org/
[Holiday Hack Challenge]: https://holidayhackchallenge.com/
[USCGA]: http://uscga.edu/
[United States Coast Guard Academy]: http://uscga.edu/
[US Coast Guard Academy]: http://uscga.edu/
[Academy]: http://uscga.edu/
[Coast Guard Academy]: http://uscga.edu/
[Hackfest]: https://www.sans.org/event/pen-test-hackfest-2015
[SSID]: https://en.wikipedia.org/wiki/Service_set_%28802.11_network%29
[DNS]: https://en.wikipedia.org/wiki/Domain_Name_System
[Python:base64]: https://docs.python.org/2/library/base64.html
[OpenWRT]: https://openwrt.org/
[node.js]: https://nodejs.org/en/
[MongoDB]: https://www.mongodb.org/
[Mongo]: https://www.mongodb.org/
[SuperGnome 01]: http://52.2.229.189/
[Shodan]: https://www.shodan.io/
[SuperGnome 02]: http://52.34.3.80/
[SuperGnome 03]: http://52.64.191.71/
[SuperGnome 04]: http://52.192.152.132/
[SuperGnome 05]: http://54.233.105.81/
[Local file inclusion]: http://hakipedia.com/index.php/Local_File_Inclusion
[LFI]: http://hakipedia.com/index.php/Local_File_Inclusion
[PNG]: http://www.libpng.org/pub/png/
[.png]: http://www.libpng.org/pub/png/
[Remote Code Execution]: https://en.wikipedia.org/wiki/Arbitrary_code_execution
[RCE]: https://en.wikipedia.org/wiki/Arbitrary_code_execution
[GNU]: https://www.gnu.org/
[regular expression]: https://en.wikipedia.org/wiki/Regular_expression
[regular expressions]: https://en.wikipedia.org/wiki/Regular_expression
[uniq]: https://en.wikipedia.org/wiki/Uniq
[sort]: https://en.wikipedia.org/wiki/Sort_%28Unix%29
[binary data]: https://en.wikipedia.org/wiki/Binary_data
[binary]: https://en.wikipedia.org/wiki/Binary
[Firebug]: http://getfirebug.com/
[SHA1]: https://en.wikipedia.org/wiki/SHA-1
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[Linux]: https://www.linux.com/
[Ubuntu]: http://www.ubuntu.com/
[Kali Linux]: https://www.kali.org/
[Over The Wire]: http://overthewire.org/wargames/
[OverTheWire]: http://overthewire.org/wargames/
[Micro Corruption]: https://microcorruption.com/
[Smash The Stack]: http://smashthestack.org/
[CTFTime]: https://ctftime.org/
[Writeups]: https://ctftime.org/writeups
[Competitions]: https://ctftime.org/event/list/upcoming
[Skull Security]: https://wiki.skullsecurity.org/index.php?title=Main_Page
[MITRE]: http://mitrecyberacademy.org/
[Trail of Bits]: https://trailofbits.github.io/ctf/
[Stegsolve]: http://www.caesum.com/handbook/Stegsolve.jar
[Steghide]: http://steghide.sourceforge.net/
[IDA Pro]: https://www.hex-rays.com/products/ida/
[Wireshark]: https://www.wireshark.org/
[Bro]: https://www.bro.org/
[Meterpreter]: https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/
[Metasploit]: http://www.metasploit.com/
[Burpsuite]: https://portswigger.net/burp/
[xortool]: https://github.com/hellman/xortool
[sqlmap]: http://sqlmap.org/
[VMWare]: http://www.vmware.com/
[VirtualBox]: https://www.virtualbox.org/wiki/Downloads
[VBScript Decoder]: https://gist.github.com/bcse/1834878
[quipqiup.com]: http://quipqiup.com/
[EXIFTool]: http://www.sno.phy.queensu.ca/~phil/exiftool/
[Scalpel]: https://github.com/sleuthkit/scalpel
[Ryan's Tutorials]: http://ryanstutorials.net
[Linux Fundamentals]: http://linux-training.be/linuxfun.pdf
[USCGA]: http://uscga.edu
[Cyberstakes]: https://cyberstakesonline.com/
[Crackmes.de]: http://crackmes.de/
[Nuit Du Hack]: http://wargame.nuitduhack.com/
[Hacking-Lab]: https://www.hacking-lab.com/index.html
[FlareOn]: http://www.flare-on.com/
[The Second Extended Filesystem]: http://www.nongnu.org/ext2-doc/ext2.html
[GIF]: https://en.wikipedia.org/wiki/GIF
[PDFCrack]: http://pdfcrack.sourceforge.net/index.html
[Hexcellents CTF Knowledge Base]: http://security.cs.pub.ro/hexcellents/wiki/home
[GDB]: https://www.gnu.org/software/gdb/
[The Linux System Administrator's Guide]: http://www.tldp.org/LDP/sag/html/index.html
[aeskeyfind]: https://citp.princeton.edu/research/memory/code/
[rsakeyfind]: https://citp.princeton.edu/research/memory/code/
[Easy Python Decompiler]: http://sourceforge.net/projects/easypythondecompiler/
[factordb.com]: http://factordb.com/
[Volatility]: https://github.com/volatilityfoundation/volatility
[Autopsy]: http://www.sleuthkit.org/autopsy/
[ShowMyCode]: http://www.showmycode.com/
[HTTrack]: https://www.httrack.com/
[theHarvester]: https://github.com/laramies/theHarvester
[Netcraft]: http://toolbar.netcraft.com/site_report/
[Nikto]: https://cirt.net/Nikto2
[PIVOT Project]: http://pivotproject.org/
[InsomniHack PDF]: http://insomnihack.ch/wp-content/uploads/2016/01/Hacking_like_in_the_movies.pdf
[radare]: http://www.radare.org/r/
[radare2]: http://www.radare.org/r/
[foremost]: https://en.wikipedia.org/wiki/Foremost_%28software%29
[ZAP]: https://github.com/zaproxy/zaproxy
[Computer Security Student]: https://www.computersecuritystudent.com/HOME/index.html
[Vulnerable Web Page]: http://testphp.vulnweb.com/
[Hipshot]: https://bitbucket.org/eliteraspberries/hipshot
[John the Ripper]: https://en.wikipedia.org/wiki/John_the_Ripper
[hashcat]: http://hashcat.net/oclhashcat/
[fcrackzip]: http://manpages.ubuntu.com/manpages/hardy/man1/fcrackzip.1.html
[Whitehatters Academy]: https://www.whitehatters.academy/
[gn00bz]: http://gnoobz.com/
[Command Line Kung Fu]:http://blog.commandlinekungfu.com/
[Cybrary]: https://www.cybrary.it/
[Obum Chidi]: https://obumchidi.wordpress.com/
[ksnctf]: http://ksnctf.sweetduet.info/
[ToolsWatch]: http://www.toolswatch.org/category/tools/
[Net Force]:https://net-force.nl/
[Nandy Narwhals]: http://nandynarwhals.org/
[CTFHacker]: http://ctfhacker.com/
[Tasteless]: http://tasteless.eu/
[Dragon Sector]: http://blog.dragonsector.pl/
[pwnable.kr]: http://pwnable.kr/
[reversing.kr]: http://reversing.kr/
[DVWA]: http://www.dvwa.co.uk/
[Damn Vulnerable Web App]: http://www.dvwa.co.uk/
[b01lers]: https://b01lers.net/
[Capture the Swag]: https://ctf.rip/
[VulnHub]: http://www.vulnhub.com/
[cryptopals.com]: http://cryptopals.com/
[getenvaddr.c]: https://github.com/Partyschaum/haxe/blob/master/getenvaddr.c
[Hopper]: http://www.hopperapp.com/
[CapLoader]: http://www.netresec.com/?page=CapLoader
[file]: https://en.wikipedia.org/wiki/File_%28command%29
[PE Tools]: http://pe-tools.soft112.com/
[PEiD]: https://www.aldeid.com/wiki/PEiD
[vinetto]: http://vinetto.sourceforge.net/
[Thumbs.db]: http://www.howtogeek.com/237091/what-are-the-thumbs.db-desktop.ini-and-.ds_store-files/
[phpdc.phpr]: https://github.com/lighttpd/xcache/blob/master/bin/phpdc.phpr
[bcompiler]: http://php.net/manual/en/book.bcompiler.php
[x64dbg]: http://x64dbg.com/
[MATLAB]: https://www.mathworks.com/products/matlab/
[wav]: https://en.wikipedia.org/wiki/WAV
[flac]: https://en.wikipedia.org/wiki/FLAC
[Sonic Visualiser]: http://www.sonicvisualiser.org/
[spectrogram]: https://en.wikipedia.org/wiki/Spectrogram
