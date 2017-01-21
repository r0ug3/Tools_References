# Web Application Security Assessment Checklist
Description: This checklist will help security analyst/consultants to test their client's web application for security assessment. I am continuously trying my best to keep this checklist up-to-date. Your ideas/suggestions & test cases are warmly welcomed for this. Kindly share those on chintangurjar@outlook.com

##### (1) Web Application Fingerprint
- Analyze default banner using netcat HEAD http method.
- Analyze robots.txt
- Analyze administrator panel using CMD identification
- Analyze administrator panel using fuzzing technique
- Analyze TRACE/TRACK method
- Fingerprint server using Wapplyzer firefox addon
- Check if DEBUG method is allowed for IIS/ASP.net web application

##### (2) Analyze Application Entry Points
- Login panel
- Search box
- Comment section
- Feedback form
- Contact us form
- All GET & POST requests
- Cookies
- Hidden parameters
- File upload
- Import things(csv, excel, contacts etc.)

##### (3) Session Management
- Sensitive information disclosure/passing through cookie
- Cookie without 'HttpOnly' flag
- Cookie without 'Secure' flag set
- Check for Path attribute value for all domains & subdomains
- Apache HttpOnly cookie disclosure
- Session prediction/randomness checking
- Session expiration
- Check if session ID is required for all critical operation
- Check for session cookie value pre and post login
- Session overriding/hijacking
- Check if session really expires post log out

##### (4) Registration Process Testing
- Check for userid enumeration
- Perform mass registration/CAPTCHA implementation/weaknesses
- Insufficient email verification process
- Overwrite existing user using duplicate registration
- Weak Password Policy
- Stored XSS
- Check for sensitive information passing through secure layer or not

##### (5) Authenticaton Process Testing
- Username enumeration
- Bypass Authentication using SQL Injection
- Credentials transmission over SSL or not?
- Account lockout
- Check for 0Auth functionality
- User credentials are stored in browser memory in clear text 
- Back Refresh Attack (Refer OWASP)

##### (6) Check for error codes
- Test  404, 301 etc pages by /test.php, /test.aspx etc..
- Use Input data -  *&^%$#@!
- Send wrong cookie value to generate error
- Change value to hidden parameter to generate error
- Add "[]" in all parameters
- Change get req to post and post to get to generate error

##### (7) Post login 'My Profile/Account' Testing
- Check for CSRF
- Check for CSRF token bypass
- Impersonate other user's account
- Check account deletion functionality

##### (8) Post login 'My Profile/Account' Testing
- Username enumeration
- Reset token key expiration time
- Check if password getting changed over SSL or not
- Weak password policy testing
- Predict reset token
- Check bruteforcing for security answer
- All Active user sessions should be destroyed when user change his password

##### (9) 'Search Box' Testing
- Smash your scanner here :)

##### (10) Product Purchase Testing
- Change value of gift voucher to receive more gifts vouchers instead of 1
- Change product id to purchase higher valued price at lower cost
- Add procut to other user's cart
- Delete product from other user's cart
- Tamper the cartid parameter for deleting other users product
- Place order behalf of other user
- Give negative values in price to add money in your account + buying product 
- Check payment card gateway testing

##### (11) Flight/Hotel/Railway Ticket Booking Testing
- Check other user's e-ticket 
- Get refund behalf of other user
- Get more refund by changing refund amount
- Book business/high class ticket by chaning parameter value of economy class variable
- Book delux room by chaning parameter value of normal room fare
- Book multiple seats/rooms by changing quantity parameter value for 1 seat/room book
- Multuple test cases based on application functionality

##### (12) Input Data Validation
- Check for Reflected XSS using scanner, manual process using burp repeater
- Bypass XSS filter using OWASP XSS filter evasion cheatsheet
- Try Blind/Boolean/Error based SQL injection
- Find red, redirect, origin type of parameters and change their value to www.testinsane.com. Check for application behaviour via response
- Local file inclusion ../../../etc/passwd or ..//..//..//..//etc/passwd use KALI's dotdotpwn.pl perl script for the same
- Check for host header attack
- Check for LDAP injection
- Check for XML injection
- - Check for OS command injection: Use burp collobrator feature for the same (https://portswigger.net/burp/help/collaborator.html)

##### (13) Miscellaneous Test Cases
- Internal files leaked
- Internal IP disclosed
- Clickjacking vulnerability
- ASP.Net viewstate encrypted or not.
- Apache Multiview Attack
- Application does not display Last login time and date 
- Weak Etag disclosed
- Server side validation is not in place
- Sensitive Information gets stored in History 
- Oracle Padding attack ASPX
- Find metadata within object see if potential information is disclosed or not

##### (14) CAPTCHA Testing
- Identify parameters which are used to send CAPTCHA
- Captcha Replay attack
- Remove captcha parameter and send request to server
- Check whether the logic f or generating CAPTCHAs is there in a .js file itself?
- Captcha should not disclose absolute path
- Remove captcha element with firebug and send it
- Check with free-ocr tool
- Insert captcha check resposne if captcha value is false chaneg to true and forward resposne

##### (15) Testing Using Automated Scanners
- Burp scan
- Netsparker
- Acunetix
- IBM AppScan


