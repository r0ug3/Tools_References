# Important WebApp Secure Code Review Assessment Keywords
#### Authentication
- password
- impersonate
- get.Local.Host()

#### Session Management
  - cookie.secure
  - secure
  - httpOnly
  - requireSSL
  - timeout
  - method
  
#### Encryption
  - RC4
  - md5
  - keyGen
  - random
  - base64

#### Error Codes
  - On Error
  - Exception
  - catch
  - system.out.printline

####Data Transmission
  - get
  - trace
  - allowNetworking 
  - http
  - allowDomain()
  - allowScriptAccess 

#### Information Disclosure
  - Debug
  - trace()
  - master
  - visa
  - method="GET"
  - location.href
  - cc
  - stacktrace

#### Database Security
  - execute
  - delete
  - executeQuery
  - Server.Create.Object
  - GetString
  - SqlDataAdapter

##### Input Validation - Injection Attack
  - InputStream
  - FileInputStream 
  - java.io.FileReader 
  - java.io.FileWriter 
  - java.io.File 
  - request.url 
  - request.files 
  - request.getParameter 
  - FlashVar
  - getURL()
  - navigateToURL()

#### Output Validation - XSS and Other Attacks
  - respone.write
  - UrlEncode
  - HtmlEncode 
  - innerHTML
