# certMe
Automatic generation of let's Encrypt Certificates


- **Install procedure** :

   - ` mvn clean install assembly:single `
   
   
- **Requirements** : 

  `openssl installed  + A server reacheable from the web on the port 80 or 443 ( if tls is activated )`


- **Command Example** :

```
  ❯ java -jar certMe.jar          \
         -outCertificate /opt/    \
         -challenge /war/www/html \
         -password crackeme       \
         -staging  PROD           \
         -alias my_app            \
         -jks  
```


- **Help Command** :

 ```
  ❯ java -jar target/certMe.jar -help
 ```
![certme](https://user-images.githubusercontent.com/7684497/49657828-def13200-fa40-11e8-8f21-57cfc394be3b.png)


- **Arguments** :
 ```
-domain         =  your_domain ( if not provided, it will be automatically processed )
-challenge      =  Where the challenge will be generated ( must be reacheable from the web on port 80 )
                   EX : /war/www/html                   
-outCertificate =  Where certificates will be generated ( include name of the certificate in the path ).
-password       =  password of the PKCS12 File.
-phrase         =  password of the JKS File 
                   ( optional, if not provided, it will be the same as the -password ).
-password       =  password of the PKCS12 File.
-phrase         =  password of the JKS File
                   ( optional, if not provided, it will be the same as the -password ).
-staging        =  Generate DEV / PROD Certificates ( By default : DEV ).
                   Nb : Only 50 PROD certificates are generated / Week
-jks            =  Import PKS12 into JKS  ( Java KeyStore ), ( Boolean. Disabled by default ).
-alias          = alias of the cert in the keystore

** Requirements  : openssl installed + server reacheable from the web on the port 80

Ex Command       :  java -jar certMe.jar          \
                          -outCertificate /opt/    \
                          -challenge /war/www/html \
                          -password crackeme       \
                          -staging  PROD           \
                          -alias jaxy              \
                          -jks  -alias jaxy     
```

**Upcoming Features :**

    - Get rid of OpenSSL
    - Get rid of the web server 
    
    
