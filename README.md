# certMe
Let's Encrypt Automatic Certificate generator tool

----------

### * Using Docker Command : [Docker Hub CertMe Image](https://hub.docker.com/r/rac021/cert-me)  : 
 - Ex : ( Generate **APP.p12** + **APP.jks** Certificates for the domain **myDomain** in the directory : **letsEncrypt_Cert** ) 
```
 sudo docker run --rm --name cert-me -p 80:80                                \
                 -v $(pwd)/letsEncrypt_Cert:/usr/src/myapp/letsEncrypt_Cert/ \
                 rac021/cert-me                                              \
                 -domain myDomain.com -jks -staging PROD 
 
```
* **Nb** : Need to have **Root privileges** in roder to use the port **80**

----------

### * Using Standalone tool :

- **Install procedure** :

   - ` mvn clean install assembly:single `
   
   
- **Requirements** : 

   - `openssl installed  + root privileges in order to use the port 80 `


- **Command Example** :

  Generate **APP.p12** + **APP.jks** Certificates for the domain **myDomain** in the directory : **letsEncrypt_Cert**

```
  ❯ java -jar certMe-1.0-jar-with-dependencies.jar  \
         -out letsEncrypt_Cert/                     \
         -password_pkcs12 myPkcs12Password          \
         -password_jks    myJksPassword             \
         -staging  PROD                             \
         -alias myAppAlias                          \
         -port 80                                   \
         -domain myDomain                           \
         -jks  
  
  ```

- **Help Command** :

 ```
  ❯ java -jar target/certMe.jar -help
 ```

![certMe-Cmd](https://user-images.githubusercontent.com/7684497/83452856-c9a06c80-a459-11ea-984e-b1d68ed00a0c.jpg)


- [**Arguments**](https://user-images.githubusercontent.com/7684497/83450268-3f560980-a455-11ea-8b37-aca5af00ee9a.jpg) :
 ```
-domain           =  your_domain ( if not provided, it will be automatically processed )
-out              =  Where certificates will be generated ( include name of the certificate in the path ).
-password_pkcs12  =  password of the PKCS12 File ( if not provided, it will be generated using UUID     )
-pawword_jks      =  password of the JKS File 
                     ( optional, if not provided, it will be the same as the -password_pkcs12 ).
-staging          =  Generate DEV / PROD Certificates ( By default : DEV ).
                     Nb : Only 50 PROD certificates are generated / Week
-jks              =  Import PKS12 into JKS  ( Java KeyStore ), ( Boolean. Disabled by default ).
-log / -log_level =  Set Log Level : WARN, TRACE, OFF, INFO, ERROR, DEBUG, ALL.
-user_key_file    =  Path of USER_KEY_FILE. Used to Renew Existing Certificiate.
-reuse_key        =  If a KEY-PAIR Already exists, then reuse, else generate new one.
-alias            =  alias of the Jks Cert in the keystore
-port             =  port used by the server ( Must Be 80 for letsEncrypt Challenge )
-interface        =  Interface of the Server ( default : 0.0.0.0                    )

** Requirements  : openssl installed.

Ex Command   : java -jar certMe.jar                    \
                    -out letsEncrypt_Cert/             \
                    -password_pkcs12 myPkcs12Password  \
                    -password_jks    myJksPassword     \
                    -staging  PROD                     \
                    -alias myAppAlias                  \
                    -port 80                           \
                    -domain myDomain                   \
                    -jks 
```

**Upcoming Features :**

   - Get rid of OpenSSL ( for pkcs12 cert )
   - ~~Get rid of the web server~~
    
