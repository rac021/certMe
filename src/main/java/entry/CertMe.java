
package entry ;

/*
 * Java ACME client ++
 */

import java.io.File ;
import java.net.URI ;
import java.util.UUID ;
import java.io.Writer ;
import java.net.Socket ;
import org.slf4j.Logger ;
import java.util.Arrays ;
import java.io.FileReader ;
import java.io.FileWriter ;
import java.io.IOException ;
import java.nio.file.Files ;
import java.nio.file.Paths ;
import java.util.Collection ;
import java.net.InetAddress ;
import java.security.KeyPair ;
import java.security.Security ;
import org.slf4j.LoggerFactory ;
import java.net.InetSocketAddress ;
import org.shredzone.acme4j.Order ;
import org.shredzone.acme4j.Status ;
import org.shredzone.acme4j.Session ;
import org.shredzone.acme4j.Account ;
import java.util.concurrent.TimeUnit ;
import org.shredzone.acme4j.Certificate ;
import org.shredzone.acme4j.Authorization ;
import org.apache.log4j.BasicConfigurator ;
import org.shredzone.acme4j.AccountBuilder ;
import org.shredzone.acme4j.util.CSRBuilder ;
import org.shredzone.acme4j.util.KeyPairUtils ;
import org.shredzone.acme4j.challenge.Challenge ;
import org.shredzone.acme4j.exception.AcmeException ;
import org.shredzone.acme4j.challenge.Dns01Challenge ;
import org.shredzone.acme4j.challenge.Http01Challenge ;
import org.bouncycastle.jce.provider.BouncyCastleProvider ;

/**
 *
 * @author ryahiaoui
 */

public class CertMe {
    
    /** File name of the User Key Pair.      */
    private static  File USER_KEY_FILE        ;

    /** File name of the Domain Key Pair.    */
    private static  File DOMAIN_KEY_FILE      ;

    /** File name of the CSR0.               */
    private static  File DOMAIN_CSR_FILE      ;

    /** File name of the signed certificate. */
    private static  File DOMAIN_CHAIN_FILE    ;

    /** RSA key size of generated key pairs. */
    private static final int KEY_SIZE = 4096  ;

    private static String   STAGING   = "DEV" ;

   
    private enum ChallengeType { HTTP, DNS    }
    
    /** Challenge type to be used. */
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP   ;
    
    private static final Logger LOG = LoggerFactory.getLogger(CertMe.class ) ;
    
    /**
     * Generates a certificate for the given domains
     * Takes care for the registration process.
     *
     * @param domains
     *  Domains to get a common certificate for
     * @param targetChallengeToResolve
     * @throws java.io.IOException
     * @throws org.shredzone.acme4j.exception.AcmeException
     */
    private void fetchCertificate( Collection<String> domains, 
                                   String targetChallengeToResolve ) throws Exception {
        
        /** Load the user key file. If there is no key file, create a new one. */
        KeyPair userKeyPair = loadOrCreateUserKeyPair() ;

        Session session = null ;
        
        if( STAGING.equalsIgnoreCase("PROD") )             {
           session = new Session("acme://letsencrypt.org") ;
        }
        else {
           session = new Session("acme://letsencrypt.org/staging") ;
        }
        
        /** Get the Account 
         If there is no account yet, create a new one. */
        Account acct = findOrRegisterAccount(session, userKeyPair) ;

        /** Load or create a key pair for the domains
            This should not be the userKeyPair! .  */
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair() ;

        /** Order the certificate. */
        Order order = acct.newOrder().domains(domains).create() ;

        /** Perform all required authorizations. */
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth, targetChallengeToResolve )       ;
        }

        /** Generate a CSR for all of the domains, and sign it 
            with the domain key pair.     */
        CSRBuilder csrb = new CSRBuilder() ;
        csrb.addDomains(domains)           ;
        csrb.sign(domainKeyPair)           ;

        /** Write the CSR to a file, for later use. */
        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out) ;
        }

        /** Order the certificate.      */
        order.execute(csrb.getEncoded()) ;

        /** Wait for the order to complete. */
        try {
            
            int attempts = 10 ;
            
            while (order.getStatus() != Status.VALID && attempts-- > 0 )  {
                /** Did the order fail ? . */
                if (order.getStatus() == Status.INVALID) {
                    throw new AcmeException("Order failed... Giving up.") ;
                }

                /** Wait for a few seconds. */
                TimeUnit.SECONDS.sleep(3) ;

                /** Then update the status. */
                order.update()            ;
            }
            
        } catch (InterruptedException ex)       {
            LOG.error( "interrupted", ex )      ;
            Thread.currentThread().interrupt()  ;
        }

        /** Get the certificate. */
        Certificate certificate = order.getCertificate() ;

        if( certificate == null )
            throw new RuntimeException("Exeption when generating Certificate") ;
        
        LOG.info("Success! The certificate for domains " + domains + " has been generated ! ") ;
        LOG.info("Certificate URL : " + certificate.getLocation())                             ;

        /** Write a combined file containing the certificate and chain. */
        try ( FileWriter fw = new FileWriter(  DOMAIN_CHAIN_FILE ) ) {
            certificate.writeCertificate(fw) ;
        }
    }
    
    /**
     * Loads a user key pair from {@value #USER_KEY_FILE}, If the file does not 
     * exist, a new key pair is generated and saves 
     * Keep this key pair in a safe place! In a production environment, 
     * you will not be able to access your account again if you should lose  
     * the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair( ) throws IOException {
        
        if ( (USER_KEY_FILE).exists())                            {
            /** If there is a key file, read it. */
            try (FileReader fr = new FileReader(USER_KEY_FILE))   {
                return KeyPairUtils.readKeyPair(fr) ;
            }

        } else {
            /** If there is none, create a new key pair and save it.  */
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE) ;
            try (FileWriter fw = new FileWriter(USER_KEY_FILE))        {
                 KeyPairUtils.writeKeyPair(userKeyPair, fw)            ;
            }
            return userKeyPair ;
        }
    }

    /**
     * Loads a domain key pair from {@value #DOMAIN_KEY_FILE},  
     * If the file does not exist, a new key pair is generated
     * and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE))  {
                return KeyPairUtils.readKeyPair(fr) ;
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE) ;
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE))        {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw)             ;
            }
            return domainKeyPair ;
        }
    }

    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's public key. If your key is not
     * known to the server yet, a new account will be created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the URL and KeyIdentifier of your
     * new account with {@link Account#getLocation()} {@link Session#getKeyIdentifier()} and store it somewhere. If you
     * need to get access to your account later, reconnect to it via {@link Account#bind(Session, URI)} by using the
     * stored location.
     *
     * @param session
     * {@link Session} to bind with
     * @return {@link Login} that is connected to your account
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
       
       /** Ask the user to accept the TOS, if server provides us with a link 
        URI tos = session.getMetadata().getTermsOfService();
        if ( tos != null )      { 
           acceptAgreement(tos) ; 
        } .  */

        Account account = new AccountBuilder().agreeToTermsOfService()
                                              .useKeyPair(accountKey)
                                              .create(session)      ;
        
        LOG.info("Registered a new user, URL : " + account.getLocation()) ;

        return account ;
    }

    /** Authorize a domain, It will be associated with your account, so you will be 
     * able to retrieve a signed certificate for the domain later . 
     *
     * @param auth
     * {@link Authorization} to perform
     */
    private void authorize(Authorization auth, String targetChallenge ) throws Exception {
    
        LOG.info("Authorization for domain " + auth.getIdentifier().getDomain()) ;

        /** The authorization is already valid, No need to process a challenge . */
        if (auth.getStatus() == Status.VALID) {
            return ;
        }

        /** Find the desired challenge and prepare it. */
        Challenge challenge = null ;
        
        switch (CHALLENGE_TYPE)    {
            
            case HTTP :
                challenge = httpChallenge(auth, targetChallenge ) ;
                break ;

            case DNS :
                challenge = dnsChallenge(auth) ;
                break ;
        }

        if (challenge == null) {
            throw new AcmeException("No challenge found") ;
        }

        /** If the challenge is already verified, there's no need to 
         *  execute it again. */
        if (challenge.getStatus() == Status.VALID) {
            return ;
        }

        /** Now trigger the challenge. */
        challenge.trigger() ;

        /** Poll for the challenge to complete. */
        try {
            int attempts = 15 ;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0 )  {
                /** Did the authorization fail? . */
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.") ;
                }

                /** Wait for a few seconds. */
                TimeUnit.SECONDS.sleep(3) ;

                /** Then update the status. */
                challenge.update()        ;
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex)  ;
            Thread.currentThread().interrupt() ;
        }

        /** All reattempts are used up and there is still no valid authorization ?. */
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "  + 
                         auth.getIdentifier().getDomain() + ", ... Giving up.") ;
        }
    }

    /**
     * Prepares a HTTP challenge.
     * @param auth
     * {@link Authorization} to find the challenge in
     * @param targetFolder
     * @return {@link Challenge} to verify
     * @throws java.lang.Exception
     */
    public Challenge httpChallenge(Authorization auth , String targetFolder ) throws Exception  {
        /** Find a single http-01 challenge. */
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE) ;
        if (challenge == null) {
            throw new AcmeException( "Found no " + Http01Challenge.TYPE      +
                                     " challenge, don't know what to do...") ;
        }

        /** Output the challenge, wait for acknowledge... */
        LOG.info("Please create a file in your web server's base directory.") ;
        LOG.info( "It must be reachable at: http://" + auth.getIdentifier().getDomain() +
                  "/.well-known/acme-challenge/" + challenge.getToken()) ;
        LOG.info("File name: " + challenge.getToken())         ;
        LOG.info("Content: "   + challenge.getAuthorization()) ;
        LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!") ;
        LOG.info("If you're ready, dismiss the dialog...");

        StringBuilder message = new StringBuilder() ;
        message.append("Please create a file in your web server's base directory.\n\n") ;
        message.append("http://").append(auth.getIdentifier().getDomain())
               .append("/.well-known/acme-challenge/")
               .append(challenge.getToken()).append("\n\n") ;
        message.append("Content:\n\n")                      ;
        message.append(challenge.getAuthorization())        ;
        
        File dir = new File(targetFolder + ".well-known/")  ;
        dir.mkdir()                                         ;
        
        dir = new File(targetFolder + ".well-known/acme-challenge/" ) ;
        dir.mkdir()                                                   ;
        
        File f = new File( dir.getAbsoluteFile() + "/" + challenge.getToken() ) ;
        
        print(" Created Fil.. Location : " + f.getPath() )            ;
        
        Files.write(Paths.get(f.getPath()), challenge.getAuthorization().getBytes()) ;
        
        /** acceptChallenge(message.toString()) ; . */

        return challenge ;
    }

    /**
     * Prepares a DNS challenge.
     * <p>
     * The verification of this challenge expects a TXT record with a certain content. 
     * <p>
     * This example outputs instructions that need to be executed manually. 
     * In a production environment, you would rather configure your DNS automatically.
     *
     * @param auth
     *            {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     * @throws org.shredzone.acme4j.exception.AcmeException
     */
    
    public Challenge dnsChallenge(Authorization auth) throws AcmeException   {
        
        /** Find a single dns-01 challenge. */
        Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE)   ;
        if (challenge == null) {
            throw new AcmeException( "Found no " + Dns01Challenge.TYPE +
                                     " challenge, don't know what to do...") ;
        }

        /** Output the challenge, wait for acknowledge... */
        LOG.info( "Please create a TXT record:") ;
        LOG.info( "_acme-challenge." + auth.getIdentifier().getDomain()+ ". IN TXT " 
                  + challenge.getDigest()) ;

        /** LOG.info("If you're ready, dismiss the dialog...") ; . */

        StringBuilder message = new StringBuilder()       ;
        message.append("Please create a TXT record:\n\n") ;
        message.append("_acme-challenge.")
               .append(auth.getIdentifier()
               .getDomain()).append(". IN TXT ")
               .append(challenge.getDigest())             ;
        
        /** acceptChallenge(message.toString()) ; .      */

        return challenge ;
    }

    /**
     * Presents the instructions for preparing the challenge validation, and waits 
     * for dismissal.If the user cancelled the dialog, an exception is thrown.
     */
    /*
    public void acceptChallenge(String message) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null, message, "Prepare Challenge", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.CANCEL_OPTION) {
            throw new AcmeException("User cancelled the challenge");
        }
    }
    /** Presents the user a link to the Terms of Service, and asks for confirmation 
       If the user denies confirmation, an exception is thrown . */
    /*
    public void acceptAgreement(URI agreement) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null, "Do you accept the Terms of Service?\n\n" + agreement,
                "Accept ToS", JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            throw new AcmeException("User did not accept Terms of Service");
        }
    }
    */
    
    /**
     * @return String
     * @throws java.lang.Exception
    */
    public static String getDomain() throws Exception {

        try (final Socket socket = new Socket())      {
            
            socket.connect(new InetSocketAddress("google.com", 80)) ;
            
            String IP_ADRESS = socket.getLocalAddress()
                                     .toString()
                                     .replace("/", "") ;
            
            InetAddress inetAddr = InetAddress.getByName(IP_ADRESS) ;

	    return inetAddr.getCanonicalHostName()  ;
		
        } catch (Exception ex) {
            throw  ex          ;
        }
    }    
    
    /**   @param domain
     *    @param targetChalengeToResolve
     */
    public static void resolveChallengeAndFetchCert( String domain , 
                                                     String targetChalengeToResolve )     {
        
        double version = Double.valueOf(System.getProperty("java.specification.version")) ;

        if ( version == 1.8 ) {
            // Command to install cacerts in /etc/ssl/certs/java
            // sudo dpkg --purge --force-depends ca-certificates-java
            // sudo apt-get install ca-certificates-java
            boolean minVarsion_111 = System.getProperty("java.runtime.version")
		                           .contains("0_111")                 ;
            
            if (minVarsion_111 )                                                   {
                    
                String randoPass = UUID.randomUUID().toString()                    ;
                print(" Set properties ... Location : cacerts ")                   ;
                System.setProperty("javax.net.ssl.trustStore", "cacerts")          ;
                System.setProperty("javax.net.ssl.trustStorePassword", "changeit") ;
                System.setProperty("javax.net.ssl.keyStorePassword", randoPass)    ;
                print(" Generated Password : " + randoPass)                        ;
            } 
                
        }

        LOG.info("Starting up...")                         ;

        Security.addProvider(new BouncyCastleProvider())   ;

        Collection<String> domains = Arrays.asList(domain) ;
        
        try {
              CertMe ct = new CertMe()               ;
              ct.fetchCertificate( domains, targetChalengeToResolve  ) ;
        } catch (Exception ex) {
            LOG.error( "Failed to get a certificate for domains " + domains, ex) ;
        }
    }
    
    /** Convert and Register Cert in P12 format.
     * @param certificate
     * @param password
     * @param alias
     * @param jks
     * @throws java.io.IOException */
    public static void convAndRegisterP12Cert( String  certificate , 
                                               String  password    , 
                                               String  alias       ,
                                               boolean jks         ) throws IOException, Exception{
        
        if( alias == null ) alias = "alias_name"                 ;
        
        String domainCert =  DOMAIN_CHAIN_FILE.getAbsolutePath() ;
        String domainKey  =  DOMAIN_KEY_FILE.getAbsolutePath()   ;
        
        print(" ====================================== " )       ;
        print(" domainCert path --> " + domainCert       )       ;
        print(" domainKey  path --> " + domainKey        )       ;
        print(" pkcs12File path --> " + certificate      )       ;
        print(" password        -->  **********        " )       ;
        print(" ====================================== " )       ;

        /** Openssl command; Must be already installed on the machine. */
        
        String[] cmd = new String[] { "openssl"          ,
                                      "pkcs12"           ,
                                      "-export"          ,
                                      "-in"              ,
                                      domainCert         ,
                                      "-inkey"           ,
                                      domainKey          ,
                                      "-out"             ,
                                      certificate        ,
                                      "-password"        ,
                                      "pass:" + password ,
                                      "-name"            , 
                                      alias            } ;
        execute( cmd )                                    ;
       
        if( jks ) {
          PKCS12Importer.imports( certificate , "jaxy_cert.jks" , password ) ;
       }
    }

     
    /** Execute the commands. */
    private static void execute(String[] command) {
        try {
            printCommand(command)                 ;
           Runtime.getRuntime().exec(command)     ;
        } catch (IOException ex)                  {
            LOG.error(ex.getMessage() )           ;
        }
    }
     
    /** Print the command. */
    private static void printCommand(String[] command) {
       print( "                       " )              ;
       print(Arrays.toString(command)   )              ;
       print( "                       " )              ;
    }
    
    private static void printHelp() {
        
      print("                                                                                                          " ) ;
      print(" -domain          =  your_domain ( if not provided, it will be automatically processed )                  " ) ;
      print(" -challenge       =  Where the challenge will be generated ( must be reacheable from the web on port 80 ) " ) ;
      print("                     EX : /war/www/html                                                                   " ) ;
      print(" -outCertificate  =  output certificate ( include int the path the name of the certificate )              " ) ;
      print(" -password        =  password of the PKCS12 File                                                          " ) ;
      print(" -phrase          =  password of the JKS File ( if not provided, it will be the same as -password )       " ) ;
      print(" -staging         =  Generate DEV / PROD Certificates ( By default : DEV )                                " ) ;
      print("                     Nb : Only 50 PROD certificates are generated / Week                                  " ) ;
      print(" -jks             =  Import PKS12 into JKS  ( Java KeyStore ), ( Boolean. Disabled by default )           " ) ;
      print(" -alias           =  alias of the cert in the keystore                                                    " ) ;
      print("                                                                                                          " ) ;
      print(" ** Requirements  : openssl installed + server reacheable from the web on the port 80                     " ) ;
      print("                                                                                                          " ) ;
      print("  Ex Command      :  java -jar certMe.jar            \\                                                   " ) ;
      print("                          -outCertificate /opt/      \\                                                   " ) ;
      print("                          -challenge /war/www/html   \\                                                   " ) ;
      print("                          -password crackeme         \\                                                   " ) ;
      print("                          -staging  PROD             \\                                                   " ) ;
      print("                          -alias jaxy                \\                                                   " ) ;
      print("                          -jks  -alias jaxy                                                               " ) ;
      print("                                                                                                          " ) ;
      System.exit(0)                                                                                                       ;
    }
    
    private static void print( String message ) {
        
        System.out.println(message )            ;
    }
    
    /**
     * Invokes this Client.
     *
     * @param args
     *  Domains to get a certificate for
     * @throws java.lang.Exception
     */
    public static void main(String... args) throws Exception {

        BasicConfigurator.configure() ;
        org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.INFO) ;
        
        String domain           = null  , 
               destChallenge    = null  , 
               password         = null  ,
               phrase           = null  ,
               alias            = null  ,
               outCertificate   = null  ;
        
        boolean jks             = false ;
        
        for ( int i = 0 ; i < args.length ; i++ ) {
            
        String token = args[i] ;
           
            switch(token)      {

               case "-domaim"         :  domain          = args[i+1] ; break ;
               case "-challenge"      :  destChallenge   = args[i+1] ; break ;
               case "-password"       :  password        = args[i+1] ; break ;                
               case "-phrase  "       :  phrase          = args[i+1] ; break ;                
               case "-outCertificate" :  outCertificate  = args[i+1] ; break ;                
               case "-staging"        :  STAGING         = args[i+1] ; break ;                
               case "-jks"            :  jks             = true      ; break ;                
               case "-alias"          :  alias           = args[i+1] ; break ;               
               case "-help"           :  printHelp()                         ; 
               case "help"            :  printHelp()                         ;
            }
        }
        
        if( destChallenge   == null )  destChallenge = "/var/www/html/"   ;
        
        if( domain          == null )  domain       = getDomain()         ;  
        
        if( phrase          == null )  phrase = password                  ;
        
        if( domain  == null ||  password == null )  {  printHelp()   ;    }
        
        String outCertificateFolder   = new File(CertMe.class.getProtectionDomain()
                                                             .getCodeSource()
                                                             .getLocation().getPath())
                                                             .getParentFile()
                                                             .getPath() + File.separator ;
        String outCertificateFileName = "app_cert.p12" ;
        
        if ( outCertificate == null || 
            outCertificate.trim().equalsIgnoreCase(outCertificateFolder.trim()) )  {
            
            outCertificate  =  outCertificateFolder ;
            
        } else {
            
            if ( Files.isRegularFile(Paths.get(outCertificate)))               {
                File out               =  new File( outCertificate )           ;
                outCertificateFolder   = out.getParentFile().getAbsolutePath() ;
                outCertificateFileName = out.getName()                         ;
            }
            
            else if ( Files.isDirectory(Paths.get(outCertificate)) )                       {
                outCertificateFolder = outCertificate                                      ;
                outCertificate       =   ( outCertificateFolder.endsWith ( File.separator) ?
                                           outCertificateFolder.trim() :
                                           outCertificateFolder.trim() + File.separator    ) 
                                          + outCertificateFileName                         ;
            }
        }
	    
        if ( ! outCertificateFolder.endsWith( File.separator ) )                { 
           outCertificateFolder = outCertificateFolder.trim() + File.separator  ;
        }

         /** File name of the User Key Pair. */
        USER_KEY_FILE = new File( outCertificateFolder   + outCertificateFileName +"_user.key")     ;

        /** File name of the Domain Key Pair. */
        DOMAIN_KEY_FILE = new File( outCertificateFolder + outCertificateFileName + "_domain.key")  ;

        /** File name of the CSR. */
        DOMAIN_CSR_FILE = new File( outCertificateFolder + outCertificateFileName + "_domain.csr")  ;

        /** File name of the signed certificate. */
        DOMAIN_CHAIN_FILE = new File( outCertificateFolder + outCertificateFileName + "_domain-chain.crt")      ;
        
        destChallenge = destChallenge.endsWith(File.separator) ? destChallenge : destChallenge + File.separator ;
                 
        resolveChallengeAndFetchCert( domain , destChallenge )        ;
        
        convAndRegisterP12Cert( outCertificate, phrase , alias, jks ) ;
        
    }
}

