
package letsencrypt ;

/**
 *
 * @author ryahiaoui
 */

import java.io.File ;
import java.net.URI ;
import java.util.UUID ;
import java.io.Writer ;
import java.util.List ;
import java.net.Socket ;
import java.util.HashSet ;
import java.io.FileReader ;
import java.io.FileWriter ;
import java.nio.file.Path ;
import java.util.ArrayList;
import java.io.IOException ;
import java.nio.file.Files ;
import java.nio.file.Paths ;
import io.undertow.Undertow ;
import java.net.InetAddress ;
import java.security.KeyPair ;
import java.security.Security ;
import java.io.BufferedWriter ;
import java.util.regex.Pattern ;
import org.slf4j.LoggerFactory ;
import io.undertow.util.Headers ;
import org.shredzone.acme4j.Order ;
import java.net.InetSocketAddress ;
import org.shredzone.acme4j.Login ;
import org.shredzone.acme4j.Status ;
import org.shredzone.acme4j.Session ;
import org.shredzone.acme4j.Account ;
import java.util.concurrent.TimeUnit ;
import org.apache.logging.log4j.Level ;
import org.apache.logging.log4j.Logger;
import org.apache.commons.io.FileUtils ;
import org.shredzone.acme4j.Certificate ;
import org.shredzone.acme4j.Authorization ;
import org.apache.logging.log4j.LogManager ;
import org.shredzone.acme4j.AccountBuilder ;
import org.shredzone.acme4j.util.CSRBuilder ;
import io.undertow.server.HttpServerExchange ;
import org.shredzone.acme4j.util.KeyPairUtils ;
import org.shredzone.acme4j.challenge.Challenge ;
import java.nio.file.attribute.PosixFilePermission ;
import org.shredzone.acme4j.exception.AcmeException ;
import org.shredzone.acme4j.challenge.Dns01Challenge ;
import org.shredzone.acme4j.challenge.Http01Challenge ;
import org.apache.logging.log4j.core.config.Configurator ;
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
    
    /** File name PEM . */
    private static  File DOMAIN_PEM_FILE      ;

    /** RSA key size of generated key pairs. */
    private static final int KEY_SIZE = 4096  ;

    private static String   STAGING   = "DEV" ;

    private enum ChallengeType {  HTTP, DNS   }
  
    private Undertow server = null ;
  
    public static final String ANSI_RESET  = "\u001B[0m"  ;
    public static final String ANSI_BLACK  = "\u001B[30m" ;
    public static final String ANSI_RED    = "\u001B[31m" ;
    public static final String ANSI_GREEN  = "\u001B[32m" ;
    public static final String ANSI_YELLOW = "\u001B[33m" ;
    public static final String ANSI_BLUE   = "\u001B[34m" ;
    public static final String ANSI_PURPLE = "\u001B[35m" ;
    public static final String ANSI_CYAN   = "\u001B[36m" ;
    public static final String ANSI_WHITE  = "\u001B[37m" ;

    private void startServer( String interfce , int port, Http01Challenge challenge ) throws InterruptedException {
        
        LOG.info(" ") ;
        
        try {
            
             LOG.info("Starting The Server on Port ( " + interfce + ":" + port  + " ) Using HTTP  ") ;
             Undertow.Builder builder = Undertow.builder()                          ;
             builder.addHttpListener( port, interfce )                              ;
             
             server = builder.setHandler(( final HttpServerExchange exchange ) ->   {
                                         exchange.setRequestPath( "/.well-known/acme-challenge/"              ) ;
                                         exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain" ) ;
                                         exchange.getResponseSender().send( challenge.getAuthorization()      ) ;
                                         LOG.info( "Server Called ! ( Probably By Let's Encrypt ) "           ) ;
                              }).build()     ;
            
            server.start()                   ;
            
            LOG.info("Server Started ! "   ) ;
            
        } catch( Exception ex ) {
            LOG.error( " ") ;
            LOG.error( ex.getMessage(), ex ) ;
            
            if( port < 1024 )   {
               LOG.error( "Need to be Root To Start the Server on the Port : " + port )  ;
            }
            LOG.error( " ")     ;
            System.exit( 2 )    ;
        }
    }

    private void stopServer() {
        LOG.info( "Stopping the Server.. " ) ;
        if( server != null )  server.stop( ) ;
        LOG.info( "Server Stoped !"        ) ;
    }

    private  static void authorizeAccessToAllCert( List<String> files ) {
        
           //Setting file permissions for owner, group and others using PosixFilePermission
           
            HashSet<PosixFilePermission> set = new HashSet<>() ;
             
            //Adding owner's file permissions
             
            set.add(PosixFilePermission.OWNER_EXECUTE) ;
            set.add(PosixFilePermission.OWNER_READ)    ;
            set.add(PosixFilePermission.OWNER_WRITE)   ;
             
            //Adding group's file permissions
             
            set.add(PosixFilePermission.GROUP_EXECUTE) ;
            set.add(PosixFilePermission.GROUP_READ)    ;
            set.add(PosixFilePermission.GROUP_WRITE)   ;
             
            //Adding other's file permissions
             
            set.add(PosixFilePermission.OTHERS_EXECUTE) ;
            set.add(PosixFilePermission.OTHERS_READ)    ;
            set.add(PosixFilePermission.OTHERS_WRITE)   ;
             
            files.forEach( file -> {
                
               try {
                  
                  if( Files.isRegularFile( Path.of(file )  ) ||
                      Files.isDirectory  ( Path.of(file )) ) {
                      LOG.info( "Authorize Access File : " +   file          ) ;
                      Files.setPosixFilePermissions(Paths.get( file ) , set  ) ;
                  } else {
                      LOG.error( "File : " + file + " -- Doesn't Exists !! " ) ;
                  }

               } catch ( IOException ex )   {
                   LOG.error( ex.getMessage(), ex) ;
               }
            } ) ;
    }
   
    /** Challenge type to be used. */
    private static final ChallengeType CHALLENGE_TYPE = ChallengeType.HTTP   ;
  
     private static final Logger LOG = LogManager.getLogger( CertMe.class.getName() ) ;
 
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
    private void fetchCertificate( String  domain    , 
                                   int     port      ,
                                   String  interfce  , 
                                   boolean reuseKey  ) throws Exception {
        
        /** Load the user key file. If there is no key file, create a new one. */
        KeyPair userKeyPair = loadOrCreateUserKeyPair( reuseKey ) ;

        Session session = null ;
        
        if( STAGING.equalsIgnoreCase("PROD") )             {
           session = new Session("acme://letsencrypt.org") ;
        }
        else {
           session = new Session("acme://letsencrypt.org/staging") ;
        }
        LOG.warn( "STAGING :  [[ " + STAGING  + " ]] " )           ;
        
        /** Get the Account 
         If there is no account yet, create a new one. */
        Account acct = findOrRegisterAccount(session, userKeyPair) ;

        /** Load or create a key pair for the domains
            This should not be the userKeyPair! .  */
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair()    ;

        /** Order the certificate. */
        Order order = acct.newOrder().domains(domain).create() ;

        /** Perform all required authorizations. */
        for (Authorization auth : order.getAuthorizations())   {
            authorize(auth , interfce, port  )       ;
        }

        /** Generate a CSR for all of the domains, and sign it 
            with the domain key pair.     */
        CSRBuilder csrb = new CSRBuilder() ;
        csrb.addDomains(domain)            ;
        csrb.sign(domainKeyPair)           ;

        /** Write the CSR to a file, for later use. */
        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out) ;
        }

        /** Order the certificate.      */
        order.execute(csrb.getEncoded()) ;

        /** Wait for the order to complete. */
        try {
            
            int attempts = 60 ;
            
            while (order.getStatus() != Status.VALID && attempts-- > 0 ) {
                
                /** Did the order fail ? . */
                if (order.getStatus() == Status.INVALID) {
                    LOG.error( "-+> " + order.getError().toString()    ) ;
                }

                /** Wait for a few seconds. */
                TimeUnit.SECONDS.sleep( 2 )  ;

                /** Then update the status. */
                order.update()               ;
            }
            if ( order.getStatus() != Status.VALID && attempts-- > 0 ) {
                 throw new AcmeException("Order failed... Giving up." ) ;
            }
        } catch (InterruptedException ex)       {
            LOG.error( "interrupted", ex )      ;
            Thread.currentThread().interrupt()  ;
        }

        /** Get the certificate. */
        Certificate certificate = order.getCertificate() ;

        if( certificate == null )
            throw new RuntimeException("Exeption when generating Certificate") ;

        LOG.info("Success ! The certificate for domain [[ " + domain + " ]] Has Been Generated :-) ") ;
        LOG.info("Certificate URL : " + certificate.getLocation())                                    ;


        /** Write a combined file containing the certificate and chain. */
        try ( FileWriter fw = new FileWriter ( DOMAIN_CHAIN_FILE ) ) {
              certificate.writeCertificate(fw) ;
        }
        
        /** CREATE PEM_FILE . */
        Path outpu_pem_path = DOMAIN_PEM_FILE.toPath() ;
        try (BufferedWriter writer = Files.newBufferedWriter(outpu_pem_path)) {
            String app_crt_content = Files.readString( DOMAIN_CHAIN_FILE.toPath() ) ;
            writer.write(app_crt_content) ;
            String app_key_content = Files.readString( DOMAIN_KEY_FILE.toPath()   ) ;
            writer.write(app_key_content) ;
        }
        
        /** Manage Authorizations. */
        List<String> files = new ArrayList<>()                    ;
        // Authorization for the directory
        files.add( DOMAIN_PEM_FILE.getAbsoluteFile().getParent()) ;       
        // Authorization for CERTs
        files.add( DOMAIN_KEY_FILE.getAbsolutePath())             ;
        files.add( DOMAIN_CSR_FILE.getAbsolutePath())             ;
        files.add( DOMAIN_CHAIN_FILE.getAbsolutePath())           ;       
        files.add( DOMAIN_PEM_FILE.getAbsolutePath())             ;

        if( USER_KEY_FILE.getAbsolutePath()
                         .equals("/tmp/domain-user.key" ) ) {
            // Copy the domain_user_key into the output Dir
            String outDir = DOMAIN_KEY_FILE.getParent()   ;
            String userKeyFileNewPath = outDir            + 
                                        File.separator    +
                                       "domain-user.key"  ;
            LOG.info( "Copy " + USER_KEY_FILE + " TO : "  + 
                      userKeyFileNewPath ) ;
            FileUtils.copyFileToDirectory( USER_KEY_FILE  ,
                                           new File(outDir) ) ;
            USER_KEY_FILE = new File( userKeyFileNewPath  )   ;
        } 
        
        files.add( DOMAIN_PEM_FILE.getAbsolutePath())         ;
        
        try {
            authorizeAccessToAllCert( files ) ;    
        } catch( Exception ex ) {
            throw new RuntimeException(ex)    ;
        }
        
        // Stop the server
        stopServer() ;
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
    private KeyPair loadOrCreateUserKeyPair ( boolean reuseKey ) throws IOException {
        
        if( reuseKey && USER_KEY_FILE.exists() ) {
            LOG.info( "+ Reuse the already existing KEY-PAIR : " + 
                      USER_KEY_FILE.getAbsolutePath() )      ;
            /** If there is a key file, read it. */
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr) ;
            }
        } else {
            /** If there is none, create a new key pair and save it.  */
            LOG.info( "+ Create a new KEY PAIR : "       + 
                      USER_KEY_FILE.getAbsolutePath() )  ;
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE) ;
            try (FileWriter fw  = new FileWriter(USER_KEY_FILE))       {
                 KeyPairUtils.writeKeyPair(userKeyPair, fw )           ;
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
        } . **/

        Account account = new AccountBuilder().agreeToTermsOfService()
                                              .useKeyPair(accountKey)
                                              .create(session)      ;

        LOG.info("Registered user, URL : " + account.getLocation()) ;

        return account ;
    }

    /** Authorize a domain, It will be associated with your account, so you will be 
     * able to retrieve a signed certificate for the domain later . 
     *
     * @param auth
     * {@link Authorization} to perform
     */
    private void authorize(Authorization auth, String interfce, int port ) throws Exception {
    
        LOG.info("Authorization for domain [[ " + auth.getIdentifier().getDomain() + " ]] ") ;

        /** The authorization is already valid, No need to process a challenge . */
        if (auth.getStatus() == Status.VALID) {
            return ;
        }

        /** Find the desired challenge and prepare it. */
        Challenge challenge = null ;
        
        switch ( CHALLENGE_TYPE )  {
            
            case HTTP -> {
                challenge = httpChallenge(auth )                               ;
                startServer( interfce , port , ( Http01Challenge ) challenge ) ;
            }

            case DNS -> challenge = dnsChallenge( auth )   ;
        }

        if ( challenge == null ) {
             throw new AcmeException("No challenge found") ;
        }

        /** If the challenge is already verified, there's no need to 
         *  execute it again. */
        if ( challenge.getStatus() == Status.VALID ) {
             return ;
        }

        /** Now trigger the challenge. */
        challenge.trigger() ;

        /** Poll for the challenge to complete. */
        try {
            int attempts = 15 ;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0  ) {
                /** Did the authorization fail? . */
                if (challenge.getStatus() == Status.INVALID)                  {
                    LOG.error( "x-> " + challenge.getError().toString()     ) ;
                    throw new AcmeException("Challenge failed... Giving up.") ;
                }

                /** Wait for a few seconds. */
                TimeUnit.SECONDS.sleep(2) ;

                /** Then update the status. */
                challenge.update()        ;
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex)  ;
            Thread.currentThread().interrupt() ;
        }

        /** All reattempts are used up and there is still no valid authorization ?. */
        if (challenge.getStatus() != Status.VALID) {
            LOG.error( "-> " + challenge.getError().toString()  )               ;
            throw new AcmeException("Failed to pass the challenge for domain "  + 
                         auth.getIdentifier().getDomain() + ", ... Giving up.") ;
        }
    }

    /**
     * Prepares a HTTP challenge.
     * @param auth
     * {@link Authorization} to find the challenge in
     * @return {@link Challenge} to verify
     * @throws java.lang.Exception
     */
    public Challenge httpChallenge(Authorization auth ) throws Exception     {
        
        /** Find a single http-01 challenge. */
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE) ;
        if (challenge == null) {
            throw new AcmeException( "Found no " + Http01Challenge.TYPE      +
                                     " challenge, don't know what to do...") ;
        }

        /** Output the challenge, wait for acknowledge... */
        LOG.info("Please create a file in your web server's base directory.") ;
        LOG.info("It must be reachable at   : http://" + auth.getIdentifier().getDomain()         +
                  "/.well-known/acme-challenge/"  + challenge.getToken())                         ;
        LOG.info("File name                 : "   + challenge.getToken())                         ;
        LOG.info("Content                   : "   + challenge.getAuthorization())                 ;
        LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!") ;
        LOG.info("If you're ready, dismiss the dialog... "  )                                     ;
        
        StringBuilder message = new StringBuilder()         ;
        message.append( "Please create a file in your web server's base directory.\n\n") ;
        message.append( "http://").append(auth.getIdentifier().getDomain())
               .append( "/.well-known/acme-challenge/"     )
               .append( challenge.getToken()).append("\n\n") ;
        message.append( "Content:\n\n"                     ) ;
        message.append( challenge.getAuthorization()       ) ;
       
        return challenge                                     ;
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
        if (challenge == null)   {
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
            
            socket.connect(new InetSocketAddress("google.com", 80 )) ;
            
            String IP_ADRESS = socket.getLocalAddress()
                                     .toString()
                                     .replace("/", "") ;
            
            InetAddress inetAddr = InetAddress.getByName(IP_ADRESS) ;

	    return inetAddr.getCanonicalHostName()  ;
		
        } catch (Exception ex) {
            throw  ex          ;
        }
    }    
    
    /** *    @param domain
     * @param port
     * @param interfce
     * @param reuseKey
     */
    public static void resolveChallengeAndFetchCert( String  domain   , 
                                                     int     port     , 
                                                     String  interfce , 
                                                     boolean reuseKey ) {
        
        double version = Double.parseDouble(System.getProperty("java.specification.version")) ;

        if ( version == 1.8 ) {
            // Command to install cacerts in /etc/ssl/certs/java
            // sudo dpkg --purge --force-depends ca-certificates-java
            // sudo apt-get install ca-certificates-java
            boolean minVarsion_111 = System.getProperty("java.runtime.version")
		                           .contains("0_111")                 ;
            
            if (minVarsion_111 )                                                   {
                    
                String randoPass = UUID.randomUUID().toString()                    ;
                LOG.info (" Set properties ... Location : cacerts ")               ;
                System.setProperty("javax.net.ssl.trustStore", "cacerts")          ;
                System.setProperty("javax.net.ssl.trustStorePassword", "changeit") ;
                System.setProperty("javax.net.ssl.keyStorePassword", randoPass   ) ;
                LOG.info (" Generated Password : " + randoPass                   ) ;
            } 
        }

        LOG.info("Starting up...")                         ;

        Security.addProvider(new BouncyCastleProvider())   ;
        
        try {
             CertMe ct = new CertMe()                      ;
             ct.fetchCertificate( domain , port , interfce , reuseKey ) ;
        } catch (Exception ex) {
            LOG.error( " " )   ;
            LOG.error( "Failed to get a certificate for domain [[ "   + 
                       domain + " ]] ", ex                        )   ;
            LOG.error( " " )   ;
            System.exit( 1 )   ;
        }
    }
    
    /** Convert and Register Cert in P
     * @param pkcs12cert
     * @param pkcs12Password
     * @param alias
     * @param jks
     * @param jksPassword
     * @throws java.io.IOException */
    public static void convAndRegisterP12Cert( String  pkcs12cert     , 
                                               String  pkcs12Password , 
                                               String  alias          ,
                                               boolean jks            ,
                                               String  jksPassword    ) throws IOException, Exception{
        
        if( alias == null ) alias = "appAliasNameCertMe"          ;
        
        String domainCert =  DOMAIN_CHAIN_FILE.getAbsolutePath()  ;
        String domainKey  =  DOMAIN_KEY_FILE.getAbsolutePath()    ;
        
        LOG.info("                                        " )     ;
        LOG.info("Generate Pkcs12 from  : " +  domainCert   )     ;
        LOG.info("Out      Pkcs12       : " +  pkcs12cert   )     ;
        LOG.info("                                        " )     ;

        LOG.info(" ====================================="   +
              "===============================================" ) ;
        
        LOG.info(" domainCert path --> " + domainCert       )     ;
        LOG.info(" domainKey  path --> " + domainKey        )     ;
        LOG.info(" pkcs12File path --> " + pkcs12cert       )     ;
        LOG.info(" password_pkcs12 --> " + pkcs12Password   )     ;
        
        LOG.info(" ====================================="   +
              "===============================================" ) ;
        LOG.info("                                        " )     ;

        /** Openssl command; Must be already installed on the machine. */
      
        String[] cmd = new String[] { "openssl"          ,
                                      "pkcs12"           ,
                                      "-export"          ,
                                      "-in"              ,
                                      domainCert         ,
                                      "-inkey"           ,
                                      domainKey          ,
                                      "-out"             ,
                                      pkcs12cert         ,
                                      "-password"        ,
                                      "pass:" + pkcs12Password ,
                                      "-name"            , 
                                      alias            } ;
        execute( cmd )                                   ;
        
        LOG.info("                                   " ) ;
        List<String> files = new ArrayList<>()           ;
        files.add( pkcs12cert )                          ;       
        authorizeAccessToAllCert( files )                ;
    
        String jksOutFile =  USER_KEY_FILE.getParentFile().getAbsolutePath() +  File.separator + "domain.jks" ;
       
        if( jks ) {
           
          LOG.info("                                                                              ") ;
          LOG.info( "Import Pkcs12  : " +  pkcs12cert + "  ( Password : " + pkcs12Password  + " ) ") ;
          LOG.info( "Into   JKS     : " +  jksOutFile + "  ( Password : " + jksPassword     + " ) ") ;
          LOG.info("                                                                              ") ;
          
          PKCS12Importer.imports( pkcs12cert , pkcs12Password,  jksOutFile , jksPassword           ) ;
          
          if( new File( jksOutFile ).exists()) {
              files.clear()                    ;
              files.add( jksOutFile )          ;
              authorizeAccessToAllCert(files ) ;
          } else {
              LOG.error( " Oups ! The JksFile : " + jksOutFile + " - Not Generated ! " ) ;
          }
        }
        
        System.out.println( "                                          " ) ;
        System.out.println( "========================================= " ) ;
        System.out.println( "                                          " ) ;
        
        System.out.println( (char)27 + ANSI_PURPLE + "Pkcs12  File : " + 
                            (char)27 + ANSI_GREEN  +  pkcs12cert       +
                            "  ( "   + (char)27    + ANSI_WHITE        +
                            "Password : "          + (char)27          +
                            ANSI_RED   + pkcs12Password                +
                            (char)27 + ANSI_GREEN  + " ) "           ) ;
        
        if( jks )   {
            
        System.out.println( (char)27 + ANSI_PURPLE    + "JKS     FIle : " +
                            (char)27 + ANSI_GREEN     + jksOutFile        +
                            "  ( " +  (char)27        + ANSI_WHITE        + 
                            "Password : " + (char)27  + ANSI_RED          +
                            jksPassword   + (char)27  + ANSI_GREEN        +
                            " ) "                                       ) ;
        }
        
        System.out.println( "                                          " ) ;
        System.out.println( "========================================= " ) ;
        System.out.println( "                                          " ) ;
        
    }

     
    /** Execute the commands. */
    private static void execute(String[] command) throws InterruptedException {
      
        try {
            LOG.info( "Exec Cmd : " + String.join (" ", command )) ;
            Process exec = Runtime.getRuntime().exec(command)      ;
            exec.waitFor()                                         ;
           
        } catch (IOException ex)      {
            LOG.error(ex.getMessage() ) ;
        }
    }
    
    private static void printHelp() {
        
      System.out.println("                                                                                                                 " ) ;
      System.out.println(" *** CertMe V 1.2 Args :                                                                                         " ) ;
      System.out.println("                                                                                                                 " ) ;
      System.out.println("     -domain           =  your_domain ( if not provided, it will be automatically Resolved )                     " ) ;
      System.out.println("     -out              =  Directory output certificate. Default : letsEncrypt_Cert                               " ) ;
      System.out.println("     -password_pkcs12  =  password of the PKCS12 File. If Not Provived, it will be Generated using UUID          " ) ;
      System.out.println("     -jks              =  Import PKS12 into JKS  ( Java KeyStore ), ( Boolean. Disabled by default )             " ) ;
      System.out.println("     -pkcs             =  Generate PKCS file , ( Boolean. Disabled by default )                                  " ) ;
      System.out.println("     -password_jks     =  password of the JKS File ( if not provided, it will be the same as -password_pkcs12 )  " ) ;
      System.out.println("     -staging          =  Generate DEV / PROD Certificates ( By default : DEV )                                  " ) ;
      System.out.println("                          Nb : Only 50 PROD certificates are generated / Week                                    " ) ;
      System.out.println("     -alias            =  alias of the cert in the keystore                                                      " ) ;
      System.out.println("     -port             =  Port of the Embedded Server  ( Default : 80 ) Need Root Privileges                     " ) ;
      System.out.println("     -reuse_key        =  If a USER-KEY-PAIR Already exists, then reuse, else generate new one                   " ) ;
      System.out.println("     -log / -log_level =  Set Log Level : WARN, TRACE, OFF, INFO, ERROR, DEBUG, ALL                              " ) ;
      System.out.println("     -user_key_file    =  Path of USER_KEY_FILE. Used when Renew  Certificiate                                   " ) ;
      System.out.println("     -help             =  Display Help                                                                           " ) ;
      System.out.println("                                                                                                                 " ) ;
      System.out.println(" ** Requirements       : OPENSSL installed + Root Privilege to launch the Server on the Port 80                  " ) ;
      System.out.println("                                                                                                                 " ) ;
      System.out.println("       Ex Command      :  java -jar  certMe-1.0-jar-with-dependencies.jar \\                                     " ) ;
      System.out.println("                               -out             letsEncrypt_Cert/         \\                                     " ) ;
      System.out.println("                               -password_pkcs12 123456                    \\                                     " ) ;
      System.out.println("                               -password_jks    abcdef                    \\                                     " ) ;
      System.out.println("                               -port            80                        \\                                     " ) ;
      System.out.println("                               -staging         PROD                      \\                                     " ) ;
      System.out.println("                               -alias           certMeAlias               \\                                     " ) ;
      System.out.println("                               -domain          myDomain.com              \\                                     " ) ;
      System.out.println("                               -jks -reuse_key                                                                   " ) ;
      System.out.println("                                                                                                                 " ) ;
      System.exit( 0 )                                                                                                                         ;
    }
        
    /**
     * Invokes this Client.
     *
     * @param args
     *  Domains to get a certificate for
     * @throws java.lang.Exception
     */
    public static void main(String... args ) throws Exception {
     
        String  domain                = null  , 
                passwordPkcs12        = null  ,
                passwordJks           = null  ,
                alias                 = null  ,
                userKeyFile           = null  ,
                outCertificateFolder  = null  ;
        
        String logLevel          = "INFO"      ;
        int    port              = 80          ;
        String interfce          = "0.0.0.0"   ;
        
        boolean jks              = false       ;
        boolean pkcs             = false       ;
        boolean reuseKey         = false       ;
     
        String outCertificateFileName = "domain" ;

       for ( int i = 0 ; i < args.length ; i++ ) {
            
        String token = args[i] ;
           
            switch(token)      {
               case "-domain"           -> domain          = args[i+1] ;
               case "-password_pkcs12"  -> passwordPkcs12  = args[i+1] ;
               case "-password_jks"     -> passwordJks     = args[i+1] ;
               case "-staging"          ->  STAGING        = args[i+1] ;
               case "-jks"              -> jks             = true      ;
               case "-pkcs"             -> pkcs            = true      ;
               case "-reuse_key"        -> reuseKey        = true      ;
               case "-user_key_file"    -> userKeyFile     = args[i+1] ;
               case "-interface"        -> interfce        = args[i+1] ;
               case "-alias"            -> alias           = args[i+1] ;
               case "-log_level","-log" -> logLevel        = args[i+1].trim()                           ;
               case "-port"             -> port            = Integer.parseInt  (args[i+1])              ;
               case "-outCertificate"  , "-outCertificates", "-out" -> outCertificateFolder = args[i+1] ;
               case "-h", "-H", "-help", "-HELP" -> {
                   printHelp() ; System.exit( 0 )   ;
                }
            }
        }
       
        setSLF4JLogLevel(List.of("org.shredzone.acme4j", "org.jose4j") , logLevel) ;
        
        Level level = checkLog( logLevel ) ;
       
        Configurator.setRootLevel( level )                         ;
        Configurator.setAllLevels( "certMe_configuration", level ) ;
        
        String jVersion = System.getProperty("java.version")       ;

        LOG.info("Java Version : " + jVersion )                    ;
        
        
        if( domain  == null )  domain = getDomain()         ;  

        LOG.info( "Domain : [[ " + domain  + " ]] " )       ;
        
        LOG.info( "Mode   : [[ " + ( reuseKey  ? "Reuse USER-KEY-PAIR if Already Exists" : 
                  "Generate New USER-KEY-PAIR" )    + " ]] " )  ;

        if( jks && passwordJks == null  ) {
            LOG.info( "No password provided for JKS. Assign PkCs12 Value " ) ;
            LOG.info( "JKS Password == PkCs12 Password  == " +
                       passwordPkcs12   )                    ;
            passwordJks = passwordPkcs12                     ;
        }
        
        if( jks && ! pkcs ) {
            LOG.info("JKS enabled => Enable PKCS" ) ;
            pkcs = true ;
        }
 
        if( pkcs && passwordPkcs12 == null )  {
            passwordPkcs12 = ( UUID.randomUUID().toString() +
                               UUID.randomUUID().toString() )
                               .replace( "-", "")           ;
            LOG.info( "Generated PkCs12 Password : "        +
                      passwordPkcs12 )                      ;
        }
        
        if ( pkcs && alias == null )         {
             alias = "certMeAliasApp"        ;
             LOG.info( "Alias  : " + alias ) ;
        }
        
        if( domain  == null )  { printHelp() ; }
       
        if( outCertificateFolder == null || outCertificateFolder.isBlank() ) {
            
            outCertificateFolder   = new File(CertMe.class.getProtectionDomain()
                                                          .getCodeSource()
                                                          .getLocation().getPath())
                                                          .getParentFile()
                                                          .getPath() + File.separator +
                                                           "letsEncrypt_Cert" + 
                                                          File.separator      ;
            FileUtils.forceMkdir ( new File(outCertificateFolder ) )          ;
        }
        
        // FileUtils.deleteQuietly( new File(outCertificateFolder) ) ;
        
         /** File name of the User Key Pair. */
        if( userKeyFile == null ) {
            USER_KEY_FILE = new File( outCertificateFolder + outCertificateFileName  +
                                      "-user.key") ;
        } else {
          LOG.info("Provided USER_KEY_FILE : "  +  userKeyFile ) ;
          USER_KEY_FILE = new File( userKeyFile )                ;
          if( ! USER_KEY_FILE.exists() ) {
              throw new RuntimeException ( "Provided USER_KEY_FILE not "    +
                                           "found at path : " + userKeyFile ) ;
          }
        }

        /** File name of the Domain Key Pair. */
        DOMAIN_KEY_FILE   = new File( outCertificateFolder   + outCertificateFileName  + ".key" )    ;

        /** File name of the CSR. */
        DOMAIN_CSR_FILE   = new File( outCertificateFolder   + outCertificateFileName  + ".csr" )    ;

        /** File name of the signed certificate. */
        DOMAIN_CHAIN_FILE = new File( outCertificateFolder + outCertificateFileName  + "-chain.crt") ;
        
        /** PEM File . */
        DOMAIN_PEM_FILE = new File( outCertificateFolder + outCertificateFileName    + ".pem")       ;
        
        if( port != 80  )  {
            LOG.warn( "For LetsEncrypt, the Port MUST BE  ( 80 ) "        ) ;
        }
        
        resolveChallengeAndFetchCert( domain ,  port, interfce , reuseKey ) ;
        
        if( pkcs ) {
            String pkcs12cert = outCertificateFolder + outCertificateFileName + ".p12" ;
            convAndRegisterP12Cert( pkcs12cert     , 
                                    passwordPkcs12 , 
                                    alias          , 
                                    jks            ,
                                    passwordJks  ) ;
        }
    }
    
    private static Level checkLog( String level )           {

       Level toLevel = Level.toLevel( level.toUpperCase() ) ;
       System.out.println( "\nRetained LOG LEVEL : "        + 
                           toLevel.name()                 ) ;
       return toLevel                                       ;
    }
    
    private static void setSLF4JLogLevel(List<String> packages, String logLevel ) {
        // Get the root logger context
        ch.qos.logback.classic.LoggerContext loggerContext = 
                 (ch.qos.logback.classic.LoggerContext) LoggerFactory.getILoggerFactory() ;
        ch.qos.logback.classic.Level toLevel = 
                 ch.qos.logback.classic.Level.toLevel(logLevel, ch.qos.logback.classic.Level.INFO ) ;
        System.out.println("+ SLF4G Level = " + toLevel.levelStr ) ;
        for (String ppackage : packages) {
            // Get the logger for the package org.shredzone.acme4j
            ch.qos.logback.classic.Logger logger = loggerContext.getLogger(ppackage.trim()) ;
            // Set the log level to toLevel for the package
            logger.setLevel( toLevel ) ;
        }
    }

    private static String toUppCase( String fileName )    {
        
       if( fileName.contains( ".")) {
	       
         return fileName.split( Pattern.quote( "."), 2 )[0]
		                    .toUpperCase()  + "."  +
                fileName.split(Pattern.quote( "."), 2 )[1] ;
       }

       return fileName ;
    }

}
