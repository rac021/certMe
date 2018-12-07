
package entry ;

import java.io.File ;
import java.util.UUID ;
import java.security.Key ;
import java.io.IOException ;
import java.io.OutputStream ;
import java.util.Enumeration ;
import java.security.KeyStore ;
import java.io.FileInputStream ;
import java.io.FileOutputStream ;
import java.security.cert.Certificate ;
import java.security.KeyStoreException ;
import java.security.NoSuchAlgorithmException ;
import java.security.UnrecoverableKeyException ;
import java.security.cert.CertificateException ;

/**
 * This class can be used to import a key/certificate pair from a pkcs12 file
 * into a regular JKS format keystore for use with java based SSL applications, etc. 

/**
 * @author ryahiaoui
 */

public class PKCS12Importer {
    
     public static void imports( String _fileIn, String _fileOut, String phrase )    {

      System.err.println ( "usage: java PKCS12Import {pkcs12_file} [new-jks_file]")  ;

      File fileIn = new File(_fileIn) ;
      File fileOut                    ;
      if (_fileOut != null )          {
         fileOut = new File(_fileOut) ;
      } else {
         fileOut = new File("new_app_store.jks") ;
      }

      if (! fileIn.canRead() ) {
         System.err.println( "Unable to access input keystore: " + fileIn.getPath()) ;
         System.exit(2) ;
      }

      if ( fileOut.exists() && !fileOut.canWrite() ) {
         System.err.println( "Output file is not writable: " + fileOut.getPath() ) ;
         System.exit(2) ;
      }

      try {
          
        if( phrase == null ) {
            System.out.println(" No Phrase was provided"  )  ;
            System.out.println(" Generate a Random Phrase")  ;
            System.out.println(" ------------------- "    )  ;
            phrase  =  UUID.randomUUID().toString()          ;
            System.out.println(" Phrase : " + phrase      )  ;
            System.out.println(" -------------------"     )  ;
        }
        KeyStore kspkcs12 = KeyStore.getInstance("pkcs12" )  ;
        
        KeyStore ksjks    = KeyStore.getInstance("jks")      ;

        char[] inphrase   = phrase.toCharArray()             ;

        char[] outphrase  = phrase.toCharArray()             ;

        kspkcs12.load(new FileInputStream(fileIn), inphrase) ;

        ksjks.load ( (fileOut.exists()) ? new FileInputStream(fileOut) : null, outphrase);

        Enumeration eAliases = kspkcs12.aliases() ;

        while (eAliases.hasMoreElements())        {

           String strAlias = (String)eAliases.nextElement() ;

           if (kspkcs12.isKeyEntry(strAlias))               {

              System.err.println("Adding key with alias " + strAlias )  ;

              Key key             = kspkcs12.getKey(strAlias, inphrase) ;

              Certificate[] chain = kspkcs12.getCertificateChain(strAlias ) ;

              ksjks.setKeyEntry(strAlias, key, outphrase, chain ) ;
           }
        }

          try ( OutputStream out = new FileOutputStream(fileOut) ) {
              ksjks.store(out, outphrase)  ;
          }
        
      } catch( IOException | KeyStoreException | 
               NoSuchAlgorithmException        |
               UnrecoverableKeyException       |
               CertificateException ex )       {
          
          ex.printStackTrace()                 ;
      }
   }

}

