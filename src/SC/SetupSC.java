/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SC;

import KerberosAPI.BuildKeyPair;
import KerberosAPI.Certificate;
import static KerberosAPI.KeyManager.storePublicKeyInFile;
import java.security.KeyPair;

/**
 *
 * @author Aliou
 */
public class SetupSC {
    
    private static KeyPair kp;
    private static java.security.cert.X509Certificate certSC ;

    public SetupSC() {
        
        //Génération d'une paire de clé
        BuildKeyPair bkp = new BuildKeyPair();        
        this.kp = bkp.generateKeyPair();                
        
        //création du certificat auto-signé
        Certificate cert = new Certificate();
        this.certSC = cert.createSelfSignedCert(kp);   
        
        //Enregistrement de la clé publique du serveur dans un fichier
        try {                        
            storePublicKeyInFile(kp.getPublic());
        } 
        catch (Exception e) {
            System.out.println("Echec d'enregistrement de la clé publique : "+e);
        }
    }
    
    public static KeyPair getKeyPairOfSC(){
        return kp;
    }
    
    public static java.security.cert.X509Certificate getCertOfSC(){
        return certSC;
    }
}
