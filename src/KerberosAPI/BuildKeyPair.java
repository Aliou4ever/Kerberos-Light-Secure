/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Aliou
 */
public class BuildKeyPair {
    
    public static KeyPair generateKeyPair() {
        
        Security.addProvider(new BouncyCastleProvider());
        
        System.out.print("Génération de la paire de clé : ");
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
        } 
        catch (Exception ex) {
            System.out.println(ex);
        }
        kpg.initialize(1024);
        KeyPair keyPair = kpg.genKeyPair();

        System.out.println("OK");
        
        return keyPair;
    }
    
}
