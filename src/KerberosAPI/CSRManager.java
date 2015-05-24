/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package KerberosAPI;

import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

/**
 *
 * @author aliou
 */
public class CSRManager {
    
    public static PKCS10CertificationRequest generateCSR(String name, KeyPair kp){
        
        Security.addProvider(new BouncyCastleProvider());
        
        PKCS10CertificationRequestBuilder csrBuilder = null;
        ContentSigner contentSign = null;
        
        try{
            KeyPair keyPair = kp;
            X500Name subject = new X500Name("cn="+name);
            
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            csrBuilder = new PKCS10CertificationRequestBuilder(subject, keyInfo);
            
            contentSign = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
            
            return csrBuilder.build(contentSign);
        }
        catch(Exception e){            
            System.out.println("Echec de génération du CSR : "+e);
        }
        return null;
    }    
}
