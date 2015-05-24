/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Aliou
 */
public class Certificate {
            
    public static X509Certificate createSelfSignedCert(KeyPair kp){
        
        Security.addProvider(new BouncyCastleProvider());
        System.out.print("Création d'un Certificat auto-signé : ");
        X509Certificate x509Cert = null;
         try {                          
             String subject = "SC";
             KeyPair keyPair = kp;
             String issuerName = "SC"; //Issuer le meme que le subject
             BigInteger serialNumber = BigInteger.ONE;
             
             Calendar cal = Calendar.getInstance();
             Date notBefore = cal.getTime();
             cal.add(Calendar.YEAR, 1);
             Date notAfter = cal.getTime();
             
             JcaX509v3CertificateBuilder builder = null;             
             
             X500Name subjectFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, subject).build();
             X500Name issuerFormated = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, issuerName).build();
             builder = new JcaX509v3CertificateBuilder(issuerFormated, serialNumber, notBefore, notAfter, subjectFormated, keyPair.getPublic());
                          
             ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());//our own key             
             
             //------------------------- Extensions ------------------------
             builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
             
             SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
             builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
             
             KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign);
             builder.addExtension(Extension.keyUsage, true, keyUsage);
             
             ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
             builder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
                          
             X509CertificateHolder holder = builder.build(contentSigner);
             
             //création du certificat
             java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
             
             //transformation au format X509
             CertificateFactory cf = CertificateFactory.getInstance("X.509");
             ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
             x509Cert = (X509Certificate) cf.generateCertificate(bais);
             
             if(x509Cert != null){
                 System.out.println("OK");
                    return x509Cert;
             }
             //return (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
         } catch (Exception e) {
             System.out.println("Echec de création du certificat auto-signé : " + e);
         }         
         return null;
    }
       
    
    public static X509Certificate createCertFromCSR(PKCS10CertificationRequest csr, KeyPair kp, X509Certificate xCert){
    
        Security.addProvider(new BouncyCastleProvider());

        //String subject = subj;          //proprietaire de la clé à signer
        KeyPair keyPair = kp;
        X509Certificate x509CertCSR = null;     
        //System.out.print("Création d'un Certificat à partir d'une CSR : ");
        try {
            Security.addProvider(new BouncyCastleProvider());
            
            BigInteger bigInt = new BigInteger(String.valueOf(System.currentTimeMillis()));
            Calendar cal = Calendar.getInstance();
            Date notbefore = cal.getTime();
            cal.add(Calendar.YEAR, 2); 
            Date notafter = cal.getTime();
            
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
            
            AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());            
            SubjectPublicKeyInfo keyInfo = csr.getSubjectPublicKeyInfo();
            
            X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(new X500Name(xCert.getSubjectDN().getName()), bigInt, notbefore, notafter, csr.getSubject(), keyInfo);
            ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);
            
            myCertificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            
            myCertificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(xCert));                                                                                            
            
            SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyInfo);
            myCertificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
            
            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.digitalSignature);
            myCertificateGenerator.addExtension(Extension.keyUsage, true, keyUsage);
            
            X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
            
            java.security.cert.Certificate certificate = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
            x509CertCSR = (X509Certificate) cf.generateCertificate(bais);
            //cert = (X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
            
            if(x509CertCSR != null){
                 //System.out.println("OK");
                    return x509CertCSR;
             }
        } catch (Exception e) {
            System.err.println("Echec de création de certificat pour le client avec ce csr: " + e);
        }        
        return null;
    }
    
    public static X509Certificate getCertBytes(byte [] certBytes){
        X509Certificate cert= null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(certBytes);
            cert = (X509Certificate)certFactory.generateCertificate(in);            
        } catch (Exception e) {
            System.out.println("Impossible de reconstruire le certificat : "+e);
        }
        return cert;   
    }   
    
}
