/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlleur;

import Client.*;
import KerberosAPI.*;
import static KerberosAPI.Symetrique.*;
import Useful.*;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aliou
 */
public class ControlleurClient {

    Client client;
    X509Certificate certSS;
    ServiceRequest servReq;
    ServiceCalc calcul;
    double resCalc;

    public ControlleurClient() {

    }

    public void lancerClient() {

        client.start();

    }

    public boolean connect(String login, String mdp) {
        boolean res = false;
        try {
            DataBase db = new DataBase("localhost", "root", "");
            db.connexion();
            byte[] mdpdb;
            byte[] mdpEntred = DigestManager.digest(mdp);

            if (db.userExists(login)) {
                mdpdb = db.getPassword(login);
                if (DigestManager.digestVerify(mdpdb, mdpEntred)) {
                    client = new Client(login, mdp);
                    res = true;
                } else {
                    System.out.println("Erreur comparaison de mot de passes");
                }

            }
            db.deconnexion();
        } catch (Exception e) {
            System.out.println("ControlleurClient => ConnectDB : " + e);
        }

        return res;
    }

    public boolean getCertSS(String loginSS) {
        boolean ret = false;
        try {
            DataBase db = new DataBase("localhost", "root", "");
            db.connexion();
            if (db.userExists(loginSS)) {

                CertSS_Request certReq = new CertSS_Request(1010, loginSS);

                certReq.connect();

                String clientID = client.getLogin();

                certReq.run(clientID);

                ret = true;
            }
            db.deconnexion();
        } catch (Exception e) {
            System.out.println("ControlleurClient => getCertSS : " + e);
        }
        return ret;
    }

    public boolean demandeService(String loginSS) {
        boolean ret = false;
        try {
            servReq = new ServiceRequest(1020, loginSS);

            servReq.connect();

            String login = client.getLogin();

            servReq.run(login, loginSS);

            ret = true;
        } catch (Exception e) {
            System.out.println("ControlleurClient => demandeService : " + e);
        }
        return ret;
    }

    public double Calculer(double a, double b, String op) {

        try {
            calcul = new ServiceCalc("calcul", a, b, op);

            byte[] sessionKey = servReq.getSessionKey();
            readAndWriteObject readWrite2 = servReq.getReadWrite2();

            System.out.println("============Demande de Service============");

            //Construction de l'objet pour le calcul
            byte[] byteCalcul = InfoService.ObjectToByte(calcul);

            //on le crypte avec la clé symétrique paryagé avec le serveur de service calcul
            byte[] crypted = symetriqueEncrypt(byteCalcul, sessionKey);

            //envoi de l'objet
            readWrite2.writeObject2(crypted);

            //récéption de la réponse du calcul
            byte[] resCalcEncrypt = readWrite2.readObject2();

            //on décrypte avec la meme clé symétrique
            byte[] resCalcDecrypt = symetriqueDecrypt(resCalcEncrypt, sessionKey);

            ServiceCalc objCalc = (ServiceCalc) InfoService.ByteToObject(resCalcDecrypt);

            //Obtention du résultat
            resCalc = objCalc.getRes();
            System.out.println("resultat du calcul : " + resCalc);

            return resCalc;
        } catch (Exception e) {
            System.out.println("ControlleurClient => calculer : " + e);
        }
        return 0;
    }

    public double resCalc() {
        return servReq.getResCalc();
    }

}
