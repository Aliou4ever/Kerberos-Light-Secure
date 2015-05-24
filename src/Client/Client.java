/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Client;

import enchange.info.ServeurInfo;
import enchange.info.ServiceObject;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import view.ClientView;

/**
 *
 * @author Aliou
 */
public class Client extends Thread {

    ServerSocket server_sock;
    Socket s;
    SocketChannel client;
    KeyStore ks;
    X509Certificate cert;
    PrivateKey privKey;
    PublicKey pubKeySC;
    String login;
    String password;
    CSRRequest csr;
    ServiceRequest servRequest;
    ServeurInfo servInfo;
    ArrayList<ServiceObject> listeContact;

    public Client(String login, String mdp) {
        this.login = login;
        this.password = mdp;
        //servInfo = new ServeurInfo(this);
    }

    public ServeurInfo getServInfo() {
        return servInfo;
    }

    public void run() {
        //Démande de certification
        try {
            csr = new CSRRequest(1010, login, password);
            csr.connect();
            csr.run();

        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public CSRRequest getCsr() {
        return csr;
    }

    public boolean containsContact(ServiceObject servObject) {

        for (int i = 0; i < listeContact.size(); i++) {
            ServiceObject obj = listeContact.get(i);
            if (obj.equals(servObject)) {
                return true;
            }
        }
        return false;
    }
    
     public String getIdentite() {
        return login;
    }

    public String getLogin() {
        return login;
    }

    public PrivateKey getPrivKey() {
        return privKey;
    }

    public String getPassword() {
        return password;
    }

    public ServiceRequest getServRequest() {
        return servRequest;
    }

    public ArrayList<ServiceObject> getListeContact() {
        return listeContact;
    }

    public void setListeContact(ArrayList<ServiceObject> listeContact) {
        this.listeContact = listeContact;
    }
    

}
