/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package SS;


import enchange.info.ServiceObject;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 *
 * @author Aliou
 */
public class ServerServices extends Thread {

    ServerSocketChannel ssc;
    ServerSocket server_sock;
    Socket s;    
    KeyStore ks;
    X509Certificate cert;
    PrivateKey privKey;
    int port;
    String login;
    String password;    
    private CSRRequestSS csrReq;
    ArrayList <ServiceObject> listeContact;
    
    public ServerServices(String login, String password) {
        this.login =  login;
        this.password = password;        
    }
    
    public void run(){
        
        try{            
            csrReq = new CSRRequestSS(1010, login, password);
            csrReq.connect();
            csrReq.run();
        }
        catch(Exception e){
            System.out.println(e);
        }
        
    }


    public CSRRequestSS getCsr() {
        return csrReq;
    }

    public boolean containsContact(ServiceObject servObject){
        
        for(int i = 0; i<listeContact.size(); i++){
            ServiceObject obj = listeContact.get(i);
            if(obj.equals(servObject)) return true;
        }
        
        return false;
    }
    
    public String getIdentite() {
        return login;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public ServerServices(String login) {
        this.login = login;
    }
    public ArrayList<ServiceObject> getListeContact() {
        return listeContact;
    }

    public void setListeContact(ArrayList<ServiceObject> listeContact) {
        this.listeContact = listeContact;
    }
    
}
