/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enchange.info;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 *
 * @author Aliou
 */
public class ServiceObject implements Serializable{
    
    String login;
    String service;
    int port;

    public ServiceObject() {
        
    }
    
    public boolean equals(ServiceObject obj){
        if(login.equals(obj.getLogin())&& service.equals(obj.getService())&& port == obj.getPort()) return true;        
        return false;
    }

    public ServiceObject(String login, String service, int port) {
        this.login = login;
        this.service = service;
        this.port = port;
    }
                            
    public static byte[] ObjectToByte(Object o) throws Exception{//transformer un objet en tableau de byte
        
      ByteArrayOutputStream b = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(b);
      oos.writeObject(o);      
      byte[] bytes =  b.toByteArray();
        
      return bytes ;
    }
    
    public static Object ByteToObject(byte[] bytes) throws Exception{//transformer un tableau de byte en objet
        
        Object obj = null;
        
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis);
        obj = ois.readObject();        
        return obj;
    }

    public String getLogin() {
        return login;
    }

    public String getService() {
        return service;
    }

    public int getPort() {
        return port;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void setService(String service) {
        this.service = service;
    }

    public void setPort(int port) {
        this.port = port;
    }
    
    
    
    
    
}
