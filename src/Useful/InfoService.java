/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Useful;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 *
 * @author Aliou
 */
public class InfoService implements Serializable {
    
    String type;
    String op;
    int a;
    int b;

    public InfoService(String type, String op, int a, int b) {
        this.type = type;
        this.op = op;
        this.a = a;
        this.b = b;
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

    public String getType() {
        return type;
    }

    public String getOp() {
        return op;
    }

    public int getA() {
        return a;
    }

    public int getB() {
        return b;
    }
    
    
    
    
    
    
    
}
