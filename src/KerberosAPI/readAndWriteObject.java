/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package KerberosAPI;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.channels.SocketChannel;

/**
 *
 * @author Aliou
 */
public class readAndWriteObject {
    
    SocketChannel sc;
    Socket s;

    public readAndWriteObject(SocketChannel sc) {
        this.sc = sc;
    }
    
    public readAndWriteObject(Socket s) {
        this.s = s;
    }
    
    public byte [] readObject() throws IOException, ClassNotFoundException{
        
        ObjectInputStream ois = new ObjectInputStream(sc.socket().getInputStream());
        byte[] object = (byte[]) ois.readObject();
            
        return object;
    }
    
    public byte [] readObject2() throws IOException, ClassNotFoundException{
        
        ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
        byte[] object = (byte[]) ois.readObject();
            
        return object;
    }
    
    public void writeObject(byte [] object) throws IOException{
    
        ObjectOutputStream oos = new ObjectOutputStream(sc.socket().getOutputStream());
        oos.writeObject(object);        
    }
    
    public void writeObject2(byte [] object) throws IOException{
    
        ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
        oos.writeObject(object);        
    }    
}
