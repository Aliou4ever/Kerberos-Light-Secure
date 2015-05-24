/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Useful;

import java.io.Serializable;

/**
 *
 * @author Aliou
 */
public class ServiceCalc implements Serializable {
    
    String type;
    double a;
    double b;
    String operateur;
    double res;

    public ServiceCalc(String type, double a, double b, String operateur) {
        this.type = type;
        this.a = a;
        this.b = b;
        this.operateur = operateur;
    }

    public ServiceCalc(double res) {
        this.res = res;
    }
    
    
    
    public static double addition(double a, double b){
        return a + b;
    }
    
    public static double sub(double a, double b){
        return a - b;
    }
    
    public static double prod(double a, double b){
        return a * b;
    }
    
    public static double div(double a, double b){
        
        if(b <= 0)
            return 0;
        else 
            return a / b;            
    }       
    
    public static double resCalcul(double a, double b, String op){
        
        double res = 0;
        
        switch(op){
        
            case "+" : res = addition(a, b);
                        break;
            case "-" : res = sub(a, b);
                        break;
            case "*" : res = prod(a, b);
                        break;
            case "/" : res = div(a, b);
                        break;                
        }
        
        return res;
    }

    public String getType() {
        return type;
    }

    public double getA() {
        return a;
    }

    public double getB() {
        return b;
    }

    public String getOperateur() {
        return operateur;
    }

    public double getRes() {
        return res;
    }
    
    
}
