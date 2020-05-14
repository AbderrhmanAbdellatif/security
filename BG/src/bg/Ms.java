/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bg;

import java.util.Scanner;

/**
 *
 * @author someo
 */
public class Ms {

    public static String convertMillis(long millis) {
        String str = String.format("%d:%d:%d",
                millis / (1000 * 60 * 60), (millis % (1000 * 60 * 60)) / (1000 * 60), ((millis % (1000 * 60 * 60)) % (1000 * 60)) / 1000);
        return str;

    }

    public static void main(String[] args) {
        long input = 555550000;
        String output = convertMillis(input);
        System.out.println(output);
    }
}
