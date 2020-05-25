/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityproject;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.json.Json;
import javax.json.JsonObject;

public class PeerThread extends Thread {

    private BufferedReader bufferedReader;
    private Peer peer;

    public PeerThread(Socket socket, Peer peer) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.peer = peer;
    }

    public void run() {
        boolean flag = true;
        while (flag) {

            try {

                //String message = bufferedReader.readLine();
                //System.out.println(message);
                //if (message.startsWith("publickey=")) {
                // String publicKey = message.substring(10);
                //} else {
                //bufferedReader.reset();
                JsonObject jsonObject = Json.createReader(bufferedReader).readObject();
                String charsetName = "ISO-8859-1";
                if (jsonObject.containsKey("username")) {
                    System.out.println("[" + jsonObject.getString("username") + "]" + jsonObject.getString("message"));
                
                } else if (jsonObject.containsKey("publicKey")) {
                    byte[] publicBytes = Base64.getDecoder().decode(jsonObject.getString("publicKey"));
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    peer.targetPublicKey = keyFactory.generatePublic(keySpec);
                    peer.sendCertificate();
                    
                } else if (jsonObject.containsKey("signal")) {
                    peer.sendHandshake();
                    
                } else if (jsonObject.containsKey("publicCertificateString")) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    InputStream in = new ByteArrayInputStream(jsonObject.getString("publicCertificateString").getBytes(charsetName));
                    X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(in);
                    peer.targetPublicKey = certificate.getPublicKey();
                    peer.nonce=jsonObject.getInt("nonce");
                    peer.sendNonceBack();
                    
                }else if (jsonObject.containsKey("nonce")) {
                    byte[] encryptedNonce = jsonObject.getString("nonce").getBytes(charsetName);
                    peer.decryptNonce(encryptedNonce);
                } 
            } catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                System.out.println(e);
                flag = false;
                interrupt();
            }
        }
    }

}
