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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.json.Json;
import javax.json.JsonObject;

public class PeerThread extends Thread {

    private final BufferedReader bufferedReader;
    private final Peer peer;

    public PeerThread(Socket socket, Peer peer) throws IOException {
        bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.peer = peer;
    }

    @Override
    public void run() {
        boolean flag = true;
        while (flag) {

            try {

                JsonObject jsonObject = Json.createReader(bufferedReader).readObject();

                if (jsonObject.containsKey("username")) {
                    String mesaage = "";

                    boolean integrity = false;

                    if (peer.peerType == Peer.PeerType.ALICE) {
                        String encryptedMessage = jsonObject.getString("message");

                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                        IvParameterSpec ivParamsA = new IvParameterSpec(peer.ivB);

                        cipher.init(Cipher.DECRYPT_MODE, peer.kB, ivParamsA);
                        mesaage = new String(cipher.doFinal(encryptedMessage.getBytes(Constants.charsetName)), Constants.charsetName);

                        String targetNonce = jsonObject.getString("nonce");
                        
                        byte targetNonceBytes[] = cipher.doFinal(targetNonce.getBytes(Constants.charsetName));// ---
    
                        byte concatanatedMessage[] = peer.concatByteArray(encryptedMessage.getBytes(Constants.charsetName), targetNonceBytes);

                        byte macBytes[] = peer.macB.doFinal(concatanatedMessage);
                        String jsonMac = jsonObject.getString("mac");
                        //Integrity check
                        if (Arrays.toString(macBytes).equals(jsonMac)) {
                            integrity = true;
                        } else {
                            System.out.println("integrity error");
                        }

                        //Replay attack check
                        if (peer.macList.contains(jsonMac)) {
                            System.out.println("Replay attack!");
                            break;
                        } else {
                            peer.macList.add(jsonMac);
                        }

                    } else if (peer.peerType == Peer.PeerType.BOB) {
                        String encryptedMessage = jsonObject.getString("message");

                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                        IvParameterSpec ivParamsB = new IvParameterSpec(peer.ivA);

                        cipher.init(Cipher.DECRYPT_MODE, peer.kA, ivParamsB);
                        mesaage = new String(cipher.doFinal(encryptedMessage.getBytes(Constants.charsetName)), Constants.charsetName);

                        String jsonMac = jsonObject.getString("mac");

                        String targetNonce = jsonObject.getString("nonce");
                        
                        byte targetNonceBytes[] = cipher.doFinal(targetNonce.getBytes(Constants.charsetName));
                       
                        byte concatanatedMessage[] = peer.concatByteArray(encryptedMessage.getBytes(Constants.charsetName), targetNonceBytes);
                        
                        String hmacA = Arrays.toString(peer.macA.doFinal(concatanatedMessage));
    
                        //Integrity check
                        if (hmacA.equals(jsonMac)) {
                            integrity = true;
                        } else {
                            System.out.println("integrity error");
                        }

                        //Replay attack check
                        if (peer.macList.contains(jsonMac)) {
                            System.out.println("Replay attack!");
                            return;
                        } else {
                            peer.macList.add(jsonMac);
                        }

                    }
                    if (integrity) {
                        System.out.println("[" + jsonObject.getString("username") + "]" + mesaage);
                    }

                } else if (jsonObject.containsKey("publicKey")) {
                    byte[] publicBytes = Base64.getDecoder().decode(jsonObject.getString("publicKey"));//TODO: Fonksiyon yapılabilir
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    peer.targetPublicKey = keyFactory.generatePublic(keySpec);

                    peer.sendCertificate();

                } else if (jsonObject.containsKey("signal")) {
                    peer.sendHandshake();

                } else if (jsonObject.containsKey("publicCertificateString")) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    InputStream in = new ByteArrayInputStream(jsonObject.getString("publicCertificateString").getBytes(Constants.charsetName));
                    X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(in);
                    peer.targetPublicKey = certificate.getPublicKey();
                    peer.authenticationNonce = jsonObject.getInt("authenticationNonce");
                    peer.messageNonce = peer.authenticationNonce;
                    peer.sendNonceBack();

                } else if (jsonObject.containsKey("nonceBack")) {
                    byte[] encryptedNonce = jsonObject.getString("nonceBack").getBytes(Constants.charsetName);
                    peer.decryptNonce(encryptedNonce);

                } else if (jsonObject.containsKey("ACK")) {
                    peer.generateKeysAndMacs();

                } else if (jsonObject.containsKey("kA")) {
                    byte[] kABytes = jsonObject.getString("kA").getBytes(Constants.charsetName);
                    SecretKey kA = new SecretKeySpec(kABytes, 0, kABytes.length, "AES");

                    byte[] kBBytes = jsonObject.getString("kB").getBytes(Constants.charsetName);
                    SecretKey kB = new SecretKeySpec(kBBytes, 0, kBBytes.length, "AES");

                    byte[] ivA = jsonObject.getString("ivA").getBytes(Constants.charsetName);

                    byte[] ivB = jsonObject.getString("ivB").getBytes(Constants.charsetName);

                    peer.SetKeys(kA, kB, ivA, ivB);
                }

            } catch (UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                System.out.println(e);
                flag = false;
                interrupt();
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(PeerThread.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
