package com.hchen90.csctest;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;


import com.google.gson.*;

public class App {
  private static final BigInteger ZERO = BigInteger.ZERO;
  private static final BigInteger ONE = BigInteger.ONE;

  private static void panic(String msg) {
    System.out.println(msg);
    System.exit(1);
  }

  private static final BigInteger RSAEP(final RSAPublicKey K, final BigInteger m)
  {
    // 1. If the representative m is not between 0 and n - 1, output
    // "representative out of range" and stop.
    final BigInteger n = K.getModulus();
    if (m.compareTo(ZERO) < 0 || m.compareTo(n.subtract(ONE)) > 0)
      throw new IllegalArgumentException();
    // 2. Let c = m^e mod n.
    final BigInteger e = K.getPublicExponent();
    final BigInteger result = m.modPow(e, n);
    // 3. Output c.
    return result;
  }

  private static final byte[] I2OSP(final BigInteger s, final int k)
  {
    byte[] result = s.toByteArray();
    if (result.length < k)
      {
        final byte[] newResult = new byte[k];
        System.arraycopy(result, 0, newResult, k - result.length, result.length);
        result = newResult;
      }
    else if (result.length > k)
      { // leftmost extra bytes should all be 0
        final int limit = result.length - k;
        for (int i = 0; i < limit; i++)
          {
            if (result[i] != 0x00)
              throw new IllegalArgumentException("integer too large");
          }
        final byte[] newResult = new byte[k];
        System.arraycopy(result, limit, newResult, 0, k);
        result = newResult;
      }
    return result;
  }

  private static final BigInteger verify(final PublicKey K, final BigInteger s)
  {
    try
      {
        return RSAEP((RSAPublicKey) K, s);
      }
    catch (IllegalArgumentException x)
      {
        throw new IllegalArgumentException("signature representative out of range");
      }
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      panic("Usage: java CscTest <host> <token> <index> <pin>");
    } else {
      Integer idx = 0;
      try {
        idx = Integer.valueOf(args[2]);
      } catch (NumberFormatException e) {
        panic("invalid index");
      }

      CscClient client = new CscClient(args[0], args[1], idx, args[3]);

      Boolean okay = client.request("/csc/v1/info", "{}", "application/json");
      if (!okay) {
        panic("cannot get /csc/v1/info");
      }

      System.out.printf("1. ==> info: %s\n", client.result());

      okay = client.request("/csc/v1/credentials/list", "{}", "application/json");
      if (!okay) {
        panic("cannot get /csc/v1/credentials/list");
      }

      System.out.printf("2. ==> credential list: %s\n", client.result());

      CredList credList = new Gson().fromJson(client.result(), CredList.class);
      if (credList.credentialIDs.length == 0) {
        panic("no credentials");
      }
      if (idx >= credList.credentialIDs.length) {
        panic("invalid index");
      }

      String credID = credList.credentialIDs[client.index];

      System.out.println(credID);

      CredReqInfo credReqInfo = new CredReqInfo();
      credReqInfo.credentialID = credID;
      credReqInfo.certificates = "single";
      credReqInfo.certInfo = true;
      credReqInfo.authInfo = true;

      okay = client.request("/csc/v1/credentials/info", new Gson().toJson(credReqInfo), "application/json");
      if (!okay) {
        panic("cannot get /csc/v1/credentials/info");
      }

      System.out.printf("3. ==> credential info: %s\n", client.result());

      CredInfo credInfo = new Gson().fromJson(client.result(), CredInfo.class);

      System.out.printf("4. ==> key info: %s - %s - %d\n", credInfo.key.status, credInfo.key.algo[0], credInfo.key.len);

      if (credInfo.cert.certificates.length == 0) {
        panic("no certificates");
      }

      PublicKey pubKey = null;
      
      try {
        byte[] raw = Base64.getDecoder().decode(credInfo.cert.certificates[0]);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(raw);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
        pubKey = cert.getPublicKey();
        System.out.printf("5. ==> certificate info: %s\n", cert.getSubjectDN().getName());
      } catch (Exception e) {
        e.printStackTrace();
      }

      if (pubKey == null) {
        panic("no public key");
      }

      byte[] hash = null;
      String hashStr = null;

      try {
        String msg = UUID.randomUUID().toString();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        hash = digest.digest(msg.getBytes());
        hashStr = Base64.getEncoder().encodeToString(hash);
      } catch (Exception e) {
        e.printStackTrace();
      }

      if (hash == null) {
        panic("no hash");
      }

      CredAuthReqInfo credAuthReqInfo = new CredAuthReqInfo();
      credAuthReqInfo.credentialID = credID;
      credAuthReqInfo.numSignatures = 1;
      credAuthReqInfo.hash = new String[1];
      credAuthReqInfo.hash[0] = hashStr;
      credAuthReqInfo.PIN = client.pin;

      okay = client.request("/csc/v1/credentials/authorize", new Gson().toJson(credAuthReqInfo), "application/json");
      if (!okay) {
        panic("cannot get /csc/v1/credentials/auth");
      }

      System.out.printf("6. ==> SAD: %s\n", client.result());

      CredAuthInfo credAuthInfo = new Gson().fromJson(client.result(), CredAuthInfo.class);

      SignReqInfo signReqInfo = new SignReqInfo();
      signReqInfo.credentialID = credID;
      signReqInfo.SAD = credAuthInfo.SAD;
      signReqInfo.hash = new String[1];
      signReqInfo.hash[0] = hashStr;
      signReqInfo.hashAlgo = "2.16.840.1.101.3.4.2.1";
      signReqInfo.signAlgo = credInfo.key.algo[0];

      okay = client.request("/csc/v1/signatures/signHash", new Gson().toJson(signReqInfo), "application/json");
      if (!okay) {
        panic("cannot get /csc/v1/signatures/signHash");
      }

      System.out.printf("7. ==> signature: %s\n", client.result());

      SignInfo signInfo = new Gson().fromJson(client.result(), SignInfo.class);
      if (signInfo.signatures.length == 0) {
        panic("no signatures");
      }

      byte[] signature = Base64.getDecoder().decode(signInfo.signatures[0]);

      okay = false;

      try {
        int modBits = ((RSAPublicKey) pubKey).getModulus().bitLength();
        int k = (modBits + 7) / 8;
        BigInteger s = new BigInteger(1, signature);
        BigInteger m = verify(pubKey, s);
        byte[] em = I2OSP(m, k);
        EMSA_PKCS1_V1_5 pkcs1 = new EMSA_PKCS1_V1_5("SHA256", 256 / 8);
        byte[] emp = pkcs1.encode(hash, k);
        okay = Arrays.equals(em, emp);
      } catch (Exception e) {
        e.printStackTrace();
      }

      if (!okay) {
        panic("verification failed");
      }

      System.out.println("8. ==> signature verified");
    }
  }

  static class SignInfo {
    String[] signatures;
  }

  static class SignReqInfo {
    String credentialID;
    String SAD;
    String[] hash;
    String hashAlgo;
    String signAlgo;
  } 

  static class CredAuthReqInfo {
    String credentialID;
		Integer numSignatures;
		String[] hash;
		String PIN;
  }

  static class CredAuthInfo {
    String SAD;
    Integer expiresIn;
  }

  static class CredList {
    String[] credentialIDs;
  }

  static class CredReqInfo {
    String credentialID;
		String certificates;
		Boolean certInfo;
		Boolean authInfo;
  }

  public class KeyInfo {
    String status;
    String[] algo;
    int len;
  }

  public class CertInfo {
    String status;
    String[] certificates;
  }

  static class CredInfo {
    String credentialID;
    KeyInfo key;
    CertInfo cert;
		String authMode;
  }

  static class CscClient {
    private final String host; // csc server host
    private final String token; // csc server token
    private final int index; // index of credential to use
    private final String pin; // pin of credential to use

    private StringBuffer response = new StringBuffer();

    public CscClient(String host, String token, int index, String pin) {
      this.host = new String(host);
      this.token = new String(token);
      this.index = index;
      this.pin = new String(pin);
    }

    public Boolean request(String urlReq, String ctx, String ctyp) {
      try {
        URL url = new URL(this.host+urlReq);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", ctyp);
        conn.setRequestProperty("Authorization", "Bearer " + this.token);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.connect();

        OutputStream os = conn.getOutputStream();
        os.write(ctx.getBytes());
        os.flush();
        os.close();

        int responseCode = conn.getResponseCode();
        if (responseCode!= HttpURLConnection.HTTP_OK) {
          System.out.println("Error: " + responseCode);
          return false;
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        
        this.response.setLength(0);
        while ((inputLine = in.readLine()) != null) {
            this.response.append(inputLine);
        }
        in.close();

        conn.disconnect();
      } catch (Exception e) {
        e.printStackTrace();
      }

      return true;
    }

    public String result() {
      return this.response.toString();
    }

  }
}