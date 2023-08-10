/**
  Copyright (c) 2019 Wolfgang Hauptfleisch <dev@augmentedlogic.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
 **/
package com.augmentedlogic.pbkdf2tool;

import java.util.*;
import java.math.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

public class Pbkdf2Tool
{

    private String prefix = "pbkdf2_sha256";
    private String algo = "PBKDF2WithHmacSHA256";
    private String delimiter = "$";
    private String random_source = "SHA1PRNG"; // alternative "NativePRNG"
    public static final int BASE64 = 1;
    public static final int HEX = 2;
    public static final int RAW = 3;
    private int use_encoding = 1;

    /**
     *
     **/
    public void setDelimiter(String delimiter)
    {
        this.delimiter = delimiter;
    }

    /**
     *
     **/
    public void setEncoding(int encoding)
    {
        this.use_encoding = encoding;
    }

    /**
     *
     **/
    public void setAlgo(String algo)
    {
        this.algo = algo;
    }

    /**
     *
     **/
    public void setRandomSource(String random_source)
    {
        this.random_source = random_source;
    }

    /**
     *
     **/
    public String genSalt(int length) throws NoSuchAlgorithmException
    {
        SecureRandom secureRandom = SecureRandom.getInstance(this.random_source);
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        return new String(Base64.getEncoder().encode(salt)).substring(0, length);
    }

    /**
     *
     **/
    private static String toHex(byte[] array) //throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  + paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }

    /**
     *
     **/
    private static byte[] fromHex(String hex) throws NoSuchAlgorithmException
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }


    /**
     * encode the actual hashed password
     * returns only the last part of the storable string
     **/
    private String getEncodedHash(String password, String salt, int iterations) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        SecretKeyFactory keyFactory = null;
        try {
            keyFactory = SecretKeyFactory.getInstance(this.algo);  // TODO configure
        } catch (NoSuchAlgorithmException e) {
            throw e;
        }
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(Charset.forName("UTF-8")), iterations, 256);
        SecretKey secret = null;
        try {
            secret = keyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw e;
        }

        byte[] rawHash = secret.getEncoded();
        byte[] hash_encoded = null;

        // user either base64, hex or raw
        switch(this.use_encoding)
        {
            case Pbkdf2Tool.BASE64: {
                                        hash_encoded = Base64.getEncoder().encode(rawHash);
                                        break;
                                    }

            case Pbkdf2Tool.HEX: {
                                     hash_encoded = this.toHex(rawHash).getBytes();
                                     break;
                                 }

            case Pbkdf2Tool.RAW: {
                                     hash_encoded = rawHash;
                                     break;
                                 }

        }

        return new String(hash_encoded);
    }

    /**
     *
     **/
    // returns hashed password, along with algorithm, number of iterations and salt
    public String encode(String password, String salt, int iterations) throws Exception
    {
        String hash = null;
        try {
            hash = getEncodedHash(password, salt, iterations);
        } catch(Exception e) {
            throw e;
        }
        return this.prefix + this.delimiter + iterations + this.delimiter + salt + this.delimiter + hash;
    }

    /**
     *
     **/
    public String encodePasswordOnly(String password, String salt, int iterations) throws Exception
    {
        return this.getEncodedHash(password, salt, iterations);
    }

    /**
     *
     **/
    public boolean checkPassword(String password, String hashedPassword) throws Exception
    {
        // expects the format ALGORITH_PREFIX, ITERATIONS, SALT, PASSWORD_HASH
        String[] parts;

        if(this.delimiter.equals("$")) {
            parts = hashedPassword.split("\\$");
        } else {
            parts = hashedPassword.split(this.delimiter);
        }

        if (parts.length != 4) {
            // invalid format
            return false;
        }

        Integer iterations = Integer.parseInt(parts[1]);
        String salt = parts[2];
        String hash = null;
        try {
            hash = this.encode(password, salt, iterations);
        } catch(Exception e) {
            throw e;
        }

        return hash.equals(hashedPassword);
    }

}
