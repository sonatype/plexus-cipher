/**
 * createCipher routine was adopted from http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.10/src/java/org/apache/commons/ssl/OpenSSL.java
 * which is distributed under APL-2.0 license: http://www.apache.org/licenses/LICENSE-2.0
 */

/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.sonatype.plexus.components.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Oleg Gusakov
 * @version $Id$
 */
public class PBECipher
{
    protected static final String STRING_ENCODING = "UTF8";
    
    protected static final int SPICE_SIZE = 16;
    
    protected static final int SALT_SIZE = 8;

    protected static final int CHUNK_SIZE = 16;
    
    protected static final byte WIPER = 0;

    protected static final String DIGEST_ALG = "SHA-256";

    protected static final String KEY_ALG = "AES";

    protected static final String CIPHER_ALG = "AES/CBC/PKCS5Padding";

    protected static int PBE_ITERATIONS = 1000;

    protected MessageDigest _digester;
    
    private static final SecureRandom _secureRandom = new SecureRandom();

    //---------------------------------------------------------------
    public PBECipher()
    throws PlexusCipherException
    {
        try
        {
            _digester = MessageDigest.getInstance( DIGEST_ALG );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new PlexusCipherException(e);
        }
    }
    //---------------------------------------------------------------
    private byte[] getSalt( final int sz )
    {
        byte[] res = new byte[ sz ];

        _secureRandom.nextBytes( res );

        return res;
    }
    //-------------------------------------------------------------------------------
    public String encrypt64( final String clearText, final String password )
    throws PlexusCipherException
    {
        try
        {
            byte[] clearBytes = clearText.getBytes( STRING_ENCODING );
    
            byte[] salt = getSalt( SALT_SIZE );
            
            Cipher cipher = createCipher( password.getBytes( STRING_ENCODING ), salt, Cipher.ENCRYPT_MODE  );
    
            byte [] encryptedBytes = cipher.doFinal( clearBytes );
            
            int len = encryptedBytes.length;
            
            byte padLen = (byte) ( CHUNK_SIZE - (SALT_SIZE + len + 1) % CHUNK_SIZE );
            
            int totalLen = SALT_SIZE + len + padLen + 1;
            
            byte [] allEncryptedBytes = getSalt( totalLen );
            
            System.arraycopy( salt, 0, allEncryptedBytes, 0, SALT_SIZE );
            
            allEncryptedBytes[ SALT_SIZE ] = padLen;
            
            System.arraycopy( encryptedBytes, 0, allEncryptedBytes, SALT_SIZE + 1, len );
            
            byte [] encryptedTextBytes = Base64.encodeBase64( allEncryptedBytes );
            
            String encryptedText = new String( encryptedTextBytes, STRING_ENCODING );
    
            return encryptedText;
        }
        catch( Exception e)
        {
            throw new PlexusCipherException(e);
        }
    }

    // -------------------------------------------------------------------------------
    public String decrypt64( final String encryptedText, final String password )
    throws PlexusCipherException
    {
        try
        {
            byte[] allEncryptedBytes = Base64.decodeBase64( encryptedText.getBytes() );
            
            int totalLen = allEncryptedBytes.length;
            
            byte [] salt = new byte[ SALT_SIZE ];
            
            System.arraycopy( allEncryptedBytes, 0, salt, 0, SALT_SIZE );
            
            byte padLen = allEncryptedBytes[ SALT_SIZE ]; 
    
            byte [] encryptedBytes = new byte[ totalLen - SALT_SIZE - 1 - padLen ];
            
            System.arraycopy( allEncryptedBytes, SALT_SIZE + 1, encryptedBytes, 0, encryptedBytes.length );
            
            Cipher cipher = createCipher( password.getBytes( STRING_ENCODING ), salt, Cipher.DECRYPT_MODE  );
    
            byte [] clearBytes = cipher.doFinal( encryptedBytes );
            
            String clearText = new String( clearBytes, STRING_ENCODING ); 
    
            return clearText;
        }
        catch( Exception e)
        {
            throw new PlexusCipherException(e);
        }
    }
    //-------------------------------------------------------------------------------
    private Cipher createCipher( final byte [] pwdAsBytes, byte [] salt, final int mode )
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        _digester.reset();
        
        byte[] keyAndIv = new byte[ SPICE_SIZE * 2 ];
        
        if( salt == null || salt.length == 0 )
        {
            // Unsalted!  Bad idea!
            salt = null;
        }
        
        byte[] result;
        
        int currentPos = 0;
        
        while (currentPos < keyAndIv.length)
        {
            _digester.update(pwdAsBytes);
            
            if (salt != null)
            {
                // First 8 bytes of salt ONLY!  That wasn't obvious to me
                // when using AES encrypted private keys in "Traditional
                // SSLeay Format".
                //
                // Example:
                // DEK-Info: AES-128-CBC,8DA91D5A71988E3D4431D9C2C009F249
                //
                // Only the first 8 bytes are salt, but the whole thing is
                // re-used again later as the IV.  MUCH gnashing of teeth!
                _digester.update( salt, 0, 8 );
            }
            result = _digester.digest();
            
            int stillNeed = keyAndIv.length - currentPos;
            
            // Digest gave us more than we need.  Let's truncate it.
            if (result.length > stillNeed)
            {
                byte[] b = new byte[stillNeed];
                
                System.arraycopy(result, 0, b, 0, b.length);
                
                result = b;
            }
            
            System.arraycopy(result, 0, keyAndIv, currentPos, result.length);
            
            currentPos += result.length;
            
            if (currentPos < keyAndIv.length)
            {
                // Next round starts with a hash of the hash.
                _digester.reset();
                _digester.update(result);
            }
        }

        byte[] key = new byte[ SPICE_SIZE ];
        
        byte[] iv = new byte[ SPICE_SIZE ];
        
        System.arraycopy(keyAndIv, 0, key, 0, key.length);
        
        System.arraycopy(keyAndIv, key.length, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance( CIPHER_ALG );

        cipher.init( mode, new SecretKeySpec( key, KEY_ALG ), new IvParameterSpec( iv ) );
        
        return cipher;
    }
    //-------------------------------------------------------------------------------
    //-------------------------------------------------------------------------------
}
