/*
 * Copyright (c) 2016, Mark Bridge <j2eewebtier@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package com.markbridge.util.crypt;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.keyczar.Crypter;
import org.keyczar.Encrypter;
import org.keyczar.KeySystem;
import org.keyczar.exceptions.KeyczarException;

/**
 * TODO: add overload methods synchronized on "crypt" to encrypt and decrypt to 
 * versions - a bottleneck but won't need this very often, just when re-encrypt
 * for forward secrecy.  Or consider adding as a KeySystem facility
 * 
 * Uses asymmetric encryption keys
 * 
 * @author Mark Bridge <j2eewebtier@gmail.com>
 */
public class Crypt {
    
    private String localStoreDirectory = KeySystem.asymmetricEncryptedStoreDirectory;
    
    /**
     * TODO: use the public key of the destination application
     * @param plaintext
     * @return ciphertext
     */
    public String remoteEncrypt(String plaintext) {
        
        String retVal = null;
        
        try {
            Encrypter enc = KeySystem.getInstance()
                    .getEncrypter("destinationPublicKeyStoreDirectory", false);
            retVal = enc.encrypt(plaintext);
        } catch (KeyczarException ex) {
            Logger.getLogger(Crypt.class.getName()).log(Level.SEVERE, "Encryption fail");
        }
        
        return retVal;
    }
    /**
     * synchronized so encrypt with the set key if being changed in overloading 
     * method
     * @param plaintext
     * @return 
     */
    public String localEncrypt(String plaintext) {
        
        String retVal = null;
        
        synchronized ("crypt") {
            try {
                Crypter crypter = KeySystem.getInstance()
                        .getCrypter(localStoreDirectory, true);
                retVal = crypter.encrypt(plaintext);
            } catch (KeyczarException ex) {
                Logger.getLogger(Crypt.class.getName()).log(Level.SEVERE, "Encryption fail");
            }
        }
        
        return retVal;
    }
    
    /**
     * expensive operation, use sparingly eg. for key rotation and re-encryption
     * synchronized so encrypt with the set key if changing
     * @param plaintext
     * @param version
     * @return 
     */
    public String localEncrypt(String plaintext, int version) {
        
        String retVal = null;
        
        synchronized ("crypt") {
            int resetPrimary = -1; 
            try {
                resetPrimary = KeySystem.getCurrentPrimary(localStoreDirectory, true);
                KeySystem.getInstance().promoteKeyToPrimary(localStoreDirectory, version, true);
                retVal = localEncrypt(plaintext);
                KeySystem.getInstance().promoteKeyToPrimary(localStoreDirectory, resetPrimary, true);
            } catch(KeyczarException ex) {
                throw new RuntimeException("Stop everything, reset primary (nb if -1 then no need,"
                        + " as failed before changing): " + resetPrimary);
            }
        }
        
        return retVal;
    }
    
    /**
     * Decrypt will find the right key ... no need to synchronize
     * @param ciphertext
     * @return 
     */
    public String localDecrypt(String ciphertext) {
        
        String retVal = null;
        
        try {
            Crypter crypter = KeySystem.getInstance()
                    .getCrypter(localStoreDirectory, true);
            retVal = crypter.decrypt(ciphertext);
        } catch (KeyczarException ex) {
            Logger.getLogger(Crypt.class.getName()).log(Level.SEVERE, "Encryption fail");
        }
        
        return retVal;
    }
    
    protected int getLocalKeyVersion() {
        int retVal = -1;
        try {
            retVal = KeySystem.getCurrentPrimary(localStoreDirectory, true);
        } catch (KeyczarException ex) {
            Logger.getLogger(Crypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        return retVal;
    }
    
}
