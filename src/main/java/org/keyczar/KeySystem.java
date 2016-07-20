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
package org.keyczar;

import com.markbridge.util.crypt.App;
import java.io.File;
import java.util.ArrayList;
import org.keyczar.enums.KeyStatus;
import org.keyczar.exceptions.KeyczarException;
import org.keyczar.interfaces.KeyczarReader;

/**
 * 
 * Use a symmetric key store to encrypt keys in an asymmetric key store
 * and create a public (unencrypted) complement to the asymmetric keys
 * for encryption operations
 * 
 * https://github.com/google/keyczar/wiki
 * 
 * https://dzone.com/articles/easy-encryption-java-and-pytho
 * https://groups.google.com/forum/#!topic/keyczar-discuss/v9Td4nwEgb8
 * keyczar paper in resources directory
 * 
 * http://stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when
 * 
 * Keyczar and different cryptography tools
 * https://groups.google.com/forum/#!topic/keyczar-discuss/v9Td4nwEgb8
 * 
 * @author Mark Bridge <j2eewebtier@gmail.com>
 */
public class KeySystem {
    
    protected static final String privateDirectory = App.CONFIG.privateDirectory();
    
    public static final String symmetricEncryptedStoreDirectory = App.CONFIG.symmetricEncryptedStoreDirectory();
    public static final String asymmetricEncryptedStoreDirectory = App.CONFIG.asymmetricEncryptedStoreDirectory();
    public static final String asymmetricPublicPlaintextStoreDirectory = App.CONFIG.asymmetricPublicPlaintextStoreDirectory();
    
    private static KeySystem singleton;
    
    /**
     * Set up a symmetric key store in a private directory to encrypt generated
     * asymmetric keys if one does not exist
     */
    private KeySystem() throws KeyczarException {
        new File(privateDirectory).mkdirs();
        new File(symmetricEncryptedStoreDirectory).mkdirs();
        new File(asymmetricEncryptedStoreDirectory).mkdirs();
        new File(asymmetricPublicPlaintextStoreDirectory).mkdirs();
        
        if(new File(privateDirectory).listFiles().length == 0) {
            this.createCryptStore("cryptkey", privateDirectory, false);
            this.addPlainKey(privateDirectory, true);
        }
        
        //add one primary key and one non-primary to any store with no keys
        if(new File(symmetricEncryptedStoreDirectory).listFiles().length == 0) {
            this.createCryptStore("keys-sym", symmetricEncryptedStoreDirectory, false);
            this.addEncryptedKey(symmetricEncryptedStoreDirectory, true);
            this.addEncryptedKey(symmetricEncryptedStoreDirectory, false);
        }
        
        if(new File(asymmetricEncryptedStoreDirectory).listFiles().length == 0) {
            this.createCryptStore("keys-asym", asymmetricEncryptedStoreDirectory, true);
            this.addEncryptedKey(asymmetricEncryptedStoreDirectory, true);
            this.addEncryptedKey(asymmetricEncryptedStoreDirectory, false);
            
            this.updatePubKeyStore();
        }
    }
    
    public synchronized static KeySystem getInstance() {
        if(singleton == null) {
            try {
                singleton = new KeySystem();
            } catch(KeyczarException ex) {
                throw new IllegalStateException(ex.getMessage());
            }
        }
        return singleton;
    }
    
    
    
    
    
    
    
    /**
     * Call this method to get a crypter to decrypt messages (can also encrypt)
     * 
     * @param storeDirectory
     * @param encrypted if the key store is an encrypted one - typically yes
     * symmetric true
     * @return 
     * @throws org.keyczar.exceptions.KeyczarException 
     */
    public Crypter getCrypter(String storeDirectory, boolean encrypted) throws KeyczarException {
        
        
        KeyczarReader keyczarReader = new KeyczarFileReader(storeDirectory);
        if(encrypted) {
            Crypter keyEncrypter = new Crypter(privateDirectory);
            keyczarReader = new KeyczarEncryptedReader(keyczarReader, keyEncrypter);
        }
        Crypter crypter = new Crypter(keyczarReader);
        
        return crypter;
    }
    
    public Encrypter getEncrypter(String storeDirectory, boolean encrypted) throws KeyczarException {
        
        KeyczarReader keyczarReader = new KeyczarFileReader(storeDirectory);
        if(encrypted) {
            Crypter keyEncrypter = new Crypter(privateDirectory);
            keyczarReader = new KeyczarEncryptedReader(keyczarReader, keyEncrypter);
        }
        Encrypter encrypter = new Encrypter(keyczarReader);
        
        return encrypter;
    }
    
    
    
    
    
    
    
    /**
     * Only one primary allowed, will demote current primary if promoting this to primary
     * @param storeDirectory
     * @param version the version to promote (if promoting to primary the previous primary will be demoted)
     * @param encrypted if the key is encrypted (eg private rsa key)
     * @throws org.keyczar.exceptions.KeyczarException
     */
    protected void promoteKey(String storeDirectory, int version, boolean encrypted) throws KeyczarException {
        GenericKeyczar genericKeyczar = getGenericKeyczar(storeDirectory, encrypted);
        genericKeyczar.promote(version);
        save(genericKeyczar, storeDirectory, encrypted);
    }
    
    /**
     * Have to have one primary, so if demoting the primary key set another to be
     * primary
     * @param storeDirectory
     * @param version the version to demote
     * @param encrypted if the key is encrypted (eg private rsa key)
     * @throws org.keyczar.exceptions.KeyczarException
     */
    protected void demoteKey(String storeDirectory, int version, boolean encrypted) throws KeyczarException {
        GenericKeyczar genericKeyczar = getGenericKeyczar(storeDirectory, encrypted);
        genericKeyczar.demote(version);
        save(genericKeyczar, storeDirectory, encrypted);
    }
    
    /**
     * Revoke an inactive key - will remove all key matter - use with caution
     * @param storeDirectory
     * @param version the version to revoke 
     * @param encrypted if the key is encrypted (eg private rsa key)
     * @throws org.keyczar.exceptions.KeyczarException
     */
    protected void revokeKey(String storeDirectory, int version, boolean encrypted) throws KeyczarException {
        GenericKeyczar genericKeyczar = getGenericKeyczar(storeDirectory, encrypted);
        genericKeyczar.revoke(version);
        save(genericKeyczar, storeDirectory, encrypted);
    }
    
    
    
    
    
    
    /**
     * Update the public key directory of an asymmetric key store
     * @throws KeyczarException 
     */
    protected void updatePubKeyStore() throws KeyczarException {
        boolean privateKeysEncrypted = true;
        GenericKeyczar genericKeyczar = getGenericKeyczar(asymmetricEncryptedStoreDirectory, privateKeysEncrypted);
        genericKeyczar.publicKeyExport(asymmetricPublicPlaintextStoreDirectory);
    }
    
    /**
     * Add a key to the store and encrypted using the configured crypter
     * @param storeDirectory
     * @param primary 
     */
    protected void addEncryptedKey(String storeDirectory, boolean primary) {
        
        String status = primary? "primary" : "active";
        
        KeyczarTool.main(
                new String[] {
                    "addKey", 
                    "--location=".concat(storeDirectory), 
                    "--crypter=".concat(privateDirectory), 
                    "--status=" + status});
    }
    
    /**
     * Set up an asymmetric key store (encrypted), and a public (encrypt only) 
     * key store from the assyemtric key store (unencrypted) - put in 'initial
     * number of keys' to start
     * 
     * Will create at least 1 primary key in keystore
     * 
     * @param initialNumberOfKeys
     * @throws KeyczarException 
     */
    protected void setUpKeystore(int initialNumberOfKeys) throws KeyczarException {
        
        if(initialNumberOfKeys < 1) {
            initialNumberOfKeys = 1;
        }
        
        KeySystem k = KeySystem.getInstance();
        
        k.createCryptStore("keys-asym", asymmetricEncryptedStoreDirectory, true);
        k.createCryptStore("keys-sym", symmetricEncryptedStoreDirectory, false);
        
        k.addEncryptedKey(asymmetricEncryptedStoreDirectory, true);
        k.addEncryptedKey(symmetricEncryptedStoreDirectory, true);
        for(int i = 1; i < initialNumberOfKeys; i++) {
            k.addEncryptedKey(asymmetricEncryptedStoreDirectory, false);
            k.addEncryptedKey(symmetricEncryptedStoreDirectory, false);
        }
        
        k.updatePubKeyStore();
    }
    
    /**
     * Only save metadata here
     * 
     * asymmetric public key stores are not encrypted
     * @param encrypted
     * @throws KeyczarException 
     */
    private void save(GenericKeyczar genericKeyczar, String storeDirectory, boolean encrypted) throws KeyczarException {
        if(encrypted) {
//            Crypter keyEncrypter = new Crypter(privateDirectory);
//            KeyczarEncryptedReader keyczarEncryptedReader = 
//                new KeyczarEncryptedReader(new KeyczarFileReader(storeDirectory), keyEncrypter);
//            genericKeyczar.writeEncrypted(storeDirectory, new Encrypter(keyczarEncryptedReader));
            genericKeyczar.getMetadata().setEncrypted(true); //or verify and throw exception if not what expect
            genericKeyczar.writeFile(genericKeyczar.getMetadata().toString(), storeDirectory + KeyczarFileReader.META_FILE);
        } else {
            genericKeyczar.getMetadata().setEncrypted(false);
            genericKeyczar.writeFile(genericKeyczar.getMetadata().toString(), storeDirectory + KeyczarFileReader.META_FILE);
            //genericKeyczar.write(storeDirectory);
        }
    }
    
    /**
     * Add a plain key to a store (not encrypted)
     * 
     * @param storeDirectory
     * @param primary 
     */
    private void addPlainKey(String storeDirectory, boolean primary) {
        
        String status = primary? "primary" : "active";
        
        KeyczarTool.main(
                new String[] {
                    "addKey", 
                    "--location=".concat(storeDirectory), 
                    "--status=" + status});
    }
    
    private void createCryptStore(String name, String location, boolean asymmetric) {
        
        ArrayList<String> params = new ArrayList<>();
        params.add("create");
        params.add("--location=".concat(location));
        params.add("--purpose=crypt");
        if(asymmetric) {
            params.add("--asymmetric=rsa");
        }
        params.add("--name=".concat(name));
        
        KeyczarTool.main(params.toArray(new String[params.size()]));
    }
    
    private GenericKeyczar getGenericKeyczar(String storeDirectory, boolean encrypted) throws KeyczarException {
        KeyczarReader reader = new KeyczarFileReader(storeDirectory);
        
        if(encrypted) {
            Crypter keyCrypter = new Crypter(privateDirectory);
            reader = new KeyczarEncryptedReader(reader, keyCrypter);
        }

        return new GenericKeyczar(reader);
    }
    
    /**
     * Initialize the key stores - 2 asymmetric encrypted private, 2 symmetric encrypted
     * 2 asymmetric plaintext public and create a privateDirectory if one does not exist
     * at the configured location.  (2 keys needed for tests)
     * 
     * @throws KeyczarException 
     */
    protected static void init() throws KeyczarException {
        KeySystem instance = KeySystem.getInstance();
        instance.setUpKeystore(1);
        instance.updatePubKeyStore();
    }
    
    /**
     * Add a key to all the stores and set them each the new primary in their store
     * Note, all keys in the encrypted stores will be re-encrypted with the new private key
     * generated and made primary as part of this addition
     * @throws KeyczarException 
     */
    protected static void rotate() throws KeyczarException {
        KeySystem instance = KeySystem.getInstance();
        instance.addPlainKey(privateDirectory, true);
        instance.addEncryptedKey(asymmetricEncryptedStoreDirectory, true);
        instance.addEncryptedKey(symmetricEncryptedStoreDirectory, true);
        instance.updatePubKeyStore();
    }
    
    /**
     * Promote encrypted key to primary - note, this will demote the current primary
     * to active.  If this is a decrypt operation for a legacy value remember to
     * promote the prior primary back to active!
     * 
     * @param storeDirectory
     * @param version the version to promote
     * @param encrypted whether the store is encrypted
     * @return the prior primary so can revert primary after done
     * @throws KeyczarException 
     */
    public synchronized Integer promoteKeyToPrimary(String storeDirectory, int version, boolean encrypted) 
            throws KeyczarException {
        
        KeySystem instance = KeySystem.getInstance();
        GenericKeyczar genericKeyczar = instance.getGenericKeyczar(storeDirectory, encrypted);
        
        int priorPrimary = genericKeyczar.primaryVersion.getVersionNumber();
        
        KeyVersion keyVersion = genericKeyczar.getVersion(version);
        KeyStatus currentStatus = keyVersion.getStatus();
        
        int promotions = 0;
        
        if(! currentStatus.equals(KeyStatus.PRIMARY)) {
            switch(currentStatus) {
                
                case ACTIVE: promotions++; 
                break;
                
                case INACTIVE: promotions+=2;
                break;
            }
        }
        
        for(int i = 0; i < promotions; i++) {
            instance.promoteKey(storeDirectory, version, true);
        }
        
        return priorPrimary;
    }
    
    /**
     * 
     * @param storeDirectory
     * @param encrypted whether the store directory keys are encrypted
     * @return the KeyVersion number plus 1 (as it seems to be zero based)
     * @throws KeyczarException 
     */
    public static Integer getCurrentPrimary(String storeDirectory, boolean encrypted) 
            throws KeyczarException {
        
        KeySystem instance = KeySystem.getInstance();
        GenericKeyczar genericKeyczar = instance.getGenericKeyczar(storeDirectory, encrypted);
        
        KeyVersion keyVersion = genericKeyczar.primaryVersion;
        
        return keyVersion.getVersionNumber();
    }
    
    public static void main(String[] args) throws KeyczarException {
        
    }
}
