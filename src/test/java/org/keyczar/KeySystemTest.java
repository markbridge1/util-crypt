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

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.keyczar.KeySystem.*;
import org.keyczar.exceptions.KeyczarException;

/**
 *
 * @author Mark Bridge <j2eewebtier@gmail.com>
 */
public class KeySystemTest {
    
    public KeySystemTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void testAsymmetricEncryptDecrypt() throws KeyczarException {
        
        KeySystem instance = KeySystem.getInstance();
        
        Crypter crypter = instance.getCrypter(asymmetricEncryptedStoreDirectory, true);
        Encrypter encrypter = instance.getEncrypter(asymmetricPublicPlaintextStoreDirectory, false);
        
        String text = "hello";
        assertTrue(crypter.decrypt(encrypter.encrypt(text)).equals(text));
        
        String s1 = encrypter.encrypt(text);
        String s2 = encrypter.encrypt(text);
        String s3 = encrypter.encrypt(text);
        
        assertNotEquals(s1, s2);
        assertNotEquals(s2, s3);
        assertNotEquals(s1, s3);
    }

    @Test
    public void testSymmetricEncryptDecrypt() throws KeyczarException {
        
        KeySystem instance = KeySystem.getInstance();
        
        Crypter crypter = instance.getCrypter(symmetricEncryptedStoreDirectory, true);
        Encrypter encrypter = instance.getEncrypter(symmetricEncryptedStoreDirectory, true);
        
        String text = "hello";
        assertTrue(crypter.decrypt(encrypter.encrypt(text)).equals(text));
        
        String s1 = encrypter.encrypt(text);
        String s2 = encrypter.encrypt(text);
        String s3 = encrypter.encrypt(text);
        
        assertNotEquals(s1, s2);
        assertNotEquals(s2, s3);
        assertNotEquals(s1, s3);
    }

    /**
     * N.B. assumes have at least two keys in store
     * @throws KeyczarException 
     */
    @Test
    public void testPromote() throws KeyczarException {
        
        int resetPrimary = KeySystem.getCurrentPrimary(asymmetricEncryptedStoreDirectory, true);
        int newPrimary = 1;
        if(newPrimary == resetPrimary) {
            newPrimary++;
        }
        
        int priorPrimary = KeySystem.getInstance().promoteKeyToPrimary(asymmetricEncryptedStoreDirectory, newPrimary, true);
        assertEquals(resetPrimary, priorPrimary);
        
        int newPrimaryCheck = KeySystem.getCurrentPrimary(asymmetricEncryptedStoreDirectory, true);
        assertEquals(newPrimary, newPrimaryCheck);
        
        
        KeySystem.getInstance().promoteKeyToPrimary(asymmetricEncryptedStoreDirectory, resetPrimary, true);
        int resetPrimaryCheck = KeySystem.getCurrentPrimary(asymmetricEncryptedStoreDirectory, true);
        assertEquals(resetPrimary, resetPrimaryCheck);
    }
    
}
