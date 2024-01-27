package com.mobiera.lib.etsi102225.impl.crypto.mac;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.mobiera.lib.etsi102225.impl.crypto.CipherParameters;
import com.mobiera.lib.etsi102225.impl.crypto.Mac;
import com.mobiera.lib.etsi102225.impl.crypto.params.KeyParameter;
import com.mobiera.lib.etsi102225.impl.crypto.params.ParametersWithIV;

public class AESCMAC implements Mac {
    private static final byte CONSTANT = (byte) 0x87;
    private static final int BLOCK_SIZE = 16;
    
    private int macLength;
    private Cipher aesCipher;
    private byte [] iv; 

    private byte[] buffer;
    private int bufferCount;

    private byte[] k1;
    private byte[] k2;
	
    public AESCMAC() throws NoSuchAlgorithmException {
        this(BLOCK_SIZE);
    }

    public AESCMAC(int length) throws NoSuchAlgorithmException {
        if (length > BLOCK_SIZE) {
            throw new NoSuchAlgorithmException("AES CMAC maximum length is " + BLOCK_SIZE);
        }

        try {
            macLength = length;
            aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
            buffer = new byte[BLOCK_SIZE];
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
        }
    }

    private byte[] doubleSubKey(byte[] k) {
        byte[] ret = new byte[k.length];

        boolean firstBitSet = ((k[0]&0x80) != 0);
        for (int i=0; i<k.length; i++) {
            ret[i] = (byte) (k[i] << 1);
            if (i+1 < k.length && ((k[i+1]&0x80) != 0)) {
                ret[i] |= 0x01;
            }
        }
        if (firstBitSet) {
            ret[ret.length-1] ^= CONSTANT;
        }
        return ret;
    }

    public final void init(Key key) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key is not of required type SecretKey.");
        }
        if (!((SecretKeySpec)key).getAlgorithm().equals("AES")) {
            throw new InvalidKeyException("Key is not an AES key.");
        }
        aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // First calculate k0 from zero bytes
        byte[] k0 = new byte[BLOCK_SIZE];
        try {
            aesCipher.update(k0, 0, k0.length, k0, 0);
        } catch (ShortBufferException sbe) {}

        // Calculate values for k1 and k2
        k1 = doubleSubKey(k0);
        k2 = doubleSubKey(k1);

        aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        bufferCount = 0;
    }

    public final void updateByte(byte b) {
        updateBlock(new byte[] { b });
    }

    public final void updateBlock(byte[] data) {
        int currentOffset = 0;

        if (data.length < BLOCK_SIZE-bufferCount) {
            System.arraycopy(data, 0, buffer, bufferCount, data.length);
            bufferCount += data.length;
            return;
        } else if (bufferCount > 0) {
            System.arraycopy(data, 0, buffer, bufferCount, BLOCK_SIZE-bufferCount);
            try {
                aesCipher.update(buffer, 0, BLOCK_SIZE, buffer, 0);
            } catch (ShortBufferException sbe) {}
            currentOffset += BLOCK_SIZE-bufferCount;
            bufferCount = 0;
        }

        // Transform all the full blocks in data
        while (currentOffset+BLOCK_SIZE < data.length) {
            try {
                aesCipher.update(data, currentOffset, BLOCK_SIZE, buffer, 0);
            } catch (ShortBufferException sbe) {}
            currentOffset += BLOCK_SIZE;
        }

        // Save the leftover bytes to buffer
        if (currentOffset != data.length) {
            System.arraycopy(data, currentOffset, buffer, 0, data.length-currentOffset);
            bufferCount = data.length-currentOffset;
        }
    }

    public final byte[] doFinal() {
        byte[] subKey = k1;
        if (bufferCount < BLOCK_SIZE) {
            // Add padding and XOR with k2 instead
            buffer[bufferCount] = (byte) 0x80;
            for (int i=bufferCount+1; i<BLOCK_SIZE; i++)
                buffer[i] = (byte) 0x00;
            subKey = k2;
        }
        for (int i=0; i<BLOCK_SIZE; i++) {
            buffer[i] ^= subKey[i];
        }

        // Calculate the final CMAC calue
        try {
            aesCipher.doFinal(buffer, 0, BLOCK_SIZE, buffer, 0);
        }
        // These should never happen because we pad manually
        catch (ShortBufferException sbe) {}
        catch (IllegalBlockSizeException ibse) {}
        catch (BadPaddingException ibse) {}
        bufferCount = 0;

        byte[] mac = new byte[macLength];
        System.arraycopy(buffer, 0, mac, 0, macLength);
        return  mac;
    }

    public final byte[] calculateHash(byte[] data) {
        updateBlock(data);
        return doFinal();
    }

	@Override
	public void init(CipherParameters cipheringParams) throws IllegalArgumentException {
		
		if (cipheringParams instanceof ParametersWithIV)
		{
			iv = ((ParametersWithIV) cipheringParams).getIV();
			if (iv == null)
				iv = new byte[16]; 

			cipheringParams = ((ParametersWithIV) cipheringParams).getParameters();
		}
		
		if (!(cipheringParams instanceof KeyParameter))
		{
			throw new IllegalArgumentException("cipheringParams must contain KeyParameter");
		}
		byte [] masterKey = ((KeyParameter) cipheringParams).getKey();
		if (masterKey == null)
		{
			throw new IllegalArgumentException("Key cannot be null");
		}
		try {
			init(new SecretKeySpec(masterKey, "AES"));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public String getAlgorithmName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getMacSize() {
		return macLength;
	}

	@Override
	public void update(byte input) throws IllegalStateException {
		updateByte(input);
	}

	@Override
	public void update(byte[] input, int inputOffset, int inputLen) throws IllegalStateException {
		updateBlock(Arrays.copyOfRange(input, inputOffset, inputOffset+inputLen));
	}

	@Override
	public int doFinal(byte[] output, int outputOffset) throws IllegalStateException {
		byte [] signedData = doFinal();
		System.arraycopy(signedData, 0, output, outputOffset, signedData.length);
		return signedData.length;
	}

	@Override
	public void reset() {
		// TODO Auto-generated method stub
		iv = new byte[16];
	}
}