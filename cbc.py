#!/usr/bin/env python

import random
import sys
import math
from Crypto.Cipher import AES
import functools

BLOCK_SIZE = 16
IV = b'This is easy HW!'

# HW - Utility function
def blockify(text, block_size=BLOCK_SIZE):
    """
    Cuts the bytestream into equal sized blocks.

    Args:
      text should be a bytestring (i.e. b'text', bytes('text') or bytearray('text'))
      block_size should be a number

    Return:
      A list that contains bytestrings of maximum block_size bytes

    Example:
      [b'ex', b'am', b'pl', b'e'] = blockify(b'example', 2)
      [b'01000001', b'01000010'] = blockify(b'0100000101000010', 8)
    """
    
    blocks = {}
    for i in range(0, len(text), block_size):
      blocks[int(i/block_size)] = text[i : i + block_size]
    return blocks

# HW - Utility function
def validate_padding(padded_text):
    """
    Verifies if the bytestream ends with a suffix of X times 'X' (eg. '333' or '22')

    Args:
      padded_text should be a bytestring

    Return:
      Boolean value True if the padded is correct, otherwise returns False
    """
    for i in range(1, 17):  #  find padding
      if bytes([padded_text[-1]]) == bytes([i]):
        for j in range (1, i + 1):  # check padding
          if bytes([padded_text[-j]]) != bytes([i]):
            return False
        return True
    return False

# HW - Utility function
def pkcs7_pad(text, block_size=BLOCK_SIZE):
    """
    Appends padding (X times 'X') at the end of a text.
    X depends on the size of the text.
    All texts should be padded, no matter their size!

    Args:
      text should be a bytestring

    Return:
      The bytestring with padding
    """
    padding_len = block_size - len(text)

    if padding_len <= 0:
      padd = bytes([block_size]) * block_size
    else:
      padd = bytes([padding_len]) * (padding_len)
    
    return text + padd

# HW - Utility function
def pkcs7_depad(text):
    """
    Removes the padding of a text (only if it's valid).
    Tip: use validate_padding

    Args:
      text should be a bytestring

    Return:
      The bytestring without the padding or None if invalid
    """
    if validate_padding(text):
      return text[:-text[-1]]
    return None

def aes_dec_cbc(k, c, iv):
    """
    Decrypt a ciphertext c with a key k in CBC mode using AES as follows:
    m = AES(k, c)

    Args:
      c should be a bytestring (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring message m
    """
    aes = AES.new(k, AES.MODE_CBC, iv)
    m = aes.decrypt(c)
    depad_m = pkcs7_depad(m)

    return depad_m

def aes_enc_cbc(m):
  """
    Encript a plaintext m with a key k in CBC mode using AES as follows:
    c = AES(k, m)

    Args:
      m should be a bytestring (i.e. a sequence of characters such as 'Hello...' or '\x02\x04...')
      k should be a bytestring of length exactly 16 bytes.
      iv should be a bytestring of length exactly 16 bytes.

    Return:
      The bytestring ciphertext c
  """
  key = b'za best key ever'
  aes = AES.new(key, AES.MODE_CBC, IV)
  c = aes.encrypt(m)

  return c

def check_cbcpad(c, iv):
    """
    Oracle for checking if a given ciphertext has correct CBC-padding.
    That is, it checks that the last n bytes all have the value n.

    Args:
      c is the ciphertext to be checked.
      iv is the initialization vector for the ciphertext.
      Note: the key is supposed to be known just by the oracle.

    Return 1 if the pad is correct, 0 otherwise.
    """

    key = b'za best key ever'

    if aes_dec_cbc(key, c, iv) != None:
        return 1

    return 0

def cbc_attck(blocks, block, block_size=BLOCK_SIZE):
  """
  More details about the algorithm can be found here:
  https://robertheaton.com/2013/07/29/padding-oracle-attack/
  """
  bit_idx = 0
  aux_ciphertext = [random.randint(0, 255)] * block_size
  message = [random.randint(0, 255)] * block_size
  msg = ""

  if block == 0: 
    iv = IV
  else:
    iv = blocks[block - 1]

  for i in range(block_size - 1, -1, -1):  # crack cyphertext block byte by byte
    for guess in range(0, 256):  # do a guess
      aux_ciphertext[i] = guess
      ciphertext = blocks[block]
      if not check_cbcpad(bytes(aux_ciphertext) + ciphertext, iv):  # check if padding is correct
        continue
      bit_idx = block_size - i  # 01 for first iteration, 02 for the second iteration and so on
      interm_state = bit_idx ^ guess
      message[i] = interm_state ^ iv[i]  # update message with the decripted byte
      break
    for j in range(1, bit_idx + 2):  # update last block_size - i bytes from aux_ciphertext for next iteration
      idx = block_size - j
      interm_state = message[idx] ^ iv[idx]
      aux_ciphertext[idx] = (block_size - i + 1) ^ interm_state

  # form decripted message block
  msg = "".join([chr(int(m)) for m in message])
  return msg

if __name__ == "__main__":
    ctext = "918073498F88237C1DC7697ED381466719A2449EE48C83EABD5B944589ED66B77AC9FBD9EF98EEEDDD62F6B1B8F05A468E269F9C314C3ACBD8CC56D7C76AADE8484A1AE8FE0248465B9018D395D3846C36A4515B2277B1796F22B7F5B1FBE23EC1C342B9FD08F1A16F242A9AB1CD2DE51C32AC4F94FA1106562AE91A98B4480FDBFAA208E36678D7B5943C80DD0D78C755CC2C4D7408F14E4A32A3C4B61180084EAF0F8ECD5E08B3B9C5D6E952FF26E8A0499E1301D381C2B4C452FBEF5A85018F158949CC800E151AECCED07BC6C72EE084E00F38C64D989942423D959D953EA50FBA949B4F57D7A89EFFFE640620D626D6F531E0C48FAFC3CEF6C3BC4A98963579BACC3BD94AED62BF5318AB9453C7BAA5AC912183F374643DC7A5DFE3DBFCD9C6B61FD5FDF7FF91E421E9E6D9F633"
    ciphertext = bytes.fromhex(ctext)
    msg = ""

    # TODO: implement the CBC-padding attack to find the message corresponding to the above ciphertext
    # Note: you cannot use the key known by the oracle
    # You can use the known IV in order to recover the full message
  
    # split ciphertext in bloks of length = 16
    blocks = blockify(ciphertext)
    # for each block, apply CBC attack
    for block in range(len(blocks)): # for each block
      msg += cbc_attck(blocks, block)
    
    print(msg)
