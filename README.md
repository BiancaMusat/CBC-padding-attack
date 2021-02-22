# CBC-padding-attack

============================= CBC Padding Attack ==============================

--------------------------------- Overview ------------------------------------

    I have implemented the CBC Padding Attack as described by Robert Heaton in
"The Padding Oracle Attack" article.
source: https://robertheaton.com/2013/07/29/padding-oracle-attack/

    In this attck we assume that we have an Oracle that tells us if the cipthertext
we are submitting produces a plaintext with valid padding, or not.
    In order to use this advantage, first we create an intermidiate state as shown
below:
    IV         cipthertext C1
     |              |
     |          Block cipther
     |            decryption
     |              |
     |      Intermidiate state I1
     |              |
     --------------xor
                    |
                plaintext P1

    The Intermidiate state is equal to the ciphertext after being decripted, but
before being xored with the IV. At the same time, the Intermidiate state is
also equal to IV xor plaintext. From this equation is easy to find the plaintext:

P1 = IV xor I1

    We already know the IV, so all we need to find is the intermidiate state
in order to decript the message.

    We will take advantaje of the fact that the Oracle will tell us if the padding
is correct or not, by passing a chosen ciphertext (we will call it IV') and
concatenate it with C1. IV' will consist of 15 random bytes + a 16th byte that we
will brute-force (this is true for the first iteration in the block, when we try to
find the last byte). After we find the byte for which the Orcale says a correct padding
resulted, we simply calculate the 16th byte of I1: I1[16] = IV'[16] xor idx, where idx
corresponds to the position of the byte that is being decripted (in our case is 01, as
we are trying to find the first byte from the end of the plaintext).
The 16th bit of plaintext will be: P1[16] = IV[16] xor I1[16].

    In order to prepare the next step, we have to update the last byte of IV' so that
the idx previously specified will increment (in our example, new_idx = 02).
SO, IV'[16] = new_idx xor I1[16].

    In the next iteration we will brute-force the 15th byte. For IV' we choose the first
14 bytes to be random, the 15th byte will be brute-forced, and the 16th byte was calculated
in the previous paragraph.
    After the Oracle tells us which byte gave a good padding, we calculate:
I1[15] = IV'[15] xor new_idx
P1[15] = IV[15] xor I1[15].

    Again, we need to update last 2 bytes of IV' in order to prepare for the next step(new_idx
will be 03).

    We will do this again and again until all the bytes in every block have been decripted.

    An important observation is that, for the first block the IV is the given IV, but for the
rest of the block, the IV will be the previous block.

--------------------------------------- Implementation details ---------------------------------------

Implementation details:
    - split the ciphertext in blocks by calling blockify method
    - for each block, call cbc_attack method that decripts one block
    - cbc_attck:
        - choose the correct iv (for block 0, the iv is the actual given IV, for the rest of
        the blocks, the iv is the previous block)
        - for each byte in the block, try every possibility (from 0 to 255) and test if it is correct:
            - iv' will be made of i-1 random bytes + one byte which we should guess + the rest of the
            bytes that are known from previos loops (note that i starts from 15 and goes to 0)
            - as described in the algorithm above, we pass to the Oracle the concatenation of iv' and the
            current ciphertext block, and then the iv. If the Oracle returns True, it means that we have a correct
            padding so the guess was right. We now calculate the intermidiate state as described before, and
            the byte in the decripted message will be the xor between the corresponding byte in the intermidiate
            state and the corresponding byte in iv.
            - the last step is to replace the last block_size - i bytes from the iv' in order to prepare
            for the next iteartion. For this, we calculate the byte in the intermidiate state (we take advantage
            of the fact that the intermidiate state is equal to plaintext xor iv, and, as we already know the
            bytes (of the plaintext) we are intrested in in this step -- as they have been calculated in the
            previos loops -- we can directly calculate the intermidiate state). The byte in the iv' will be
            calculated as xor between this intermidiate state byte and the new_idx from the description above
            which corresponds to the next iteration (new_idx = block_size - i + 1).
