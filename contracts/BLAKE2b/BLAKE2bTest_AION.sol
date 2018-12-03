pragma solidity ^0.4.15;

contract BLAKE2_Constants{
    /*
    Constants, as defined in RFC 7693
    */


      uint64[8] public IV = [
          0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
          0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
          0x510e527fade682d1, 0x9b05688c2b3e6c1f,
          0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
      ];

      uint64 constant MASK_0 = 0xFF00000000000000;
      uint64 constant MASK_1 = 0x00FF000000000000;
      uint64 constant MASK_2 = 0x0000FF0000000000;
      uint64 constant MASK_3 = 0x000000FF00000000;
      uint64 constant MASK_4 = 0x00000000FF000000;
      uint64 constant MASK_5 = 0x0000000000FF0000;
      uint64 constant MASK_6 = 0x000000000000FF00;
      uint64 constant MASK_7 = 0x00000000000000FF;

      uint64 constant SHIFT_0 = 0x0100000000000000;
      uint64 constant SHIFT_1 = 0x0000010000000000;
      uint64 constant SHIFT_2 = 0x0000000001000000;
      uint64 constant SHIFT_3 = 0x0000000000000100;
}

contract GasTest{
  uint128 lastGas;
  uint128 constant calibration = 5194;
  event LogGas(string message, int gas);

  function Log(string message){
      if(lastGas == 0){
        lastGas = msg.gas;
      }
      LogGas(message, int(lastGas - msg.gas - calibration));
      lastGas = msg.gas;
  }

  event LogVal(string message, bytes32 v);
}

contract BLAKE2b is GasTest, BLAKE2_Constants{

  struct BLAKE2b_ctx {
    uint256[4] b; //input buffer
    uint64[8] h;  //chained state
    uint128 t; //total bytes
    uint64 c; //Size of b
    uint128 outlen; //diigest output size
  }

  // Mixing Function
  function G(uint64[16] v, uint128 a, uint128 b, uint128 c, uint128 d, uint64 x, uint64 y) constant {

       // Dereference to decrease memory reads
       uint64 va = v[a];
       uint64 vb = v[b];
       uint64 vc = v[c];
       uint64 vd = v[d];

       //Optimised mixing function
       assembly{
         // v[a] := (v[a] + v[b] + x) mod 2**64
         va := addmod(add(va,vb),x, 0x10000000000000000)
         //v[d] := (v[d] ^ v[a]) >>> 32
         vd := xor(div(xor(vd,va), 0x100000000), mulmod(xor(vd, va),0x100000000, 0x10000000000000000))
         //v[c] := (v[c] + v[d])     mod 2**64
         vc := addmod(vc,vd, 0x10000000000000000)
         //v[b] := (v[b] ^ v[c]) >>> 24
         vb := xor(div(xor(vb,vc), 0x1000000), mulmod(xor(vb, vc),0x10000000000, 0x10000000000000000))
         // v[a] := (v[a] + v[b] + y) mod 2**64
         va := addmod(add(va,vb),y, 0x10000000000000000)
         //v[d] := (v[d] ^ v[a]) >>> 16
         vd := xor(div(xor(vd,va), 0x10000), mulmod(xor(vd, va),0x1000000000000, 0x10000000000000000))
         //v[c] := (v[c] + v[d])     mod 2**64
         vc := addmod(vc,vd, 0x10000000000000000)
         // v[b] := (v[b] ^ v[c]) >>> 63
         vb := xor(div(xor(vb,vc), 0x8000000000000000), mulmod(xor(vb, vc),0x2, 0x10000000000000000))
       }

       v[a] = va;
       v[b] = vb;
       v[c] = vc;
       v[d] = vd;
  }


  function compress(BLAKE2b_ctx ctx, bool last) internal {
    //TODO: Look into storing these as uint256[4]
    uint64[16] memory v;
    uint64[16] memory m;


    for(uint128 i=0; i<8; i++){
      v[i] = ctx.h[i]; // v[:8] = h[:8]
      v[i+8] = IV[i];  // v[8:] = IV
    }

    //
    v[12] = v[12] ^ uint64(ctx.t % 2**64);  //Lower word of t
    v[13] = v[13] ^ uint64(ctx.t / 2**64);

    if(last) v[14] = ~v[14];   //Finalization flag

    uint64 mi;  //Temporary stack variable to decrease memory ops
    uint128 b; // Input buffer

    for(i = 0; i <16; i++){ //Operate 16 words at a time
      uint128 k = i%4; //Current buffer word
      mi = 0;
      if(k == 0){
        b=ctx.b[i/4];  //Load relevant input into buffer
      }

      //Extract relevent input from buffer
      assembly{
        mi := and(div(b,exp(2,mul(64,sub(3,k)))), 0xFFFFFFFFFFFFFFFF)
      }

      //Flip endianness
      m[i] = getWords(mi);
    }

    //Mix m

          G( v, 0, 4, 8, 12, m[0], m[1]);
          G( v, 1, 5, 9, 13, m[2], m[3]);
          G( v, 2, 6, 10, 14, m[4], m[5]);
          G( v, 3, 7, 11, 15, m[6], m[7]);
          G( v, 0, 5, 10, 15, m[8], m[9]);
          G( v, 1, 6, 11, 12, m[10], m[11]);
          G( v, 2, 7, 8, 13, m[12], m[13]);
          G( v, 3, 4, 9, 14, m[14], m[15]);


          G( v, 0, 4, 8, 12, m[14], m[10]);
          G( v, 1, 5, 9, 13, m[4], m[8]);
          G( v, 2, 6, 10, 14, m[9], m[15]);
          G( v, 3, 7, 11, 15, m[13], m[6]);
          G( v, 0, 5, 10, 15, m[1], m[12]);
          G( v, 1, 6, 11, 12, m[0], m[2]);
          G( v, 2, 7, 8, 13, m[11], m[7]);
          G( v, 3, 4, 9, 14, m[5], m[3]);


          G( v, 0, 4, 8, 12, m[11], m[8]);
          G( v, 1, 5, 9, 13, m[12], m[0]);
          G( v, 2, 6, 10, 14, m[5], m[2]);
          G( v, 3, 7, 11, 15, m[15], m[13]);
          G( v, 0, 5, 10, 15, m[10], m[14]);
          G( v, 1, 6, 11, 12, m[3], m[6]);
          G( v, 2, 7, 8, 13, m[7], m[1]);
          G( v, 3, 4, 9, 14, m[9], m[4]);


          G( v, 0, 4, 8, 12, m[7], m[9]);
          G( v, 1, 5, 9, 13, m[3], m[1]);
          G( v, 2, 6, 10, 14, m[13], m[12]);
          G( v, 3, 7, 11, 15, m[11], m[14]);
          G( v, 0, 5, 10, 15, m[2], m[6]);
          G( v, 1, 6, 11, 12, m[5], m[10]);
          G( v, 2, 7, 8, 13, m[4], m[0]);
          G( v, 3, 4, 9, 14, m[15], m[8]);


          G( v, 0, 4, 8, 12, m[9], m[0]);
          G( v, 1, 5, 9, 13, m[5], m[7]);
          G( v, 2, 6, 10, 14, m[2], m[4]);
          G( v, 3, 7, 11, 15, m[10], m[15]);
          G( v, 0, 5, 10, 15, m[14], m[1]);
          G( v, 1, 6, 11, 12, m[11], m[12]);
          G( v, 2, 7, 8, 13, m[6], m[8]);
          G( v, 3, 4, 9, 14, m[3], m[13]);


          G( v, 0, 4, 8, 12, m[2], m[12]);
          G( v, 1, 5, 9, 13, m[6], m[10]);
          G( v, 2, 6, 10, 14, m[0], m[11]);
          G( v, 3, 7, 11, 15, m[8], m[3]);
          G( v, 0, 5, 10, 15, m[4], m[13]);
          G( v, 1, 6, 11, 12, m[7], m[5]);
          G( v, 2, 7, 8, 13, m[15], m[14]);
          G( v, 3, 4, 9, 14, m[1], m[9]);


          G( v, 0, 4, 8, 12, m[12], m[5]);
          G( v, 1, 5, 9, 13, m[1], m[15]);
          G( v, 2, 6, 10, 14, m[14], m[13]);
          G( v, 3, 7, 11, 15, m[4], m[10]);
          G( v, 0, 5, 10, 15, m[0], m[7]);
          G( v, 1, 6, 11, 12, m[6], m[3]);
          G( v, 2, 7, 8, 13, m[9], m[2]);
          G( v, 3, 4, 9, 14, m[8], m[11]);


          G( v, 0, 4, 8, 12, m[13], m[11]);
          G( v, 1, 5, 9, 13, m[7], m[14]);
          G( v, 2, 6, 10, 14, m[12], m[1]);
          G( v, 3, 7, 11, 15, m[3], m[9]);
          G( v, 0, 5, 10, 15, m[5], m[0]);
          G( v, 1, 6, 11, 12, m[15], m[4]);
          G( v, 2, 7, 8, 13, m[8], m[6]);
          G( v, 3, 4, 9, 14, m[2], m[10]);


          G( v, 0, 4, 8, 12, m[6], m[15]);
          G( v, 1, 5, 9, 13, m[14], m[9]);
          G( v, 2, 6, 10, 14, m[11], m[3]);
          G( v, 3, 7, 11, 15, m[0], m[8]);
          G( v, 0, 5, 10, 15, m[12], m[2]);
          G( v, 1, 6, 11, 12, m[13], m[7]);
          G( v, 2, 7, 8, 13, m[1], m[4]);
          G( v, 3, 4, 9, 14, m[10], m[5]);


          G( v, 0, 4, 8, 12, m[10], m[2]);
          G( v, 1, 5, 9, 13, m[8], m[4]);
          G( v, 2, 6, 10, 14, m[7], m[6]);
          G( v, 3, 7, 11, 15, m[1], m[5]);
          G( v, 0, 5, 10, 15, m[15], m[11]);
          G( v, 1, 6, 11, 12, m[9], m[14]);
          G( v, 2, 7, 8, 13, m[3], m[12]);
          G( v, 3, 4, 9, 14, m[13], m[0]);


          G( v, 0, 4, 8, 12, m[0], m[1]);
          G( v, 1, 5, 9, 13, m[2], m[3]);
          G( v, 2, 6, 10, 14, m[4], m[5]);
          G( v, 3, 7, 11, 15, m[6], m[7]);
          G( v, 0, 5, 10, 15, m[8], m[9]);
          G( v, 1, 6, 11, 12, m[10], m[11]);
          G( v, 2, 7, 8, 13, m[12], m[13]);
          G( v, 3, 4, 9, 14, m[14], m[15]);


          G( v, 0, 4, 8, 12, m[14], m[10]);
          G( v, 1, 5, 9, 13, m[4], m[8]);
          G( v, 2, 6, 10, 14, m[9], m[15]);
          G( v, 3, 7, 11, 15, m[13], m[6]);
          G( v, 0, 5, 10, 15, m[1], m[12]);
          G( v, 1, 6, 11, 12, m[0], m[2]);
          G( v, 2, 7, 8, 13, m[11], m[7]);
          G( v, 3, 4, 9, 14, m[5], m[3]);



    //XOR current state with both halves of v
    for(i=0; i<8; ++i){
      ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i+8];
    }

  }


  function init(BLAKE2b_ctx ctx, uint64 outlen, bytes key, uint64[2] salt, uint64[2] person) internal{

      if(outlen == 0 || outlen > 64 || key.length > 64) throw;

      //Initialize chained-state to IV
      for(uint128 i = 0; i< 8; i++){
        ctx.h[i] = IV[i];
      }

      // Set up parameter block
      ctx.h[0] = ctx.h[0] ^ 0x01010000 ^ shift_left(uint64(key.length), 8) ^ outlen;
      ctx.h[4] = ctx.h[4] ^ salt[0];
      ctx.h[5] = ctx.h[5] ^ salt[1];
      ctx.h[6] = ctx.h[6] ^ person[0];
      ctx.h[7] = ctx.h[7] ^ person[1];

      ctx.outlen = outlen;
      i = key.length;

      //Run hash once with key as input
      if(key.length > 0){
        update(ctx, key);
        ctx.c = 128;
      }
  }


  function update(BLAKE2b_ctx ctx, bytes input) internal {

    for(uint128 i = 0; i < input.length; i++){
      //If buffer is full, update byte counters and compress
      if(ctx.c == 128){
        ctx.t += ctx.c;
        compress(ctx, false);
        ctx.c = 0;
      }

      //Update temporary counter c
      uint128 c = ctx.c++;

      // b -> ctx.b
      uint128[4] memory b = ctx.b;
      uint8 a = uint8(input[i]);

      // ctx.b[c] = a
      assembly{
        mstore8(add(b,c),a)
      }
    }
  }


  function finalize(BLAKE2b_ctx ctx, uint64[8] out) internal {
    // Add any uncounted bytes
    ctx.t += ctx.c;

    // Compress with finalization flag
    compress(ctx,true);

    //Flip little to big endian and store in output buffer
    for(uint128 i=0; i < ctx.outlen / 8; i++){
      out[i] = getWords(ctx.h[i]);
    }

    //Properly pad output if it doesn't fill a full word
    if(ctx.outlen < 64){
      out[ctx.outlen/8] = shift_right(getWords(ctx.h[ctx.outlen/8]),64-8*(ctx.outlen%8));
    }

  }

  //Helper function for full hash function
  function blake2b(bytes input, bytes key, bytes salt, bytes personalization, uint64 outlen) constant public returns(uint64[8]){

    BLAKE2b_ctx memory ctx;
    uint64[8] memory out;

    init(ctx, outlen, key, formatInput(salt), formatInput(personalization));
    update(ctx, input);
    finalize(ctx, out);
    return out;
  }

  function blake2b(bytes input, bytes key, uint64 outlen) constant returns (uint64[8]){
    return blake2b(input, key, "", "", outlen);
  }

// Utility functions

  //Flips endianness of words
  function getWords(uint64 a) constant returns (uint64 b) {
    return  (a & MASK_0) / SHIFT_0 ^
            (a & MASK_1) / SHIFT_1 ^
            (a & MASK_2) / SHIFT_2 ^
            (a & MASK_3) / SHIFT_3 ^
            (a & MASK_4) * SHIFT_3 ^
            (a & MASK_5) * SHIFT_2 ^
            (a & MASK_6) * SHIFT_1 ^
            (a & MASK_7) * SHIFT_0;
  }

  function shift_right(uint64 a, uint128 shift) constant returns(uint64 b){
    return uint64(a / 2**shift);
  }

  function shift_left(uint64 a, uint128 shift) constant returns(uint64){
    return uint64((a * 2**shift) % (2**64));
  }

  //bytes -> uint64[2]
  function formatInput(bytes input) constant returns (uint64[2] output){
    for(uint128 i = 0; i<input.length; i++){
        output[i/8] = output[i/8] ^ shift_left(uint64(input[i]), 64-8*(i%8+1));
    }
        output[0] = getWords(output[0]);
        output[1] = getWords(output[1]);
  }

  function formatOutput(uint64[8] input) constant returns(bytes32[2]){
    bytes32[2] memory result;

    for(uint128 i = 0; i < 8; i++){
        result[i/4] = result[i/4] ^ bytes32(input[i] * 2**(64*(3-i%4)));
    }
    return result;
  }
}

contract EventDefinitions {
  event Param(uint64[8] h, uint64[2] salt);
  event ReportGas(uint128 g);
}

contract BlakeTest is Test, EventDefinitions, GasTest {
  BLAKE2b blake;
  Tester tester;
  uint128 startGas;

  function BlakeTest(){
    blake = new BLAKE2b();
  }

  function setUp(){
    tester = new Tester();
    tester._target(blake);
  }

  function testDeploy(){
    startGas = msg.gas;
    new BLAKE2b();
    ReportGas(startGas-msg.gas);
  }

  function testFinalHash(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("abc", "", 64);
    ReportGas(startGas-msg.gas);

    uint64[8] memory trueHash = [0xba80a53f981c4d0d,0x6a2797b69f12f6e9,
                                0x4c212f14685ac4b7,0x4b12bb6fdbffa2d1,
                                0x7d87c5392aab792d,0xc252d5de4533cc95,
                                0x18d38aa8dbf1925a,0xb92386edd4009923];

    assertTrue(equals(result, trueHash));

  }

  function testLongInput(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("The quick brown fox jumped over the lazy dog.", "", 64);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash = [0x054b087096f9a555,0x3a09a8419cfd16db,
                                 0x872805a31dd518be,0x12534d03749edb2a,
                                 0x09da6731b89b5f71,0x38fcedc93cbf7536,
                                 0x8db91378930e94c3,0xccc65e829b0aa349];

    assertTrue(equals(result, trueHash));

  }

  function test256ByteInput(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis a ornare ligula. In finibus justo erat, eu tristique lacus nullam","","","",64);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash = [0x43c111a9341fb609,0x185d4e93afaf43b6,
                                 0x4fd494647231c452,0x4d5ea1f8535cc7e0,
                                 0x59adb2896939e9e4,0x48d6d6c7de06090d,
                                 0xb225d13e6174c132,0xa639848c2148563c];

     assertTrue(equals(result, trueHash),bytes32(result[0]));
  }

  function testShortOutput(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("abc", "", 20);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash =[0x384264f676f39536,0x840523f284921cdc,
                                0x0000000068b6846b,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000];

      assertTrue(equals(result, trueHash));
  }

  function testKeyedHash(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("hello", "world", 32);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash =[0x38010cfe3a8e684c,0xb17e6d049525e71d,
                                0x4e9dc3be173fc05b,0xf5c5ca1c7e7c25e7,
                                0x0000000000000000,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000];

    assertTrue(equals(result, trueHash));
  }

  function testPersonalization(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("hello world", "", "This is a salt", "ZcashPoW", 16);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash =[0xf5777402bb566668,0xe12a1399014d4724,
                                0x0000000000000000,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000];

    assertTrue(equals(result, trueHash), bytes32(result[0]));
    ReportGas(startGas-msg.gas);
  }

  function testSaltedHash(){
    startGas = msg.gas;
    uint64[8] memory result = blake.blake2b("hello world", "", "This is a salt", "", 32);
    ReportGas(startGas-msg.gas);
    uint64[8] memory trueHash =[0x7d6bd0ad9213190a,0xef28530c87359f3a,
                                0x1a7cd77c22828ba8,0x916784d56b576e67,
                                0x0000000000000000,0x0000000000000000,
                                0x0000000000000000,0x0000000000000000];

    assertTrue(equals(result, trueHash), bytes32(result[0]));
  }

  function testOutputFormatter(){
    uint64[8] memory out =[0x054b087096f9a555,0x3a09a8419cfd16db,
                          0x872805a31dd518be,0x12534d03749edb2a,
                          0x09da6731b89b5f71,0x38fcedc93cbf7536,
                          0x8db91378930e94c3,0xccc65e829b0aa349];

    bytes32[2] memory formatted =[bytes32(0x054b087096f9a5553a09a8419cfd16db872805a31dd518be12534d03749edb2a),
                                  bytes32(0x09da6731b89b5f7138fcedc93cbf75368db91378930e94c3ccc65e829b0aa349)];

    bytes32[2] memory result = blake.formatOutput(out);

    assertTrue(result[0] == formatted[0] && result[1] == formatted[1], result[0]);
  }
/*
  function testEventParams(){
    expectEventsExact(blake);
    uint64[8] memory h = [0x6a09e667f2bdc948, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x731fad91702a397b, 0x9b05688c4d6b282c, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
    uint64[2] memory salt = [0x2211ffeeddccbbaa,0x66554433];
    Param(h, salt);
    blake.blake2b("abc","","\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66","",64);
  }
*/
  function equals(uint64[8] a, uint64[8] b) constant returns(bool){
    for(uint128 i; i<8; i++){
      if(a[i] != b[i]){
        return false;
      }
    }
    return true;
  }

}

