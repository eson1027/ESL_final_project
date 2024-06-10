#include <cmath>
#ifndef NATIVE_SYSTEMC
#include "stratus_hls.h"
#endif

#include "SobelFilter.h"

SobelFilter::SobelFilter(sc_module_name n) : sc_module(n)
{
#ifndef NATIVE_SYSTEMC
  // HLS_FLATTEN_ARRAY(expansion);
  // HLS_FLATTEN_ARRAY(ciphertext);
  // HLS_FLATTEN_ARRAY(key);
  // HLS_FLATTEN_ARRAY(subkeys[16]);
#endif
  SC_THREAD(do_filter);
  sensitive << i_clk.pos();
  dont_initialize();
  reset_signal_is(i_rst, false);

#ifndef NATIVE_SYSTEMC
  i_rgb.clk_rst(i_clk, i_rst);
  o_result.clk_rst(i_clk, i_rst);
#endif
}

SobelFilter::~SobelFilter() {}

uint32_t SobelFilter::left_rot(uint32_t value, int shift)
{
  if ((shift %= 28) == 0)
    return value;
  return ((value << shift) | (value >> (28 - shift))) & mask28bit;
} // 旋轉左半邊的28bit

uint32_t SobelFilter::right_rot(uint32_t value, int shift)
{
  if ((shift %= 28) == 0)
    return value;
  return ((value >> shift) | (value << (28 - shift))) & mask28bit;
} // 旋轉右半邊的28bit

uint8_t SobelFilter::PC_1_permutation(uint8_t *key)
{
  uint8_t res[8];
  HLS_FLATTEN_ARRAY(res);
  for (int j = 0; j < 8; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE, "1");
    uint8_t temp = 0;
    for (int i = j * 7; i < (j + 1) * 7; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"2");
      int k_1 = (PC_1[i] >> 3);  // 前5 bit存到k_1
      int k_2 = PC_1[i] & 0b111; // 後3 bit存到k_2
      if (key[k_1] & (1 << (8 - k_2)))
      {
        temp = (temp << 1) + 1;
      }
      else
      {
        temp = temp << 1;
      }
    }
    res[j] = temp;
  }
  for (int i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"3");
    key[i] = res[i];
  }

  return 0;
}

uint8_t SobelFilter::PC_2_permutation(uint8_t *key, uint8_t *subkey)
{
  uint8_t res[8];
  HLS_FLATTEN_ARRAY(res);
  for (int j = 0; j < 8; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"4");
    uint8_t temp = 0;
    for (int i = j * 6; i < (j + 1) * 6; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"5");
      int k_1 = (PC_2[i] - 1) / 7;
      int k_2 = (PC_2[i] - 1) % 7;
      if (key[k_1] & (1 << (6 - k_2)))
      {
        temp = (temp << 1) + 1;
      }
      else
      {
        temp = temp << 1;
      }
    }
    res[j] = temp;
  }
  for (int i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"6");
    subkey[i] = res[i];
  }

  return 0;
}

uint8_t SobelFilter::IP_or_IP_inv(uint8_t *plaintext, const int *table)
{
  uint8_t res[8];
  HLS_FLATTEN_ARRAY(res);
  for (int j = 0; j < 8; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"7");
    uint8_t temp = 0;
    for (int i = j * 8; i < (j + 1) * 8; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"8");
      int k_1 = (table[i] - 1) / 8;
      int k_2 = (table[i] - 1) % 8;
      // printf("table[0]=%d, table[%d]=%d\n", table[0], i, table[i]);
      // printf("k_2: %d\n", k_2);
      if (plaintext[k_1] & (1 << (7 - k_2)))
      {
        temp = (temp << 1) + 1;
      }
      else
      {
        temp = temp << 1;
      }
    }
    res[j] = temp;
  }
  for (int i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"9");
    plaintext[i] = res[i];
  }
  return 0;
}

uint8_t SobelFilter::Expansion(uint8_t *R, uint8_t *output)
{
  uint8_t res[8];

  for (int j = 0; j < 8; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"10");//花 8 cycle
    uint8_t temp = 0;
    for (int i = j * 6; i < (j + 1) * 6; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"11"); //花 1 cycle
      int k_1 = (E[i] - 1) / 8;
      int k_2 = (E[i] - 1) % 8;
      if (R[k_1] & (1 << (7 - k_2)))
      {
        temp = (temp << 1) + 1;
      }
      else
      {
        temp = temp << 1;
      }
    }
    res[j] = temp;
  }
  for (int i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"12");
    output[i] = res[i];
  }
  return 0;
}

uint8_t SobelFilter::S_box(uint8_t *xored_R)
{

  for (int i = 0; i < 8; i++)
  {
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE, "13");
    int column = (xored_R[i] & 0b011110) >> 1;
    int row = ((xored_R[i] & 0b100000) >> 4) | (xored_R[i] & 0b000001);
    xored_R[i] = S[i][row][column];
  }
  return 0;
}

uint8_t SobelFilter::P_perm_and_xored(uint8_t *s_boxed, uint8_t *plaintext)
{
  uint8_t res[4];
  HLS_FLATTEN_ARRAY(res);
  for (int j = 0; j < 4; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"14");
    uint8_t temp = 0;
    for (int i = j * 8; i < (j + 1) * 8; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"15");
      int k_1 = (P[i] - 1) / 4;
      int k_2 = (P[i] - 1) % 4;
      if (s_boxed[k_1] & (1 << (3 - k_2)))
      {
        temp = (temp << 1) + 1;
      }
      else
      {
        temp = temp << 1;
      }
    }
    res[j] = temp ^ plaintext[j];
  }
  for (int i = 0; i < 4; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"16");
    plaintext[i] = res[i];
  }
  return 0;
}

void SobelFilter::do_filter()
{
  {
#ifndef NATIVE_SYSTEMC
    HLS_DEFINE_PROTOCOL("main_reset");
    i_rgb.reset();
    o_result.reset();
#endif
    wait();
  }
  uint8_t subkeys[16][8];
  HLS_FLATTEN_ARRAY(subkeys);
  uint8_t expansion[8];
  HLS_FLATTEN_ARRAY(expansion);
  uint8_t ciphertext[8];
  HLS_FLATTEN_ARRAY(ciphertext);
  uint8_t key[8];
  HLS_FLATTEN_ARRAY(key);

  uint32_t temp1, temp2;

  for (uint_fast16_t i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"17");//花 4 cycle
#ifndef NATIVE_SYSTEMC
    {
      HLS_DEFINE_PROTOCOL("input");
      ciphertext[i] = i_rgb.get();
      wait();
      key[i] = i_rgb.get();
      wait();
    }
#else
    R = i_rgb.read();
    wait();
    G = i_rgb.read();
    wait();
#endif
  }
  // for (uint_fast16_t i = 0; i < 8; i++) {
  //	printf("k: %d\n",ciphertext[i]);
  // }
  IP_or_IP_inv(ciphertext, IP);

  // for (uint_fast16_t i = 0; i < 8; i++)
  // {
  //   printf("first: %d\n", ciphertext[i]);
  // }
  PC_1_permutation(key);

  // 計算子密鑰
  for (int j = 0; j < 16; j++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"18");
    memset(subkeys[j], 0, sizeof(subkeys[j]));
    memset(&temp1, 0, sizeof(temp1));
    memset(&temp2, 0, sizeof(temp2));

    temp1 = (key[0] << 21) | (key[1] << 14) | (key[2] << 7) | key[3];
    temp2 = (key[4] << 21) | (key[5] << 14) | (key[6] << 7) | key[7];
    temp1 = left_rot(temp1, shift_table[j]);
    temp2 = left_rot(temp2, shift_table[j]);
    for (int i = 0; i < 4; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"19");
      key[3 - i] = temp1 & 0b1111111;
      key[7 - i] = temp2 & 0b1111111;
      temp1 = temp1 >> 7;
      temp2 = temp2 >> 7;
    }
    PC_2_permutation(key, subkeys[j]);
  }

  // 加密
  for (int j = 0; j < 16; j++)
  {
    // HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"20");//花 17 cycle
    Expansion(ciphertext + 4, expansion);
    for (int i = 0; i < 8; i++)
    {
      HLS_UNROLL_LOOP(ON, "");
      HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"21");
      expansion[i] ^= subkeys[j][i];
    }
    S_box(expansion);
    P_perm_and_xored(expansion, ciphertext);

    if (j != 15)
    {
      for (int i = 0; i < 4; i++)
      {
        HLS_UNROLL_LOOP(ON, "");
        HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"22");
        ciphertext[i] ^= ciphertext[4 + i];
        ciphertext[4 + i] ^= ciphertext[i];
        ciphertext[i] ^= ciphertext[4 + i];
      }
    }
  }

  // 解密
  // for (int j = 0; j < 16; j++) {
  //   HLS_UNROLL_LOOP( ON, "" );
  //   Expansion(ciphertext + 4, expansion);
  //   for (int i = 0; i < 8; i++) {
  //   HLS_UNROLL_LOOP( ON, "" );
  //     expansion[i] ^= subkeys[15 - j][i];
  //   }
  //   S_box(expansion);
  //   P_perm_and_xored(expansion, ciphertext);

  //   if (j != 15) {
  //     for (int i = 0; i < 4; i++) {
  //        HLS_UNROLL_LOOP( ON, "" );
  //       ciphertext[i] ^= ciphertext[4 + i];
  //       ciphertext[4 + i] ^= ciphertext[i];
  //       ciphertext[i] ^= ciphertext[4 + i];
  //     }
  //   }
  // }

  IP_or_IP_inv(ciphertext, IP_inv);

  // for (uint_fast16_t i = 0; i < 8; i++)
  // {
  //   printf("second: %d\n", ciphertext[i]);
  // }

  for (uint_fast16_t i = 0; i < 8; i++)
  {
    HLS_UNROLL_LOOP(ON, "");
    HLS_CONSTRAIN_LATENCY(0, HLS_ACHIEVABLE,"23");//花 2 cycle
    // printf("k: %d\n",ciphertext[i]);
#ifndef NATIVE_SYSTEMC
    {
      HLS_DEFINE_PROTOCOL("output");
      o_result.put(static_cast<unsigned char>(ciphertext[i]));
      wait();
    }
#else
    o_result.write(ciphertext[i]);
    wait();
#endif
  }
}
