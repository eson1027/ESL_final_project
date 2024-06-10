#ifndef SOBEL_FILTER_H_
#define SOBEL_FILTER_H_
#include <systemc>
using namespace sc_core;

#ifndef NATIVE_SYSTEMC
#include <cynw_p2p.h>
#endif

#include "filter_def.h"

class SobelFilter : public sc_module {
public:
  sc_in_clk i_clk;
  sc_in<bool> i_rst;
#ifndef NATIVE_SYSTEMC
  cynw_p2p<rgb_t>::in i_rgb;
  cynw_p2p<result_t>::out o_result;
#else
  sc_fifo_in<rgb_t> i_rgb;
  sc_fifo_out<result_t> o_result;
#endif

  SC_HAS_PROCESS(SobelFilter);
  SobelFilter(sc_module_name n);
  ~SobelFilter();

private:
  void do_filter();
  uint32_t left_rot(uint32_t value, int shift);
  uint32_t right_rot(uint32_t value, int shift);
  uint8_t PC_1_permutation(uint8_t *key);
  uint8_t PC_2_permutation(uint8_t *key, uint8_t *subkey);
  uint8_t IP_or_IP_inv(uint8_t *plaintext, const int *table);
  uint8_t Expansion(uint8_t *R, uint8_t *output);
  uint8_t S_box(uint8_t *xored_R);
  uint8_t P_perm_and_xored(uint8_t *s_boxed, uint8_t *plaintext);

};
#endif
