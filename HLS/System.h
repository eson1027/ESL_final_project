#ifndef SYSTEM_H_
#define SYSTEM_H_
#include <systemc>
using namespace sc_core;

#include "Testbench.h"
#ifndef NATIVE_SYSTEMC
#include "SobelFilter_wrap.h"
#else
#include "SobelFilter.h"
#endif

class System: public sc_module
{
public:
	SC_HAS_PROCESS( System );
	System( sc_module_name n );
	~System();
private:
  Testbench tb;
#ifndef NATIVE_SYSTEMC
	SobelFilter_wrapper sobel_filter;
#else
	SobelFilter sobel_filter;
#endif
	sc_clock clk;
	sc_signal<bool> rst;
#ifndef NATIVE_SYSTEMC
	cynw_p2p< rgb_t > rgb;
	cynw_p2p< result_t > result;
#else
	sc_fifo< rgb_t > rgb;
	sc_fifo< result_t > result;
#endif

};
#endif
