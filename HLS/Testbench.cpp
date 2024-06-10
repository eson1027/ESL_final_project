#include <cstdio>
#include <cstdlib>
#include <bitset>
using namespace std;

#include "Testbench.h"

const uint8_t test_plaintext[8] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36};
const uint8_t test_key[8] = {0xAA, 0xBB, 0x09, 0x18, 0x27, 0x36, 0xCC, 0xDD};
// const uint8_t test_plaintext[8] = {0xC0, 0xB7, 0xA8, 0xD0, 0x5F, 0x3A, 0x82, 0x9C};


// static uint8_t test_ciphertext[8] = {0xCD, 0x13, 0x25, 0x36, 0x12, 0x34, 0x56, 0xAB};
// static uint8_t test_plaintext[8] = {0x8C, 0x1D, 0x7E, 0xCF, 0x96, 0x2D, 0x6D, 0xB1};


Testbench::Testbench(sc_module_name n) : sc_module(n)
{
	SC_THREAD(feed_rgb);
	sensitive << i_clk.pos();
	dont_initialize();
	SC_THREAD(fetch_result);
	sensitive << i_clk.pos();
	dont_initialize();
}

Testbench::~Testbench()
{
	// cout<< "Max txn time = " << max_txn_time << endl;
	// cout<< "Min txn time = " << min_txn_time << endl;
	// cout<< "Avg txn time = " << total_txn_time/n_txn << endl;
	cout << "Total run time = " << total_run_time << endl;
}

constexpr int_fast16_t LATENCY = 1;

void Testbench::feed_rgb()
{
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    uint8_t key[8];
	n_txn = 0;
	max_txn_time = SC_ZERO_TIME;
	min_txn_time = SC_ZERO_TIME;
	total_txn_time = SC_ZERO_TIME;

#ifndef NATIVE_SYSTEMC
	o_rgb.reset();
#endif
	o_rst.write(false);
	wait(5);
	o_rst.write(true);
	wait(1);
	total_start_time = sc_time_stamp();
	for (int_fast16_t i = 0; i != 8; ++i)
	{
		plaintext[i] = test_plaintext[i];
		key[i] = test_key[i];

#ifndef NATIVE_SYSTEMC
				o_rgb.put(plaintext[i]);
				wait(LATENCY*1);// additional
				// std::cout << std::hex << static_cast<int>(plaintext[i]) << " ";
				o_rgb.put(key[i]);
				wait(LATENCY*1);// additional
#else
				o_rgb.write(plaintext[i]);
				wait(LATENCY*1);// additional
				o_rgb.write(key[i]);
				wait(LATENCY*1);// additional
#endif

	}
}




void Testbench::fetch_result()
{
	int_fast16_t ciphertext[8];
#ifndef NATIVE_SYSTEMC
	i_result.reset();
#endif
	wait(5);
	wait(1);

		// std::cout << y << std::endl;
		for (int_fast16_t i = 0; i != 8; ++i)
		{
#ifndef NATIVE_SYSTEMC
			ciphertext[i] = i_result.get();
#else
			ciphertext[i] = i_result.read();
#endif

		}

		for (int_fast16_t i = 0; i != 8; ++i){
			
			// std::cout <<  bitset < 8 >(ciphertext[i] )<< endl;
			std::cout << std::hex << uint(ciphertext[i])<< endl;
		}
		std::cout << endl;


	total_run_time = sc_time_stamp() - total_start_time;
	sc_stop();
}
