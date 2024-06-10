#ifndef SOBEL_FILTER_H_
#define SOBEL_FILTER_H_
#include <cmath>
#include <iomanip>
#include <systemc>
using namespace sc_core;

#include <tlm_utils/simple_target_socket.h>

#include <tlm>

#include "filter_def.h"

struct SobelFilter : public sc_module {
	tlm_utils::simple_target_socket<SobelFilter> tsock;

	sc_fifo<unsigned char> i_r;
	sc_fifo<unsigned char> i_g;
	// sc_fifo<unsigned char> i_b;
	sc_fifo<uint64_t> o_result;

	SC_HAS_PROCESS(SobelFilter);

	SobelFilter(sc_module_name n) : sc_module(n), tsock("t_skt"), base_offset(0) {
		tsock.register_b_transport(this, &SobelFilter::blocking_transport);
		SC_THREAD(do_filter);
	}

	~SobelFilter() {}

	unsigned int base_offset;

	uint32_t left_rot(uint32_t value, int shift) {
		if ((shift %= 28) == 0)
			return value;
		return ((value << shift) | (value >> (28 - shift))) & mask28bit;
	}  // 旋轉左半邊的28bit

	uint32_t right_rot(uint32_t value, int shift) {
		if ((shift %= 28) == 0)
			return value;
		return ((value >> shift) | (value << (28 - shift))) & mask28bit;
	}  // 旋轉右半邊的28bit

	uint8_t PC_1_permutation(uint8_t *key) {
		uint8_t res[8];
		for (int j = 0; j < 8; j++) {
			uint8_t temp = 0;
			for (int i = j * 7; i < (j + 1) * 7; i++) {
				int k_1 = (PC_1[i] >> 3);   // 前5 bit存到k_1
				int k_2 = PC_1[i] & 0b111;  // 後3 bit存到k_2
				if (key[k_1] & (1 << (8 - k_2))) {
					temp = (temp << 1) + 1;
				} else {
					temp = temp << 1;
				}
			}
			res[j] = temp;
		}
		memcpy(key, res, sizeof(uint8_t) * 8);
		return 0;
	}

	uint8_t PC_2_permutation(uint8_t *key, uint8_t *subkey) {
		uint8_t res[8];
		for (int j = 0; j < 8; j++) {
			uint8_t temp = 0;
			for (int i = j * 6; i < (j + 1) * 6; i++) {
				int k_1 = (PC_2[i] - 1) / 7;
				int k_2 = (PC_2[i] - 1) % 7;
				if (key[k_1] & (1 << (6 - k_2))) {
					temp = (temp << 1) + 1;
				} else {
					temp = temp << 1;
				}
			}
			res[j] = temp;
		}
		memcpy(subkey, res, sizeof(uint8_t) * 8);
		return 0;
	}

	uint8_t IP_or_IP_inv(uint8_t *plaintext, const int *table) {
		uint8_t res[8];
		for (int j = 0; j < 8; j++) {
			uint8_t temp = 0;
			for (int i = j * 8; i < (j + 1) * 8; i++) {
				int k_1 = (table[i] - 1) / 8;
				int k_2 = (table[i] - 1) % 8;
				if (plaintext[k_1] & (1 << (7 - k_2))) {
					temp = (temp << 1) + 1;
				} else {
					temp = temp << 1;
				}
			}
			res[j] = temp;
		}
		memcpy(plaintext, res, sizeof(uint8_t) * 8);
		return 0;
	}

	uint8_t Expansion(uint8_t *R, uint8_t *output) {
		uint8_t res[8];

		for (int j = 0; j < 8; j++) {
			uint8_t temp = 0;
			for (int i = j * 6; i < (j + 1) * 6; i++) {
				int k_1 = (E[i] - 1) / 8;
				int k_2 = (E[i] - 1) % 8;
				if (R[k_1] & (1 << (7 - k_2))) {
					temp = (temp << 1) + 1;
				} else {
					temp = temp << 1;
				}
			}
			res[j] = temp;
		}
		memcpy(output, res, sizeof(uint8_t) * 8);
		return 0;
	}

	uint8_t S_box(uint8_t *xored_R) {
		for (int i = 0; i < 8; i++) {
			int column = (xored_R[i] & 0b011110) >> 1;
			int row = ((xored_R[i] & 0b100000) >> 4) | (xored_R[i] & 0b000001);
			xored_R[i] = S[i][row][column];
		}
		return 0;
	}

	uint8_t P_perm_and_xored(uint8_t *s_boxed, uint8_t *plaintext) {
		uint8_t res[4];
		for (int j = 0; j < 4; j++) {
			uint8_t temp = 0;
			for (int i = j * 8; i < (j + 1) * 8; i++) {
				int k_1 = (P[i] - 1) / 4;
				int k_2 = (P[i] - 1) % 4;
				if (s_boxed[k_1] & (1 << (3 - k_2))) {
					temp = (temp << 1) + 1;
				} else {
					temp = temp << 1;
				}
			}
			res[j] = temp ^ plaintext[j];
		}
		memcpy(plaintext, res, sizeof(uint8_t) * 4);
		return 0;
	}

	void do_filter() {
		// std::cout << "k" << endl;
		{ wait(CLOCK_PERIOD, SC_NS); }

		uint8_t subkeys[16][8];
		uint8_t expansion[8];
		uint8_t ciphertext[8];
		uint8_t key[8];
		uint32_t temp1, temp2;
		for (uint_fast16_t i = 0; i < 8; i++) {
			ciphertext[i] = i_r.read();
			key[i] = i_g.read();
		}

		IP_or_IP_inv(ciphertext, IP);
		PC_1_permutation(key);

		for (int j = 0; j < 16; j++) {
			memset(subkeys[j], 0, sizeof(subkeys[j]));
			memset(&temp1, 0, sizeof(temp1));
			memset(&temp2, 0, sizeof(temp2));

			temp1 = (key[0] << 21) | (key[1] << 14) | (key[2] << 7) | key[3];
			temp2 = (key[4] << 21) | (key[5] << 14) | (key[6] << 7) | key[7];
			temp1 = left_rot(temp1, shift_table[j]);
			temp2 = left_rot(temp2, shift_table[j]);
			for (int i = 0; i < 4; i++) {
				key[3 - i] = temp1 & 0b1111111;
				key[7 - i] = temp2 & 0b1111111;
				temp1 = temp1 >> 7;
				temp2 = temp2 >> 7;
			}
			PC_2_permutation(key, subkeys[j]);
		}

		// 加密
		for (int j = 0; j < 16; j++) {
			Expansion(ciphertext + 4, expansion);
			for (int i = 0; i < 8; i++) {
				expansion[i] ^= subkeys[j][i];
			}
			S_box(expansion);
			P_perm_and_xored(expansion, ciphertext);

			if (j != 15) {
				for (int i = 0; i < 4; i++) {
					ciphertext[i] ^= ciphertext[4 + i];
					ciphertext[4 + i] ^= ciphertext[i];
					ciphertext[i] ^= ciphertext[4 + i];
				}
			}
		}

		// 解密
		// for (int j = 0; j < 16; j++) {
		//   Expansion(ciphertext + 4, expansion);
		//   for (int i = 0; i < 8; i++) {
		//     expansion[i] ^= subkeys[15 - j][i];
		//   }
		//   S_box(expansion);
		//   P_perm_and_xored(expansion, ciphertext);

		//   if (j != 15) {
		//     for (int i = 0; i < 4; i++) {
		//       ciphertext[i] ^= ciphertext[4 + i];
		//       ciphertext[4 + i] ^= ciphertext[i];
		//       ciphertext[i] ^= ciphertext[4 + i];
		//     }
		//   }
		// }
		IP_or_IP_inv(ciphertext, IP_inv);
		// for (uint_fast16_t i = 0; i < 8; i++) {
		// 	std::cout << std::hex << int(ciphertext[i]) << std::endl;
		// }
		sc_dt::sc_uint<64> total = 0;
		for (uint_fast16_t i = 0; i < 8; i++){
			total.range(8*(i+1)-1,8*(i)) = ciphertext[i];
		}
		// total.range(8*(0+1)-1,8*(0)) = ciphertext[0];
		// total.range(8*(1+1)-1,8*(1)) = ciphertext[1];
		// total.range(8*(2+1)-1,8*(2)) = ciphertext[2];
		// total.range(8*(3+1)-1,8*(3)) = ciphertext[3];
		// total.range(8*(4+1)-1,8*(4)) = ciphertext[4];
		// total.range(8*(5+1)-1,8*(5)) = ciphertext[5];
		// total.range(8*(6+1)-1,8*(6)) = ciphertext[6];
		// total.range(8*(7+1)-1,8*(7)) = ciphertext[7];
		wait(3190, SC_NS);
		o_result.write(total);
		
		
		
		// for (uint_fast16_t i = 0; i < 8; i++) {
		// 	o_result.write(ciphertext[i]);
		// }
	}
	void blocking_transport(tlm::tlm_generic_payload &payload, sc_core::sc_time &delay) {
		// delay += sc_time(10 * CLOCK_PERIOD, SC_NS);
		// wait(delay);
		// unsigned char *mask_ptr = payload.get_byte_enable_ptr();
		// auto len = payload.get_data_length();
		tlm::tlm_command cmd = payload.get_command();
		sc_dt::uint64 addr = payload.get_address();
		unsigned char *data_ptr = payload.get_data_ptr();

		addr -= base_offset;

		// cout << (int)data_ptr[0] << endl;
		// cout << (int)data_ptr[1] << endl;
		// cout << (int)data_ptr[2] << endl;
		word buffer;

		switch (cmd) {
			case tlm::TLM_READ_COMMAND: {
				// cout << "READ" << endl;
				// int k = o_result.num_available();
				switch (addr) {
					case SOBEL_FILTER_RESULT_ADDR: {
						delay += sc_time(18 * CLOCK_PERIOD, SC_NS);
						buffer.uint = o_result.read();

						// std::cout << int(k) << std::endl;
						break;
					}
					default: {
						std::cerr << "READ Error! SobelFilter::blocking_transport: address 0x" << std::setfill('0')
						          << std::setw(8) << std::hex << addr << std::dec << " is not valid" << std::endl;
					}
				}
				data_ptr[0] = 0xff;
				data_ptr[1] = buffer.uint & 0xff;
				// std::cout << "1 " << int(data_ptr[1]) << std::endl;
				data_ptr[2] = (buffer.uint >> 8) & 0xff ;
				// std::cout << "2 " << int(data_ptr[2]) << std::endl;
				data_ptr[3] = (buffer.uint >> 16) & 0xff ;
				// std::cout << "2 " << int(data_ptr[3]) << std::endl;
				data_ptr[4] = (buffer.uint >> 24) & 0xff ;
				// std::cout << "2 " << int(data_ptr[4]) << std::endl;
				data_ptr[5] = (buffer.uint >> 32) & 0xff ;
				// std::cout << "2 " << int(data_ptr[5]) << std::endl;
				data_ptr[6] = (buffer.uint >> 40) & 0xff ;
				// std::cout << "2 " << int(data_ptr[6]) << std::endl;
				data_ptr[7] = (buffer.uint >> 48) & 0xff ;
				// std::cout << "2 " << int(data_ptr[7]) << std::endl;
				data_ptr[8] = (buffer.uint >> 56) & 0xff ;
				// std::cout << "2 " << int(data_ptr[8]) << std::endl;
				data_ptr[9] = 0xff;
				// data_ptr[2] = 0xff;
				// data_ptr[3] = 0xff;
				// data_ptr[4] = 0xff;
				// data_ptr[5] = (buffer.uint >> 8) & 0xff ;
				// std::cout << "2 " << int(data_ptr[2]) << std::endl;
				// data_ptr[6] = 0xff;
				// data_ptr[7] = 0xff;
				// data_ptr[8] = 0xff;
				// data_ptr[9] = (buffer.uint >> 16) & 0xff;
				// std::cout << "3 " << int(data_ptr[3]) << std::endl;
				// data_ptr[10] = 0xff;
				// data_ptr[11] = 0xff;
				// data_ptr[12] = 0xff;
				// data_ptr[13] = (buffer.uint >> 32) & 0xff;
				// std::cout << "4 " << int(data_ptr[4]) << std::endl;
				// data_ptr[14] = 0xff;
				// data_ptr[15] = 0xff;
				// data_ptr[16] = 0xff;
				// data_ptr[17] = (buffer.uint >> 40) & 0xff;
				// std::cout << "5 " << int(data_ptr[5]) << std::endl;
				// data_ptr[18] = 0xff;
				// data_ptr[19] = 0xff;
				// data_ptr[20] = 0xff;
				// data_ptr[21] = (buffer.uint >> 48) & 0xff;
				// std::cout << "6 " << int(data_ptr[6]) << std::endl;
				// data_ptr[22] = 0xff;
				// data_ptr[23] = 0xff;
				// data_ptr[24] = 0xff;
				// data_ptr[25] = (buffer.uint >> 56) & 0xff;
				// std::cout << "7" << int(data_ptr[7]) << std::endl;
				// data_ptr[26] = 0xff;
				// data_ptr[27] = 0xff;
				// data_ptr[28] = 0xff;
				// data_ptr[29] = (buffer.uint >> 8) & 0xff;
				// std::cout << "8 " << int(data_ptr[8]) << std::endl;
				// data_ptr[30] = 0xff;
				// data_ptr[31] = 0xff;
				// data_ptr[0] = 0xff;
				// data_ptr[1] = buffer.uint;
				// data_ptr[2] = 0xff;
				// data_ptr[3] = 0xff;
				break;
			}
			case tlm::TLM_WRITE_COMMAND: {
				// cout << "WRITE" << endl;
				switch (addr) {
					case SOBEL_FILTER_R_ADDR: {
						// i_r.write(data_ptr[0]);
						// i_g.write(data_ptr[1]);
						i_r.write(data_ptr[0]);
						i_g.write(data_ptr[1]);
						i_r.write(data_ptr[4]);
						i_g.write(data_ptr[5]);
						i_r.write(data_ptr[8]);
						i_g.write(data_ptr[9]);
						i_r.write(data_ptr[12]);
						i_g.write(data_ptr[13]);
						i_r.write(data_ptr[16]);
						i_g.write(data_ptr[17]);
						i_r.write(data_ptr[20]);
						i_g.write(data_ptr[21]);
						i_r.write(data_ptr[24]);
						i_g.write(data_ptr[25]);
						i_r.write(data_ptr[28]);
						i_g.write(data_ptr[29]);
						// i_b.write(data_ptr[2]);
						break;
					}
					default: {
						std::cerr << "WRITE Error! SobelFilter::blocking_transport: address 0x" << std::setfill('0')
						          << std::setw(8) << std::hex << addr << std::dec << " is not valid" << std::endl;
					}
				}
				break;
				case tlm::TLM_IGNORE_COMMAND: {
					payload.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
					return;
				}
				default: {
					payload.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
					return;
				}
			}
		}
		payload.set_response_status(tlm::TLM_OK_RESPONSE);  // Always OK
	}
};
#endif
