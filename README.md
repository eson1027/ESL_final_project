# Final_project
- In this homework, you should download
```shell
git clone https://gitlab.larc-nthu.net/ee6470_TA/sobel_riscv_vp.git
git clone https://github.com/eson1027/ESL_HW4
```
## 1.** (50 pt) Implement HLS accelerator PEs**
```shell
cd HLS
cd status
make sim_V_BASIC
```



## 2. ** (50 pt) Implement multiple accelerator PEs with a multi-core riscv-vp platform**

- Replace "RISCV\basic-acc" file in "riscv-vp\vp\src\platform" and "RISCV\basic-sobel" file in "riscv-vp\sw"
```shell
cd $EE6470 && cd riscv-vp/vp/build && rm -r CMakeCache.txt && make install
cd $EE6470 && cd riscv-vp/sw && cd basic-sobel && make && make sim
```
