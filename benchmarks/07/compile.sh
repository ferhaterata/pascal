# https://gcc.gnu.org/onlinedocs/gcc-4.3.2/gcc/ARM-Options.html
arm-none-eabi-gcc -Wall -ggdb -mbig-endian -O0 -mcpu=cortex-m4 -march=armv7e-m int32_minmax.c -c -no-pie
# arm-none-eabi-gcc -Wall -ggdb -mlittle-endian -O0 -mcpu=cortex-m4 -march=armv7e-m int32_minmax.c -c -no-pie