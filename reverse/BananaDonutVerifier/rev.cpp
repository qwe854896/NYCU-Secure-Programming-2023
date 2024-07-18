#include <cstdio>
#include <cstring>
#include <cmath>
#include <unistd.h>
#include <iostream>

typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned char bb;

int main(int a1, char **a2, char **a3)
{
  char s[1760];
  float v20[1760];
  long long input[129];
  int v22;
  int v23;
  int v24;
  int v25;
  int v26;
  float v27;
  float v28;
  float v29;
  float v30;
  float v31;
  float v32;
  float v33;
  float v34;
  float v35;
  float v36;
  float v37;
  int v38;
  int v39;
  int v40;
  unsigned long long i;
  unsigned long long v42;
  int m;
  float j;
  float k;
  float v46;
  float v47;
  float v13;
  float v14;

  v47 = 0.0;
  v46 = 0.0;
  v42 = 0LL;
  memset(input, 0, 1024);
//   printf("Dount Verifier\nInput: ");
//   scanf("%1023s", (char *)input);
//   printf("\x1B[2J");
  for (i = 0LL; i <= 499; ++i)
  {
    memset(s, 32, sizeof(s));
    memset(v20, 0, sizeof(v20));
    for (j = 0.0; j < 6.28; j = v14)
    {
      v40 = 0;
      for (k = 0.0; k < 6.28; k = v13)
      {
        v37 = sinf(k);
        v36 = cosf(j);
        v35 = sinf(v47);
        v34 = sinf(j);
        v33 = cosf(v47);
        v32 = v36 + 2.0;
        v31 = 1.0 / ((v37 * (v36 + 2.0) * v35) + (v34 * v33) + 5.0);
        v30 = cosf(k);
        v29 = cosf(v46);
        v28 = sinf(v46);
        v27 = (v37 * v32 * v33) - (v34 * v35);
        v26 = (int)((v31 * 30.0) * ((v30 * v32 * v29) - (v27 * v28)) + 40.0);
        v25 = (int)((v31 * 15.0) * (v27 * v29 + (v30 * v32 * v28)) + 12.0);
        v24 = 80 * v25 + v26;
        v23 = (int)(8.0 * ((v34 * v35) - (v37 * v36 * v33) * v29 - (v34 * v33) - (v30 * v36 * v28)));
        if (v25 <= 21 && v25 > 0 && v26 > 0 && v26 <= 79 && v31 > v20[v24])
        {
          v20[v24] = v31;
          if (v23 < 0)
            v23 = 0;
          s[v24] = " .-:=+*#%@"[v23];
        }
        if (v40 == 30 && v42 <= 0x3FF)
        {
          v22 = v24 ^ v23 ^ (v26 + v25);
          std::cout << (long)(int)(uint)(bb)v22 << std::endl;
          *((char *)input + v42) ^= (unsigned char)v24 ^ v23 ^ (v26 + v25);
          v42++;
        }
        ++v40;
        v13 = k + 0.02;
      }
      v14 = j + 0.07000000000000001;
    }
    // printf("\x1B[H");
    for (m = 0; m <= 1760; ++m)
    {
    //   if (m % 80)
    //     putchar(s[m]);
    //   else
    //     putchar(10);
      v47 += 0.00004;
      v46 += 0.00002;
    }
    // usleep(0x7530u);
  }
//   v39 = sub_1A05(input, 1024LL);
//   v38 = sub_1A05(off_6050, 1024LL);
//   if (v39 == v38)
//     puts("Donut likes your input!! :D");
//   else
//     puts("Donut Reject You!! :(");
//   puts("No matter donut accept you or not. Here's a bananacat for you");
//   puts(asc_24B0);
//   puts(asc_2520);
//   puts(asc_2598);
//   puts(asc_2610);
//   puts(asc_2690);
//   puts(asc_2708);
//   puts(asc_2788);
//   puts(asc_2808);
//   puts(asc_2890);
//   puts(asc_2918);
//   puts(asc_29A8);
//   puts(asc_2A40);
//   puts(asc_2AD8);
//   puts(asc_2B78);
//   puts(asc_2C18);
//   puts(asc_2CB8);
//   puts(asc_2D58);
//   puts(asc_2E00);
//   puts(asc_2EA8);
//   puts(asc_2F50);
//   puts(asc_2FF8);
//   puts(asc_30A0);
//   puts(asc_3148);
//   puts(asc_31F0);
//   puts(asc_3298);
//   puts(asc_3340);
//   puts(asc_33E8);
//   puts(asc_3488);
//   puts(asc_3528);
//   puts(asc_35C8);
//   puts(asc_3668);
//   puts(asc_3708);
//   puts(asc_37B0);
//   puts(asc_3860);
//   puts(asc_3918);
//   puts(asc_39D0);
//   puts(asc_3A88);
//   puts(asc_3B28);
//   puts(asc_3BC0);
//   puts(asc_3C50);
//   puts(asc_3CE8);
//   puts(asc_3D78);
//   puts(asc_3E08);
//   puts(asc_3EA0);
//   puts(asc_3F18);
  return 0LL;
}
