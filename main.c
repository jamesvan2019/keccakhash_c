//
//  main.c

#include <stdio.h>
#include <string.h>
//#include <malloc.h>
#include <stdlib.h>
#include "sph_types.h"


#include "keccak.h"

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;



#define GOLDEN_COUNTER 3

uint32_t  endiandata[GOLDEN_COUNTER][29] = {
{
0x00000000,
0x465d4f58,
0x15b0ed40,
0xee2c3b35,
0x7203cfa6,
0x391e224f,
0xee85549c,
0x00040811,
0x00000000,
0x00000000,
0x5ce9c0f4,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x01d02306,
0x9eb8fd6a,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x55626ece,
0x0000006a,
},
{ 
0x00000000,
0x465d4f58,
0x15b0ed40,
0xee2c3b35,
0x7203cfa6,
0x391e224f,
0xee85549c,
0x00040811,
0x00000000,
0x00000000,
0x5ce9c0f4,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x01d02306,
0x9eb8fd6a,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x00221fe5,
0x0000006a,
},
{ 
0x00000000,
0x465d4f58,
0x15b0ed40,
0xee2c3b35,
0x7203cfa6,
0x391e224f,
0xee85549c,
0x00040811,
0x00000000,
0x00000000,
0x5ce9c0f4,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x01d02306,
0x9eb8fd6a,
0x8fb801ed,
0x7fc3fb9c,
0xa70c3cd8,
0x34eaeb75,
0x095586b5,
0x9d38e171,
0x026b6d6c,
0x559e816f,
0x0000006a,
}
};


static const uint32_t  sha3_hash_golden_data[GOLDEN_COUNTER][8] = {
{
0x329a69d6,
0xc9157162,
0xbe2d67db,
0x0df9aa71,
0x4812f94a,
0xcf50d30a,
0x3d3223c7,
0x8e14129a,
},
{
0xae02c080,
0xb38a9ad1,
0x507e7297,
0x3af3b1b2,
0x553c7096,
0x36c16df3,
0x16c102ad,
0x4f6a23a0,
},
{
0x38997d59,
0x13d87560,
0xfe72def4,
0x2b92e0f8,
0x9f60808d,
0xf42079b9,
0x683438f7,
0xd43b482c,
},

};



void sha3_test(void)
{
	uint32_t  hash32[8];
	int i;
	for (i = 0; i < GOLDEN_COUNTER; i++)
	{

		keccakhash(hash32,endiandata[i]);

		if (memcmp(hash32, sha3_hash_golden_data[i], 32) != 0)
		{
			printf("sha3 output data check failed!\n");
			for(int j=0;j<8;j++)
			{
				printf("0x%08x,\n",hash32[j]);
			}
		}
		else
		{
			printf("sha3 output data check success!\n");
		}
	}
}



int main(int argc, const char * argv[])
{

	sha3_test();
	uint8_t  hash32[32];
	char s[113] = "helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhel";
	keccakhash(hash32,s);
	printf("input 113 bytes header:%s\nkeccakhash result:",s);
	for(int j=0;j<32;j++)
    {
    	printf("%02x",hash32[j]);
    }
    printf("\n");
	return 0;
}
