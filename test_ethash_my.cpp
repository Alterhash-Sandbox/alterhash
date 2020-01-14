#include "endianness.hpp"
#include "ethash-internal.hpp"
#include "ethash.hpp"
#include "keccak.hpp"

#include "helpers.hpp"
#include "test_cases.hpp"

//#include <gtest/gtest.h>

#include <array>
#include <future>
#include <string>
#include <stdio.h>

#include <bits/stdc++.h>

//#define POINTER_MEM_SIZE 27721721 //8388593 (0 epoch)
//#define NONCE_CNT 1000000 //1000000

int main()
{
    using namespace ethash;
    int test = 0;
    char * final_hash_str = new char [32];

    /*int *pointer_acc {new int[POINTER_MEM_SIZE]{} };
    printf("Start: Initializing pointer memory \n");
    for(int k = 0; k < POINTER_MEM_SIZE; k++) {
      pointer_acc[k] = 0;
    }
    printf("Done: Initializing pointer memory \n");
    */
    for (const auto& t : hash_test_cases)
        {
            test++;
            //printf("header_hash == %s\n", to_hex(header_hash).c_str());
            //printf("x16r_algo   == %d\n", x16r_algo);


            //const int full_dataset_num_items = calculate_full_dataset_num_items(epoch_number);
            //const uint64_t full_dataset_size = get_full_dataset_size(full_dataset_num_items);




        //if (context == nullptr)
        //printf ("Test case No %d Context generated successfully\n", test);
        //else 
        //{
        //    printf("ERROR: Test case No %d Context\n", test);
        //    return 0;
        //}
        //if(full_dataset_size == 0)
            //printf ("Test case No %d Dataset is correct\n",test);
        //else
        //{
        //    printf("Test case No %d Dataset is incorrrect\n",test);
        //    return 0;
        //}
        hash(t.header_hash_hex, t.block_number, final_hash_str);
       
        if (!strncmp(final_hash_str, t.final_hash_hex, 32))
            printf("Test case No %d Final hashes match\n",test);
        else
        {
            printf("ERROR: Test case No %d Hash %s didn't match to Reference: %s\n", test, final_hash_str, t.final_hash_hex);
        }
        //if (to_hex(r.mix_hash) == t.mix_hash_hex)
        //    printf("Test case No %d Mix hashes match\n",test);
        //else
        //{
        //    printf("ERROR: Test case No %d Mix hash %s didn't match to Reference: %s\n",test,to_hex(r.mix_hash).c_str(),t.mix_hash_hex);
        //}
        
        
        }
    return 0;
}
/*        std::sort(pointer_acc, pointer_acc + POINTER_MEM_SIZE, std::greater<int>() );
        printf("Maximum repeating request count: %d \n",pointer_acc[0]);
        
        int repnum[4300];
        
        for(int k = 0; k <4300; k++) {
           repnum[k] = 0;
        }

        for( long int k=0; k < POINTER_MEM_SIZE; k++) {
            repnum[pointer_acc[k]]++; //
            if(pointer_acc[k] == 0) {
               break;
            }
        }
        for(int k = 4299; k >1; k--) {
            if (repnum[k] != 0){
                printf("repitition count for k=%d: %d \n", k ,repnum[k]);
            }
        }


        
        }
    return 0;
}*/
