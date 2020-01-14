// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
/// Shared test cases.

#pragma once

// Put in anonymous namespace to allow be include in multiple files
// but also make iteration over test cases easy with range-based for loop_dag_fnv_128.
namespace
{
struct hash_test_case
{
    int block_number;
    const char* header_hash_hex;
    const char* final_hash_hex;
};

hash_test_case hash_test_cases[] = {
    {
        1057863,
        "2a8de2adf8424242429af77358250bf42424242908bf04ba94a6e8c3ba4242424287775564a41d269a05e4ce2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce42424242",
        "4edc8f39f37ae4745c0bf0effd9996ab3f8511e1eb2fa7bda6a564f4c94cb0bc",
    },
    {
        1057864,
        "acf48b00bda6d3a01a2f60d53f5a1257b746ed4b731a5786b828a713bfc38d314287775564a41d269a05e4ce2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce42424242",
        "f649189a6d4065ac36391258d36c7b75cd2118240515afbdfb9494862d28b826",
    },
    {
        4750000,
        "000cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe4287775564a41d269a05e4ce2a8de2adf89af77358250bf908bf04ba94a6e8c3ba87775564a41d269a05e4ce42424242",
        "c85c86dfdcca8132514e4ac7e8079f0aaafbcfd0011300e28e0dde483bd106ed",
    },
    /*
    {
        2,
        "000cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",
        "307692cf71b12f6d",
        "d5b9d62b63cc5c5fdcd727dd7148ea6b9ba97a4bcb4a7c7a7a50269792bd4d11",
        "acf48b00bda6d3a01a2f60d53f5a1257b746ed4b731a5786b828a713bfc38d31",
    },
    {
        30001,
        "100cbec5e5ef82991290d0d93d758f19082e71f234cf479192a8b94df6da6bfe",
        "307692cf71b12f6d",
        "d1a32e1f7219e7bf3b09ed3eb7dc2439ed8ce203733e485eebf50bd1e3335a65",
        "9050cad229ea6c21c672214e9b99c5fde71f0d2acfd52c1e068f0a55dff19d00",
    },
    {
        2683077,
        "0313d03c5ed78694c90ecb3d04190b82d5b222c75ba4cab83383dde4d11ed512",
        "8c5eaec000788d41",
        "93e85c97b34ccd8091e09ddb513fdc9e680fa8898d4a0737205e60af710a3dcb",
        "00000000000204882a6213f68fe89bc368df25c1ad999f82532a7433e99bc48e",
    },
    {
        5000000,
        "bc544c2baba832600013bd5d1983f592e9557d04b0fb5ef7a100434a5fc8d52a",
        "4617a20003ba3f25",
        "94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea",
        "0000000000001a5b18ae31b7417b7c045bc6dd78cc3b694c4bebfaefef6b3c56",
    },
    {
        5000001,
        "2cd14041cfc3bd13064cfd58e26c0bddf1e97a4202c4b8076444a7cd4515f8c3",
        "1af47f2007922384",
        "46cb1268ac6b218eb01b9bd46f1533561d085620c9bfc23eadb8ab106f84b2d8",
        "0000000000000a4230cfc483a3f739a5101192c3d4f9c8314f4508be24c28257",
    },
    {
        5000002,
        "9e79bced19062baf7c47e516ad3a1bd779222404d05b4205def30a13c7d87b5b",
        "c9a044201dd998f2",
        "028a19d6dcf0975972285f71a23fe3a468886ad24cc63f969158d427556d6bb5",
        "0000000000000eec80fbc4c472507b6c212c4f216043318f3fb3e696a0e80b06",
    },
    {
        5306861,
        "53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f",
        "d337f82001e992c5",
        "26c64f063dac85ae3585526b446be6754faf044876aa3e20f770bea567e04d1d",
        "00000000000003f1554d8071ff0903268fcb70f30f4af3bf7ec7dc69cdf509f3",
    },
    {
        8850000,
        "12bc33ef14d42703453f31e51ba6106920eb41ceb182656d9b7dcd892b08cf7d",
        "fe0f929a76aa9dc8",
        "cb9b26b842c522f850454549b95ffb69830109bc79fb4a048b7a8dab0b1a1a51",
        "000000008b7058a73979781a86892d14f244ca1428b155e31a6c48dacc3beafe",
    },
    
    {
        8850000,
        "2e530ff7e831a842fb452e791df1da80e4f276207fcc5158d525dec3fed12e84",
        "46681ae4af142c08",
        "5812ea4871769cbc6f42937316807a7fce6d9dc9bd3b61f00fd71ada49f95c80",
        "00000001010f4576208fa4f7a3df5445d1dfb08e84705e26f9ba209f52ea136d",
    },
    {
        8850000,
        "daa227ad7c5affa90204a5f84469232cabc896eef64c4bc4d14bb3b57efcb04a",
        "dabbb48f8ce664b0",
        "696c905b2a7f4b926dd19e50c131b3730a2e05a75eec5b551ebea9066fe662c1",
        "00000000cd9db71459deb9041a295b304dfca6684b2ff9434aa4b0ceea8ac08f",
    },
    {
        8910000,
        "2a98ab95bc123611fa5311490f013022e1919ca5e15f28b82cc5da31e3144783",
        "cbe877c67d3e2121",
        "129948aeb9dd004106ffb1d2b63e26a6e0ff8e33d37cd511dd7b3948d9b335c3",
        "",
    },*/
};
}  // namespace