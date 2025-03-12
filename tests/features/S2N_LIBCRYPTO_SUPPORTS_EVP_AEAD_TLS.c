/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <openssl/aead.h>

int main()
{
    EVP_AEAD_CTX evp_aead_ctx = { 0 };
    EVP_AEAD_CTX_zero(&evp_aead_ctx);
    EVP_aead_aes_256_gcm_tls13();
    EVP_aead_aes_128_gcm_tls13();
    EVP_AEAD_CTX_free(&evp_aead_ctx);
    return 0;
}
