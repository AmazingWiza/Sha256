/*
 *  This program implements the sha256 algorithm according to the 
 *  FIPS 180-2 standard 
 *  Author: Josh Germain
 */
#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

// 4. FUNCTIONS AND CONSTANTS *******************************************************************************
std::array<uint32_t, 64> Konstant = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t lsig0(uint32_t num) {
  return (((num >> 7) | (num << (32 - 7))) ^
          ((num >> 18) | (num << (32 - 18))) ^ (num >> 3));
}
uint32_t lsig1(uint32_t num) {
  return (((num >> 17) | (num << (32 - 17))) ^
          ((num >> 19) | (num << (32 - 19))) ^ (num >> 10));
}
uint32_t usig0(uint32_t num) {
  return (((num >> 2) | (num << (32 - 2))) ^
          ((num >> 13) | (num << (32 - 13))) ^
          ((num >> 22) | (num << (32 - 22))));
}
uint32_t usig1(uint32_t num) {
  return (((num >> 6) | (num << (32 - 6))) ^
          ((num >> 11) | (num << (32 - 11))) ^
          ((num >> 25) | (num << (32 - 25))));
}
uint32_t choice(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}
uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

// 5. PREPROCESSING *****************************************************************************************
std::vector<uint32_t> strToHash(std::string str) {
  std::vector<uint8_t> bytes;
  std::vector<uint32_t> hash;
  for (int i = 0; i < str.size(); i++) {
    bytes.push_back(uint8_t(str[i]));
  }
  bytes.push_back(0x80);
  int i = 0;
  while (i + 3 < bytes.size()) {
    uint32_t curr = 0;
    curr += bytes[i] << (3) * 8;
    curr += bytes[i + 1] << (2) * 8;
    curr += bytes[i + 2] << (1) * 8;
    curr += bytes[i + 3] << (0) * 8;
    hash.push_back(curr);
    i += 4;
  }
  uint32_t curr = 0;
  for (int b = 3; i < bytes.size(); b--) {
    curr += bytes[i] << b * 8;
    i++;
  }
  hash.push_back(curr);

  uint64_t size = str.size() * 8;
  while (((hash.size() + 2) % 16) != 0) {
    hash.push_back(0);
  }
  hash.push_back(size >> 32 & 0xFFFFFFFF);
  hash.push_back(size & 0xFFFFFFFF);
  return hash;
}
std::vector<uint32_t> hexToHash(std::string hex) {
  std::map<char, int> hexMap{
      {'0', 0},  {'1', 1},  {'2', 2},  {'3', 3},  {'4', 4},  {'5', 5},
      {'6', 6},  {'7', 7},  {'8', 8},  {'9', 9},  {'a', 10}, {'b', 11},
      {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15},
  };
  std::vector<uint32_t> hash;
  uint32_t i, curr;
  /*
   *
   *   The following if statment is not defined in FIPS 180-2
   *   It's added to match the results of other implementations of Sha256
   *
   */
  if (hex.size() % 2 != 0) {
    std::string zero = "0";
    hex = zero.append(hex);
  }

  uint64_t size = hex.size() * 4;
  hex.append("8");

  i = 0;
  while (i + 7 < hex.size()) {
    curr = 0;
    curr += hexMap[hex[i]] << (7) * 4;
    curr += hexMap[hex[i + 1]] << (6) * 4;
    curr += hexMap[hex[i + 2]] << (5) * 4;
    curr += hexMap[hex[i + 3]] << (4) * 4;
    curr += hexMap[hex[i + 4]] << (3) * 4;
    curr += hexMap[hex[i + 5]] << (2) * 4;
    curr += hexMap[hex[i + 6]] << (1) * 4;
    curr += hexMap[hex[i + 7]] << (0) * 4;
    hash.push_back(curr);
    i += 8;
  }
  curr = 0;
  int b = 7;
  while (i < hex.size()) {
    curr += hexMap[hex[i]] << b * 4;
    i++;
    b--;
  }
  hash.push_back(curr);

  while (((hash.size() + 2) % 16) != 0) {
    hash.push_back(0);
  }
  hash.push_back(size >> 32 & 0xFFFFFFFF);
  hash.push_back(size & 0xFFFFFFFF);
  return hash;
}
std::array<uint32_t, 8> InitHash = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                    0xa54ff53a, 0x510e527f, 0x9b05688c,
                                    0x1f83d9ab, 0x5be0cd19};

// 6. SECURE HASH ALGORITHMS ********************************************************************************
std::array<uint32_t, 64> MakeWords(uint32_t messageBlock[]) {
  std::array<uint32_t, 64> w;
  for (int i = 0; i < 16; i++) {
    w[i] = messageBlock[i];
  }
  for (int i = 16; i < 64; i++) {
    w[i] = lsig1(w[i - 2]) + w[i - 7] + lsig0(w[i - 15]) + w[i - 16];
  }
  return w;
}
std::array<uint32_t, 8> sha256(std::vector<uint32_t> hash) {
  for (int n = 0; n < hash.size() / 16; n++) {
    uint32_t messageBlock[16];
    for (int i = 0; i < 16; i++) {
      messageBlock[i] = hash[n * 16 + i];
    }
    std::array<uint32_t, 64> words = MakeWords(messageBlock);
    uint32_t a = InitHash[0];
    uint32_t b = InitHash[1];
    uint32_t c = InitHash[2];
    uint32_t d = InitHash[3];
    uint32_t e = InitHash[4];
    uint32_t f = InitHash[5];
    uint32_t g = InitHash[6];
    uint32_t h = InitHash[7];
    for (int t = 0; t < 64; t++) {
      uint32_t T1 = h + usig1(e) + choice(e, f, g) + Konstant[t] + words[t];
      uint32_t T2 = usig0(a) + majority(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }
    InitHash[0] += a;
    InitHash[1] += b;
    InitHash[2] += c;
    InitHash[3] += d;
    InitHash[4] += e;
    InitHash[5] += f;
    InitHash[6] += g;
    InitHash[7] += h;
  }

  return InitHash;
}

// Main *****************************************************************************************************
int main() {
  std::cout << "Enter string or hex number starting with 0x: ";
  std::string prehash;
  std::vector<uint32_t> hash;
  std::cin >> prehash;
  if (prehash.size() > 2 && prehash[0] == '0' &&
      (prehash[1] == 'x' || prehash[1] == 'X')) {
    hash = hexToHash(prehash.substr(2));
  } else {
    hash = strToHash(prehash);
  }

  std::array<uint32_t, 8> res = sha256(hash);
  for (int i = 0; i < 8; i++) {
    std::cout << std::hex << res[i] << " ";
  }
  std::cout << std::endl;
  return 0;
}
