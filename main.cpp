#include <sys/mman.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>

static std::vector<uint8_t> before = {
        0x55,               // push     rbp
        0x48, 0x89, 0xe5,   // mov      rbp, rsp
        0x50,               // push     rax
};

static std::vector<uint8_t> after = {
        0x58,               // pop      rax
        0x5d,               // pop      rbp
        0xc3                // ret
};


static std::vector<uint8_t> initializeRax = {
        0x48, 0xc7, 0xc0    // mov      rax, ?
};


std::vector<uint8_t> getBytes(uint32_t value) {
    std::vector<uint8_t> result(4, 0);
    result[3] = (value >> 24) & 0xFF;
    result[2] = (value >> 16) & 0xFF;
    result[1] = (value >> 8) & 0xFF;
    result[0] = value & 0xFF;
    return result;
}


// jmp   .loop
//
// .loop:
//
//              cmp         rax, 0
//              je          done
//              push        rbx
//              mov         rbx, 10
//              push        rdx
//              xor         rdx, rdx        we divide number rdx:rax, res in rax
//              idiv        rbx             remainder in rdx
//              add         rdx, '0'        to get char representation of a digit in rdx
//              push        rsi
//              push        rax
//              push        rdx
//              mov         rax, 1          sys_write syscall
//              mov         rsi, rsp        data address
//              push        rdi
//              mov         rdi, 1          fd (stdout)
//              mov         rdx, 1          data size
//              syscall
//
//              pop rdi
//              pop rdx
//              pop rax
//              pop rsi
//              pop rdx
//              pop rbx
//              jmp .loop
//
//  done:
std::vector<uint8_t> writeReversedNumber = {
        0xeb, 0x00, 0x48, 0x83, 0xf8, 0x00,
        0x74, 0x39, 0x53, 0x48, 0xc7, 0xc3,
        0x0a, 0x00, 0x00, 0x00, 0x52, 0x48,
        0x31, 0xd2, 0x48, 0xf7, 0xfb, 0x48,
        0x83, 0xc2, 0x30, 0x56, 0x50, 0x52,
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00,
        0x00, 0x48, 0x89, 0xe6, 0x57, 0x48,
        0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
        0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00,
        0x00, 0x0f, 0x05, 0x5f, 0x5a, 0x58,
        0x5e, 0x5a, 0x5b, 0xeb, 0xc1
 };


static const size_t CODE_SIZE = before.size() + initializeRax.size() + 4 + writeReversedNumber.size() + after.size();

std::vector<uint8_t> getCode(uint32_t raxValue) {
    std::vector<uint8_t> code;
    code.reserve(CODE_SIZE);
    code.insert(code.end(), before.begin(), before.end());
    code.insert(code.end(), initializeRax.begin(), initializeRax.end());
    auto rax = getBytes(raxValue);
    code.insert(code.end(), rax.begin(), rax.end());
    code.insert(code.end(), writeReversedNumber.begin(), writeReversedNumber.end());
    code.insert(code.end(), after.begin(), after.end());

    return code;
}


int main() {
    uint32_t arg;

    std::cout << "Hi, I'll reverse all uint32_t numbers you give me until 666 is passed ¯\\_(ツ)_/¯" << std::endl;

    while (std::cin >> arg) {
        if (arg == 666) {
            break;
        }

        auto code = getCode(arg);

        void *ptr = mmap(nullptr, CODE_SIZE, PROT_WRITE | PROT_READ,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED) {
            perror("Mapping failed");
            return 0;
        }
        memcpy(ptr, code.data(), code.size());
        if (mprotect(ptr, CODE_SIZE, PROT_EXEC | PROT_READ) == -1) {
            perror("Changing protection failed");
        } else {
            ((void (*)()) ptr) ();
        }
        if (munmap(ptr, CODE_SIZE) == -1) {
            perror("Memory freeing failed");
            return 0;
        }
        std::cout << std::endl;
    }
}