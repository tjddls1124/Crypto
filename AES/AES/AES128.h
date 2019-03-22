// 암호화모드
#define ENC 1 
// 복호화모드
#define DEC 0 

typedef unsigned char BYTE;

// 128비트AES 암복호화인터페이스
void AES128(BYTE *input, BYTE *output, BYTE *key, int mode);