// ��ȣȭ���
#define ENC 1 
// ��ȣȭ���
#define DEC 0 

typedef unsigned char BYTE;

// 128��ƮAES �Ϻ�ȣȭ�������̽�
void AES128(BYTE *input, BYTE *output, BYTE *key, int mode);