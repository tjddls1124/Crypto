#include <stdio.h>
#include <stdlib.h>
#include "AES128.h"


#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define BLOCK_SIZE 16
#define col_size 4


BYTE R[] = { 0x02, 0x00, 0x00, 0x00 };

static BYTE sbox[256] = {
	// 0    1     2     3     4     5     6     7     8     9    a     b     c     d     e     f
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7	
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };// f


static BYTE inv_s_box[256] = {
	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };// f



BYTE aes_xtime(BYTE x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
BYTE aes_xtimes(BYTE x, int ts)
{
	while (ts-- > 0) {
		x = aes_xtime(x);
	}

	return x;
}

BYTE gfmult(BYTE a, BYTE b) { // GF(2^8) 곱

	BYTE p = 0, i = 0, top = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {//b의 마지막 bit가 1 이라면
			p ^= a; // p에 a를 XOR
		}

		top = a & 0x80; // a의 최상위 bit 
		a <<= 1;
		if (top) a ^= 0x1b; //최상위 bit 가 1 이면 top을 제외하고 modulo다항식 0000 0001 0001 1011	과 XOR
		b >>= 1;
	}

	return (BYTE)p;
}

void coef_mult(BYTE *a, BYTE *b, BYTE *d) {

	d[0] = gfmult(a[0], b[0]) ^ gfmult(a[3], b[1]) ^ gfmult(a[2], b[2]) ^ gfmult(a[1], b[3]);
	d[1] = gfmult(a[1], b[0]) ^ gfmult(a[0], b[1]) ^ gfmult(a[3], b[2]) ^ gfmult(a[2], b[3]);
	d[2] = gfmult(a[2], b[0]) ^ gfmult(a[1], b[1]) ^ gfmult(a[0], b[2]) ^ gfmult(a[3], b[3]);
	d[3] = gfmult(a[3], b[0]) ^ gfmult(a[2], b[1]) ^ gfmult(a[1], b[2]) ^ gfmult(a[0], b[3]);
}




BYTE *Rcon(BYTE i) {

	if (i == 1) {
		R[0] = 0x01; // x^(1-1) = x^0 = 1
	}
	else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i - 1 > 0) {
			R[0] = gfmult(R[0], 0x02);
			i--;
		}
	}

	return R;
}

/* 기타 필요한 함수 추가 선언 및 정의 */
void addByte(BYTE* a, BYTE* b, BYTE* d) {

	d[0] = a[0] ^ b[0];
	d[1] = a[1] ^ b[1];
	d[2] = a[2] ^ b[2];
	d[3] = a[3] ^ b[3];
}




/*  <키스케줄링 함수>
*
*  key         키스케줄링을 수행할 16바이트 키
*  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
*/

void rotate(BYTE *r) {
	BYTE temp;
	int i;
	temp = r[0];
	for (i = 0; i<3; i++) {
		r[i] = r[i + 1];
	}
	r[3] = temp;
}

void sub(BYTE *w) {
	int i;
	for (i = 0; i< 4; i++) {
		w[i] = sbox[w[i]];

	}
}

void expandKey(BYTE *key, BYTE *roundKey) {

	BYTE k[KEY_SIZE];
	for (int i = 0; i < KEY_SIZE; i++) {
		k[i] = key[i];
	}

	BYTE temp[KEY_SIZE / 4];
	int i;
	for (i = 0; i < KEY_SIZE; i++)
	{
		roundKey[i] = k[i];
	}

	for (int i = KEY_SIZE / 4; i < ROUNDKEY_SIZE / 4; i++) {
		temp[0] = roundKey[4 * i - 4];
		temp[1] = roundKey[4 * i - 3];
		temp[2] = roundKey[4 * i - 2];
		temp[3] = roundKey[4 * i - 1];

		if (i % 4 == 0) {
			rotate(temp);
			sub(temp);

			addByte(temp, Rcon(i / 4), temp);
		}

		roundKey[4 * i + 0] = roundKey[4 * (i - 4) + 0] ^ temp[0];
		roundKey[4 * i + 1] = roundKey[4 * (i - 4) + 1] ^ temp[1];
		roundKey[4 * i + 2] = roundKey[4 * (i - 4) + 2] ^ temp[2];
		roundKey[4 * i + 3] = roundKey[4 * (i - 4) + 3] ^ temp[3];
	}
}


/*  <SubBytes 함수>
*
*  block   SubBytes 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
*  mode    SubBytes 수행 모드
*/
BYTE* subBytes(BYTE *block, int mode) {



	switch (mode) {

	case ENC:

		/* 추가 구현 */
		for (int i = 0; i<BLOCK_SIZE; i++) {
			block[i] = sbox[block[i]];
		}


		break;

	case DEC:

		/* 추가 구현 */
		for (int i = 0; i<BLOCK_SIZE; i++) {
			block[i] = inv_s_box[block[i]];
		}

		break;

	default:
		fprintf(stderr, "Invalid mode!\n");
		exit(1);
	}

	return block;
}


/*  <ShiftRows 함수>
*
*  block   ShiftRows 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
*  mode    ShiftRows 수행 모드
*/

void shiftLeft(BYTE* block) { // 왼쪽으로 1칸이동
	BYTE temp;
	temp = block[0];
	for (BYTE i = 0; i < 3; i++) {

		block[4 * i] = block[4 * (i + 1)];
	}
	block[4 * 3] = temp;
}


BYTE* shiftRows(BYTE *block, int mode) {

	switch (mode) {

	case ENC:


		/*
		행 단위  shift 연산
		*/

		for (int i = 0; i < BLOCK_SIZE / 4; i++) {
			for (int j = 0; j < i; j++) {
				shiftLeft(block + i); //i번째 행을 i번 왼쪽으로 이동
			}


		}
		break;

	case DEC:

		for (int i = BLOCK_SIZE / 4; i > 0; i--) {
			for (int j = 0; j < i; j++) {
				shiftLeft(block + 4 - i); //i번째 행을 4-i번 왼쪽으로 이동
			}


		}

		break;

	default:
		fprintf(stderr, "Invalid mode!\n");
		exit(1);
	}

	return block;
}


/*  <MixColumns 함수>
*
*  block   MixColumns을 수행할 16바이트 블록. 수행 결과는 해당 배열에 바로 반영
*  mode    MixColumns의 수행 모드
*/

void mcol(BYTE* col) {
	BYTE t[4];
	for (int i = 0; i < col_size; i++) { //t is temp, temp에 copy
		t[i] = col[i];
	}
	col[0] = gfmult(0x02, t[0]) ^ gfmult(0x03, t[1]) ^ t[2] ^ t[3];
	col[1] = t[0] ^ gfmult(0x02, t[1]) ^ gfmult(0x03, t[2]) ^ t[3];
	col[2] = t[0] ^ t[1] ^ gfmult(t[2], 0x02) ^ gfmult(t[3], 0x03);
	col[3] = gfmult(0x03, t[0]) ^ t[1] ^ t[2] ^ gfmult(0x02, t[3]);

}

BYTE* prodMat(BYTE* matA, BYTE* matB) {
	BYTE mA[16], mB[16];
	for (int i = 0; i < 16; i++) {
		mA[i] = matA[i];
		mB[i] = matB[i];
	}

	BYTE result = 0x00;
	int i, j, k;
	BYTE rMat[16] = { 0, };
	for (k = 0; k< col_size; k++) {
		for (i = 0; i < col_size; i++) {
			for (j = 0; j< col_size; j++) {
				result = result ^ gfmult(mA[i*col_size + j], mB[col_size*k + j]);
			}
			rMat[4 * k + i] = result;
			result = 0x00;
		}
	}
	return rMat;


}


BYTE* mixColumns(BYTE *block, int mode) {

	BYTE mixMat[16] = { 2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2 };
	/* a(x) = {02} + {01}x + {01}x2 + {03}x3
	2 3 1 1
	1 2 3 1
	1 1 2 3
	3 1 1 2
	*/
	BYTE invMixMat[16] = { 14,11,13,9,9,14,11,13,13,9,14,11,11,13,9,14 };
	/* a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
	14 11 13 9
	9 14 11 13
	13 9 14 11
	11 13 9 14
	*/
	BYTE* tempMat;

	tempMat = (BYTE*)malloc(sizeof(BYTE) * 16);



	switch (mode) {

	case ENC:


		tempMat = prodMat(mixMat, block);
		for (int i = 0; i< BLOCK_SIZE; i++) {
			block[i] = tempMat[i];
		}



		break;

	case DEC:

		/* 추가 구현 */
		tempMat = prodMat(invMixMat, block);
		for (int i = 0; i< BLOCK_SIZE; i++) {
			block[i] = tempMat[i];
		}
		break;

	default:
		fprintf(stderr, "Invalid mode!\n");
		exit(1);
	}

	return block;
}


/*  <AddRoundKey 함수>
*
*  block   AddRoundKey를 수행할 16바이트 블록. 수행 결과는 해당 배열에 반영
*  rKey    AddRoundKey를 수행할 16바이트 라운드키
*/
BYTE* addRoundKey(BYTE *block, BYTE *rKey) {



	for (int i = 0; i <BLOCK_SIZE; i++) {
		block[i] = block[i] ^ rKey[i];
	}


	return block;
}




/*  <128비트 AES 암복호화 함수>
*
*  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
*
*  [ENC 모드]
*  input   평문 바이트 배열
*  output  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
*  key     128비트 암호키 (16바이트)
*
*  [DEC 모드]
*  input   암호문 바이트 배열
*  output  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
*  key     128비트 암호키 (16바이트)
*/
void AES128(BYTE *input, BYTE *output, BYTE *key, int mode) {

	BYTE temp[16];
	for (int i = 0; i < BLOCK_SIZE; i++) {
		temp[i] = input[i];
	}
	BYTE *roundKey;
	roundKey = (BYTE*)malloc(ROUNDKEY_SIZE);
	memcpy(output, input, BLOCK_SIZE);

	if (mode == ENC) {

		expandKey(key, roundKey);
		addRoundKey(temp, &roundKey[0]);


		for (int i = 1; i<10; i++) { //9round 반복
			subBytes(temp, ENC);
			shiftRows(temp, ENC);
			mixColumns(temp, ENC);
			addRoundKey(temp, &roundKey[i*KEY_SIZE]);
		}

		subBytes(temp, ENC);
		shiftRows(temp, ENC);
		addRoundKey(temp, &roundKey[10 * KEY_SIZE]);



		for (int i = 0; i < BLOCK_SIZE; i++) {
			output[i] = temp[i];
		}

		free(roundKey);


	}
	else if (mode == DEC) {

		expandKey(key, roundKey);
		addRoundKey(temp, &roundKey[10 * KEY_SIZE]);

		for (int i = 9; i>0; i--) {
			shiftRows(temp, DEC);
			subBytes(temp, DEC);
			addRoundKey(temp, &roundKey[i*KEY_SIZE]);
			mixColumns(temp, DEC);

		}
		shiftRows(temp, DEC);
		subBytes(temp, DEC);
		addRoundKey(temp, &roundKey[0]);

		for (int i = 0; i < BLOCK_SIZE; i++) {
			output[i] = temp[i];
		}



	}
	else {
		fprintf(stderr, "Invalid mode!\n");
		exit(1);
	}
}



