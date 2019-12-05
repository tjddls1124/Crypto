/*
* @file    rsa.c
* @brief   mini RSA implementation code
* @details 세부 설명
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "miniRSA.h"

uint p, q, e, d, n;


/*
* @brief     모듈러 덧셈 연산을 하는 함수.
* @param     uint a     : 피연산자1.
* @param     uint b     : 피연산자2.
* @param     byte op    : +, - 연산자.
* @param     uint n      : 모듈러 값.
* @return    uint result : 피연산자의 덧셈에 대한 모듈러 연산 값. (a op b) mod n
*/
uint ModAdd(uint a, uint b, byte op, uint n) {
	uint result = 0;
	if (op == '+') {
		result = a + b;
	}
	else if (op == '-') {
		result = a - b;
	}
	result = mod(result, n);

	return result;
}
uint divide(uint dividend, uint divisor) // 나눗셈 비트연산 구현은 너무어려워서 구글링하였습니다ㅠㅠㅠ 죄송합니다
{
	uint i = 0, sign = 0, div = 0;

	sign = 0;
	if (dividend < 0)
	{
		dividend = ~dividend + 1;
		sign++;
	}
	if (divisor < 0)
	{
		divisor = ~divisor + 1;
		sign++;
	}
	if (dividend < divisor)
	{
		div = 0;
	}
	else
	{
		for (i = 0; i<32; i++)
		{
			if (dividend < (divisor << i))
			{
				if (i > 0) i--;
				break;
			}
			else if (dividend == (divisor << i))
			{
				break;
			}
		}

		div = 0;
		for (; i >= 0; i--)
		{
			if (dividend < divisor)
				break;

			if (dividend >= (divisor << i))
			{
				dividend -= (divisor << i);
				div += (1 << i);
			}
		}
	}
	if (sign & 0x01)
	{
		div = ~div + 1;
	}
	return div;
}
uint mod(uint dividend, uint divisor)
{
	uint result = dividend - mul(divisor, div(dividend, divisor));
	if (result < 0) result += divisor;
	return result;
}


/*
* @brief      모듈러 곱셈 연산을 하는 함수.
* @param      uint x       : 피연산자1.
* @param      uint y       : 피연산자2.
* @param      uint n       : 모듈러 값.
* @return     uint result  : 피연산자의 곱셈에 대한 모듈러 연산 값. (a x b) mod n
*/
uint ModMul(uint x, uint y, uint n) {
	uint result = 0;
	result = mod((x * y), n);
	if (result < 0) result = result + n;

	return result;
}

/*
* @brief      모듈러 거듭제곱 연산을 하는 함수.
* @param      uint base   : 피연산자1.
* @param      uint exp    : 피연산자2.
* @param      uint n      : 모듈러 값.
* @return     uint result : 피연산자의 연산에 대한 모듈러 연산 값. (base ^ exp) mod n
'square and multiply' 알고리즘을 사용하여 작성한다.
*/
uint sqMult(uint base, uint exp, uint n) {
	if (exp == 1)
		return base;
	else if (exp == 0) return 0;
	else if (exp % 2 == 0) {
		return  ModMult(sqMult(base, exp / 2, n), sqMult(base, exp / 2, n), n);
	}
	else if (exp % 2 == 1)
		return  ModMul(base, ModMul(sqMult(base, exp / 2, n), sqMult(base, exp / 2, n), n), n);



}

uint ModPow(uint base, uint exp, uint n) {
	if (exp == 1) {
		return mod(base, n);
	}
	else if (exp == 0) {
		return 1;
	}

	//squre multiplication - recursive call을 사용한다. 2로 나누어지면 결과값을 제곱, 홀수이면 1을 빼서 제곱 * base

	if (exp % 2 == 0) {
		return (ModPow(base, exp / 2, n) * ModPow(base, exp / 2, n)) % n;
	}
	else if (exp % 2 == 1) {
		return (base * ModPowlt(base, (exp - 1) / 2, n) * ModPow(base, (exp - 1) / 2, n)) % n;
	}
}

/*
* @brief      입력된 수가 소수인지 입력된 횟수만큼 반복하여 검증하는 함수.
* @param      uint testNum   : 임의 생성된 홀수.
* @param      uint repeat    : 판단함수의 반복횟수.
* @return     uint result    : 판단 결과에 따른 TRUE, FALSE 값.
* @todo       Miller-Rabin 소수 판별법과 같은 확률적인 방법을 사용하여,
이론적으로 4N(99.99%) 이상 되는 값을 선택하도록 한다.
*/
bool IsPrime(uint testNum, uint repeat) { // 밀러-라빈 소수판별법 알고리즘을 이용

	uint n = testNum;
	uint m = n - 1;
	uint k = 0;
	uint a, b;

	while (m % 2 == 0) { // 2^k * m  = n-1
		m = divide(m, 2);
		k++;
	}
	srand(time(NULL));

	for (int i = 0; i < repeat; i++) {
		a = mod(rand(), n) + 1;  // 1~n 사이의 a를 무작위로 선택
		if (GCD(a, n) != 1) {
			return FALSE;
		}
		b = sqMult(a, m, n); // b = a^m mod n
		if (b == 1 || b == n - 1) {  // 강한 유사소수
			continue;
		}
		else {
			for (int i = 0; i<k - 1; i++)
				if (mod((b*b), n) == n - 1) { // 강한 유사소수
					continue;
				}
			if (mod((b*b), n) != n - 1) { // 합성수 강한증거 FALSE 리턴
				return FALSE;
			}
		}
	}

	return TRUE; // 루프통과, 1-(1/4)^repeat 의 확률로 소수
}

/*
* @brief       모듈러 역 값을 계산하는 함수.
* @param       uint a      : 피연산자1.
* @param       uint m      : 모듈러 값.
* @return      uint result : 피연산자의 모듈러 역수 값.
* @todo        확장 유클리드 알고리즘을 사용
*/
uint ModInv(uint a, uint m) {
	uint x = a;
	uint y = m;
	uint result;
	uint t1 = 1, t2 = 0;
	uint p1 = 0, p2 = 1;
	uint q;
	uint r;
	uint temp1, temp2;

	while (y != 1) {
		q = divide(y, x);			// y = x * q + r
		r = (t1 - q* p1) * m + (t2 - q * p2) * a;  // t1 * a + t2* b =1 이면, gcd(a,b) = 1 이고 , t2 = a^(-1) mod b 임을 이용한다.
		temp1 = p1;
		temp2 = p2;
		p1 = t1 - q * p1;
		p2 = t2 - q * p2;
		t1 = temp1;
		t2 = temp2;

		y = x;
		x = r;
	}
	result = mod(t2, m);
	if (result < 0) result = result + m;

	return result;

}

/*
* @brief     RSA 키를 생성하는 함수.
* @param     uint *p   : 소수 p.
* @param     uint *q   : 소수 q.
* @param     uint *e   : 공개키 값.
* @param     uint *d   : 개인키 값.
* @param     uint *n   : 모듈러 n 값.
* @return    void
*/
void miniRSAKeygen(uint *p, uint *q, uint *e, uint *d, uint *n) {

	srand(time(NULL));
	uint r;  //r 값 생성

	uint phi_n;
	*n = 0;



	while (*n < sqMult(2, 31, UINT_MAX)) // 2^31 <= n < 2^32 인 n 을 찾을때까지 반복
	{
		r = (uint)(divide(UINT_MAX, 2)* WELLRNG512a()); //  0 ~ 2^31 보다 작은 r값을 임의로 생성하여 p와 q에 할당
		while (!IsPrime(r, 100)) {
			r = (uint)(divide(UINT_MAX, 2)* WELLRNG512a());
		}
		*p = r;
		r = (uint)(divide(UINT_MAX, 2)* WELLRNG512a());
		while (!IsPrime(r, 100)) {
			r = (uint)(divide(UINT_MAX, 2)* WELLRNG512a());
		}
		*q = r; // prime q 생성
		*n = *p * *q;
	}

	phi_n = ModMul(*p - 1, *q - 1, *n);

	*e = (uint)(WELLRNG512a() * phi_n) + 2;	 // 조건을 만족하는 1< e < phi_n 의 e 생성
	while (gcd(*e, n != 1)) {
		*e = (uint)(WELLRNG512a() * phi_n) + 2;
	}
	*d = ModInv(*e, phi_n);

}

/*
* @brief     RSA 암복호화를 진행하는 함수.
* @param     uint data   : 키 값.
* @param     uint key    : 키 값.
* @param     uint n      : 모듈러 n 값.
* @return    uint result : 암복호화에 결과값
*/
uint miniRSA(uint data, uint key, uint n) {
	uint result;
	result = sqMult(data, key, n);
	return result;
}

uint GCD(uint a, uint b) {
	uint prev_a;

	while (b != 0) {
		printf("GCD(%u, %u)\n", a, b);
		prev_a = a;
		a = b;
		while (prev_a >= b) prev_a -= b;
		b = prev_a;
	}
	printf("GCD(%u, %u)\n\n", a, b);
	return a;
}

int main(int argc, char* argv[]) {
	byte plain_text[4] = { 0x12, 0x34, 0x56, 0x78 };
	uint plain_data, encrpyted_data, decrpyted_data;
	uint seed = time(NULL);

	memcpy(&plain_data, plain_text, 4);

	// 난수 생성기 시드값 설정
	seed = time(NULL);
	InitWELLRNG512a(&seed);

	// RSA 키 생성
	miniRSAKeygen(&p, &q, &e, &d, &n);
	printf("0. Key generation is Success!\n ");
	printf("p : %u\n q : %u\n e : %u\n d : %u\n N : %u\n\n", p, q, e, d, n);

	// RSA 암호화 테스트
	encrpyted_data = miniRSA(plain_data, e, n);
	printf("1. plain text : %u\n", plain_data);
	printf("2. encrypted plain text : %u\n\n", encrpyted_data);

	// RSA 복호화 테스트
	decrpyted_data = miniRSA(encrpyted_data, d, n);
	printf("3. cipher text : %u\n", encrpyted_data);
	printf("4. Decrypted plain text : %u\n\n", decrpyted_data);

	// 결과 출력
	printf("RSA Decryption: %s\n", (decrpyted_data == plain_data) ? "SUCCESS!" : "FAILURE!");

	return 0;
}
