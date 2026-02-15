#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX 10

/*  FULL S-DES */

int IP[8] = {2, 6, 3, 1, 4, 8, 5, 7};
int IP_INV[8] = {4, 1, 3, 5, 7, 2, 8, 6};
int EP[8] = {4, 1, 2, 3, 2, 3, 4, 1};
int P4[4] = {2, 4, 3, 1};

int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}};

int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}};

void permute(int *in, int *out, int *p, int n)
{
    for (int i = 0; i < n; i++)
        out[i] = in[p[i] - 1];
}

void xor_bits(int *a, int *b, int *out, int n)
{
    for (int i = 0; i < n; i++)
        out[i] = a[i] ^ b[i];
}

void sbox(int *in, int box[4][4], int *out)
{
    int row = in[0] * 2 + in[3];
    int col = in[1] * 2 + in[2];
    int val = box[row][col];
    out[0] = (val >> 1) & 1;
    out[1] = val & 1;
}

void fk(int *bits, int *key)
{
    int L[4], R[4], ep[8], temp[8];
    int s0o[2], s1o[2], p4[4];

    for (int i = 0; i < 4; i++)
    {
        L[i] = bits[i];
        R[i] = bits[i + 4];
    }

    permute(R, ep, EP, 8);
    xor_bits(ep, key, temp, 8);

    sbox(temp, S0, s0o);
    sbox(temp + 4, S1, s1o);

    int s[4] = {s0o[0], s0o[1], s1o[0], s1o[1]};
    permute(s, p4, P4, 4);
    xor_bits(L, p4, L, 4);

    for (int i = 0; i < 4; i++)
    {
        bits[i] = L[i];
        bits[i + 4] = R[i];
    }
}

void swap(int *b)
{
    for (int i = 0; i < 4; i++)
    {
        int t = b[i];
        b[i] = b[i + 4];
        b[i + 4] = t;
    }
}

void sdes_encrypt(int *pt, int *k1, int *k2, int *ct)
{
    int t[8];
    permute(pt, t, IP, 8);
    fk(t, k1);
    swap(t);
    fk(t, k2);
    permute(t, ct, IP_INV, 8);
}

void sdes_decrypt(int *ct, int *k1, int *k2, int *pt)
{
    int t[8];
    permute(ct, t, IP, 8);
    fk(t, k2);
    swap(t);
    fk(t, k1);
    permute(t, pt, IP_INV, 8);
}

// modes of operation

void ecb_dec(int ct[][8], int pt[][8], int n, int *k1, int *k2)
{
    for (int i = 0; i < n; i++)
        sdes_decrypt(ct[i], k1, k2, pt[i]);
}

void cbc_dec(int ct[][8], int pt[][8], int n, int iv[8], int *k1, int *k2)
{
    int temp[8], prev[8];
    for (int i = 0; i < 8; i++)
        prev[i] = iv[i];
    for (int i = 0; i < n; i++)
    {
        sdes_decrypt(ct[i], k1, k2, temp);
        xor_bits(temp, prev, pt[i], 8);
        for (int j = 0; j < 8; j++)
            prev[j] = ct[i][j];
    }
}

void cfb_dec(int ct[][8], int pt[][8], int n, int iv[8], int *k1, int *k2)
{
    int temp[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(iv, k1, k2, temp);
        xor_bits(ct[i], temp, pt[i], 8);
        for (int j = 0; j < 8; j++)
            iv[j] = ct[i][j];
    }
}

void ofb_dec(int ct[][8], int pt[][8], int n, int iv[8], int *k1, int *k2)
{
    int stream[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(iv, k1, k2, stream);
        xor_bits(ct[i], stream, pt[i], 8);
        for (int j = 0; j < 8; j++)
            iv[j] = stream[j];
    }
}

void ctr_dec(int ct[][8], int pt[][8], int n, int ctr[][8], int *k1, int *k2)
{
    int stream[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(ctr[i], k1, k2, stream);
        xor_bits(ct[i], stream, pt[i], 8);
    }
}

int main()
{
    WSADATA wsa;
    SOCKET s, cs;
    struct sockaddr_in server, client;
    int len = sizeof(client);

    int ct[MAX][8], pt[MAX][8], ctr[MAX][8];
    int iv[8], k1[8], k2[8];
    int blocks, mode;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    bind(s, (struct sockaddr *)&server, sizeof(server));
    listen(s, 3);

    printf("Server waiting...\n");
    cs = accept(s, (struct sockaddr *)&client, &len);

    recv(cs, (char *)&mode, sizeof(mode), 0);
    recv(cs, (char *)&blocks, sizeof(blocks), 0);
    if (mode != 1 && mode != 5)
        recv(cs, (char *)iv, sizeof(iv), 0);
    if (mode == 5)
        recv(cs, (char *)ctr, sizeof(ctr), 0);
    recv(cs, (char *)ct, sizeof(ct), 0);

    printf("\nReceived Ciphertext at Server:\n");
    for (int i = 0; i < blocks; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            printf("%d", ct[i][j]);
        }
        printf("\n");
    }

    printf("Enter same K1: ");
    for (int i = 0; i < 8; i++)
        scanf("%d", &k1[i]);
    printf("Enter same K2: ");
    for (int i = 0; i < 8; i++)
        scanf("%d", &k2[i]);

    if (mode == 1)
        ecb_dec(ct, pt, blocks, k1, k2);
    if (mode == 2)
        cbc_dec(ct, pt, blocks, iv, k1, k2);
    if (mode == 3)
        cfb_dec(ct, pt, blocks, iv, k1, k2);
    if (mode == 4)
        ofb_dec(ct, pt, blocks, iv, k1, k2);
    if (mode == 5)
        ctr_dec(ct, pt, blocks, ctr, k1, k2);

    printf("\nRecovered Plaintext:\n");
    for (int i = 0; i < blocks; i++)
    {
        for (int j = 0; j < 8; j++)
            printf("%d", pt[i][j]);
        printf("\n");
    }

    closesocket(cs);
    closesocket(s);
    WSACleanup();
    return 0;
}
