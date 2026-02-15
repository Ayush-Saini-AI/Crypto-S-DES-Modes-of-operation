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
void ecb_enc(int pt[][8], int ct[][8], int n, int *k1, int *k2)
{
    for (int i = 0; i < n; i++)
        sdes_encrypt(pt[i], k1, k2, ct[i]);
}

void cbc_enc(int pt[][8], int ct[][8], int n, int iv[8], int *k1, int *k2)
{
    int temp[8];
    for (int i = 0; i < n; i++)
    {
        xor_bits(pt[i], iv, temp, 8);
        sdes_encrypt(temp, k1, k2, ct[i]);
        for (int j = 0; j < 8; j++)
            iv[j] = ct[i][j];
    }
}

void cfb_enc(int pt[][8], int ct[][8], int n, int iv[8], int *k1, int *k2)
{
    int temp[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(iv, k1, k2, temp);
        xor_bits(pt[i], temp, ct[i], 8);
        for (int j = 0; j < 8; j++)
            iv[j] = ct[i][j];
    }
}

void ofb_enc(int pt[][8], int ct[][8], int n, int iv[8], int *k1, int *k2)
{
    int stream[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(iv, k1, k2, stream);
        xor_bits(pt[i], stream, ct[i], 8);
        for (int j = 0; j < 8; j++)
            iv[j] = stream[j];
    }
}

void ctr_enc(int pt[][8], int ct[][8], int n, int ctr[][8], int *k1, int *k2)
{
    int stream[8];
    for (int i = 0; i < n; i++)
    {
        sdes_encrypt(ctr[i], k1, k2, stream);
        xor_bits(pt[i], stream, ct[i], 8);
    }
}

int main()
{
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;

    int pt[MAX][8], ct[MAX][8], ctr[MAX][8];
    int iv[8], k1[8], k2[8];
    int blocks, mode;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(s, (struct sockaddr *)&server, sizeof(server));

    printf("Blocks: ");
    scanf("%d", &blocks);
    printf("Plaintext:\n");
    for (int i = 0; i < blocks; i++)
        for (int j = 0; j < 8; j++)
            scanf("%d", &pt[i][j]);

    printf("Mode 1-ECB 2-CBC 3-CFB 4-OFB 5-CTR: ");
    scanf("%d", &mode);

    printf("Enter K1 (8): ");
    for (int i = 0; i < 8; i++)
        scanf("%d", &k1[i]);
    printf("Enter K2 (8): ");
    for (int i = 0; i < 8; i++)
        scanf("%d", &k2[i]);

    if (mode != 1 && mode != 5)
    {
        printf("Enter IV: ");
        for (int i = 0; i < 8; i++)
            scanf("%d", &iv[i]);
    }
    if (mode == 5)
    {
        printf("Enter Counter blocks:\n");
        for (int i = 0; i < blocks; i++)
            for (int j = 0; j < 8; j++)
                scanf("%d", &ctr[i][j]);
    }

    if (mode == 1)
        ecb_enc(pt, ct, blocks, k1, k2);
    if (mode == 2)
        cbc_enc(pt, ct, blocks, iv, k1, k2);
    if (mode == 3)
        cfb_enc(pt, ct, blocks, iv, k1, k2);
    if (mode == 4)
        ofb_enc(pt, ct, blocks, iv, k1, k2);
    if (mode == 5)
        ctr_enc(pt, ct, blocks, ctr, k1, k2);

    send(s, (char *)&mode, sizeof(mode), 0);
    send(s, (char *)&blocks, sizeof(blocks), 0);
    if (mode != 1 && mode != 5)
        send(s, (char *)iv, sizeof(iv), 0);
    if (mode == 5)
        send(s, (char *)ctr, sizeof(ctr), 0);
    send(s, (char *)ct, sizeof(ct), 0);

    printf("Ciphertext sent\n");

    closesocket(s);
    WSACleanup();
    return 0;
}
