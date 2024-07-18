#include <iostream>
#include <vector>
using namespace std;

const int V = 64;

class LFSR
{
public:
    LFSR(vector<int> &tap, vector<int> &state)
    {
        m_tap = move(tap);
        m_state = move(state);
    }

    int getbit()
    {
        int f = 0;
        for (int i : m_tap)
            f ^= m_state[i] & 1;

        int x = m_state[0];
        m_state.erase(m_state.begin());
        m_state.emplace_back(f);

        return x;
    }

private:
    vector<int> m_tap;
    vector<int> m_state;
};

void matrix_mul(int A[V][V], int B[V][V])
{
    int C[V][V] = {0};

    for (int i = 0; i < V; ++i)
        for (int j = 0; j < V; ++j)
            for (int k = 0; k < V; ++k)
                C[i][j] ^= A[i][k] & B[k][j];

    for (int i = 0; i < V; ++i)
        for (int j = 0; j < V; ++j)
            A[i][j] = C[i][j];
}

void matrix_power(int A[V][V], int n)
{
    int I[V][V] = {0};
    for (int i = 0; i < V; ++i)
        I[i][i] = 1;

    for (; n; n >>= 1, matrix_mul(A, A))
        if (n & 1)
            matrix_mul(I, A);

    for (int i = 0; i < V; ++i)
        for (int j = 0; j < V; ++j)
            A[i][j] = I[i][j];
}

signed main()
{
    vector<int> taps{0, 2, 17, 19, 23, 37, 41, 53};
    vector<int> stream{0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0};

    int A[V][V] = {0};
    for (int i = 0; i < 63; ++i)
        A[i][i + 1] = 1;

    for (int tap : taps)
        A[63][tap] = 1;

    int A71[V][V] = {0};
    int A_b[V][V] = {0};
    int B[V][V + 2] = {0};

    for (int i = 0; i < V; ++i)
        for (int j = 0; j < V; ++j)
            A71[i][j] = A_b[i][j] = A[i][j];

    matrix_power(A71, 71);
    matrix_power(A_b, 70 + 256 * 71);

    for (int i = 0; i < V; ++i)
    {
        for (int j = 0; j < V; ++j)
            B[i][j] = A_b[0][j];
        matrix_mul(A_b, A71);
    }

    for (int i = 0; i < V; ++i)
    {
        B[i][V] = stream[256 + i];
        B[i][V + 1] = i;
    }

    for (int i = 0; i < V; ++i)
    {
        int mxi = i;
        for (int j = i; j < V; ++j)
        {
            if (B[j][i])
            {
                mxi = j;
                break;
            }
        }
        if (mxi != i)
            for (int j = i; j < V + 2; ++j)
                swap(B[i][j], B[mxi][j]);

        for (int j = i + 1; j < V; ++j)
            if (B[j][i])
                for (int k = i; k < V + 1; ++k)
                    B[j][k] ^= B[i][k];
    }

    for (int i = V - 1; i >= 0; --i)
        for (int j = 0; j < i; ++j)
            if (B[j][i])
                for (int k = i; k < V + 1; ++k)
                    B[j][k] ^= B[i][k];

    vector<int> key(V, 0);

    for (int i = 0; i < V; ++i)
        key[i] = B[i][V];

    LFSR randomness(taps, key);
    vector<int> output;

    for (int i = 0; i < stream.size(); ++i)
    {
        for (int j = 0; j < 70; ++j)
            randomness.getbit();
        output.emplace_back(randomness.getbit());
    }

    vector<int> flag(256, 0);
    for (int i = 0; i < 256; ++i)
        flag[i] = output[i] ^ stream[i];

    for (int i = 0; i < 256; ++i)
        cout << flag[i];
    cout << endl;
}