// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2025 Badcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include "serialize.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "version.h"

#include <stdexcept>
#include <stdint.h>
#include <vector>
#include <limits>
#include <algorithm>

extern const signed char p_util_hexdigit[256]; // defined in util.cpp

inline signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

/** C++ wrapper for arith_uint256 (modern bignum) */
class CBigNum final
{
private:
    arith_uint256 value;
    bool negative;

    void Normalize()
    {
        if (value == 0) negative = false;
    }
    
    void CheckDivisionByZero(const CBigNum& b) const
    {
        if (b.value == 0) throw bignum_error("CBigNum division by zero");
    }

public:
    CBigNum() : value(0), negative(false) { Normalize(); }

    CBigNum(const CBigNum& b) : value(b.value), negative(b.negative) { Normalize(); }

    CBigNum& operator=(const CBigNum& b)
    {
        value = b.value;
        negative = b.negative;
        Normalize();
        return *this;
    }

    ~CBigNum() = default;

    // Constructors from various types
    explicit CBigNum(signed char n) : negative(n < 0), value((uint64_t)(n < 0 ? -n : n)) { Normalize(); }
    explicit CBigNum(short n) : negative(n < 0), value((uint64_t)(n < 0 ? -n : n)) { Normalize(); }
    explicit CBigNum(int n) : negative(n < 0), value((uint64_t)(n < 0 ? -n : n)) { Normalize(); }
    explicit CBigNum(long n) : negative(n < 0), value((uint64_t)(n < 0 ? -n : n)) { Normalize(); }
    explicit CBigNum(long long n) : negative(n < 0), value(n < 0 ? arith_uint256(-(uint64_t)n) : arith_uint256((uint64_t)n)) { Normalize(); }
    explicit CBigNum(unsigned char n) : negative(false), value(n) {}
    explicit CBigNum(unsigned short n) : negative(false), value(n) {}
    explicit CBigNum(unsigned int n) : negative(false), value(n) {}
    explicit CBigNum(unsigned long n) : negative(false), value(n) {}
    explicit CBigNum(unsigned long long n) : negative(false), value(n) {}
    explicit CBigNum(uint256 n) : negative(false), value(UintToArith256(n)) {}

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        setvch(vch);
    }

    void setulong(unsigned long n)
    {
        value = n;
        negative = false;
        Normalize();
    }

    unsigned long getulong() const
    {
        return value.GetLow64();
    }

    unsigned int getuint() const
    {
        return (unsigned int)value.GetLow64();
    }

    int getint() const
    {
        uint64_t low = value.GetLow64();
        if (negative && value != 0) {
            return low > (uint64_t)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)low;
        } else {
            return low > (uint64_t)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : (int)low;
        }
    }

    void setint64(int64_t sn)
    {
        negative = sn < 0;
        value = arith_uint256((uint64_t)(negative ? -sn : sn));
        Normalize();
    }

    void setuint64(uint64_t n)
    {
        value = n;
        negative = false;
        Normalize();
    }

    void setuint256(uint256 n)
    {
        value = UintToArith256(n);
        negative = false;
        Normalize();
    }

    uint256 getuint256() const
    {
        return ArithToUint256(value);
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        value = 0;
        negative = false;
        // Import in big-endian order (MSB first)
        for (size_t i = 0; i < vch.size(); ++i) {
            value = (value << 8) | vch[i];
        }
        Normalize();
    }

    std::vector<unsigned char> getvch() const
    {
        if (value == 0) return std::vector<unsigned char>();
        // Build big-endian byte vector (MSB first, minimal representation)
        int bytes = (value.bits() + 7) / 8;
        std::vector<unsigned char> vch(bytes);
        arith_uint256 temp = value;
        for (int i = bytes - 1; i >= 0; --i) {
            vch[i] = temp.GetLow64() & 0xff;
            temp >>= 8;
        }
        // Remove leading zeros
        while (!vch.empty() && vch[0] == 0) vch.erase(vch.begin());
        return vch;
    }

    CBigNum& SetCompact(unsigned int nCompact)
    {
        bool fOverflow;
        value.SetCompact(nCompact, &negative, &fOverflow);
        // Sanity check for overflow
        if (fOverflow) throw bignum_error("CBigNum::SetCompact overflow");
        return *this;
    }

    unsigned int GetCompact() const
    {
        return value.GetCompact(negative);
    }

    void SetHex(const std::string& str)
    {
        std::string s = str;
        // Handle sign
        negative = false;
        if (!s.empty() && s[0] == '-') {
            negative = true;
            s = s.substr(1);
        }
        value.SetHex(s);
    }

    std::string ToString(int nBase = 10) const
    {
        if (nBase == 16) {
            std::string s = value.GetHex();
            if (negative) s = "-" + s;
            return s;
        }
        if (nBase == 10) {
            if (value == 0) return "0";
            std::string str;
            CBigNum n = *this;
            bool neg = negative;
            if (neg) {
                str = "-";
                n.negative = false;
            }
            CBigNum ten(10);
            while (n > 0) {
                CBigNum rem = n % ten;
                str += '0' + rem.getulong();
                n /= ten;
            }
            std::reverse(str.begin() + (neg ? 1 : 0), str.end());
            return str;
        }
        // For other bases, fallback to hex
        return ToString(16);
    }

    std::string GetHex() const
    {
        return ToString(16);
    }

    CBigNum abs() const
    {
        CBigNum r = *this; r.negative = false; return r;
    }

    unsigned int GetSerializeSize(int nType = 0, int nVersion = PROTOCOL_VERSION) const
    {
        return ::GetSerializeSize(getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType = 0, int nVersion = PROTOCOL_VERSION) const
    {
        ::Serialize(s, getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType = 0, int nVersion = PROTOCOL_VERSION)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion);
        setvch(vch);
    }

    bool operator!() const
    {
        return value == 0;
    }

    // Friend declarations for operators accessing private members
    friend bool operator==(const CBigNum& a, const CBigNum& b);
    friend bool operator<=(const CBigNum& a, const CBigNum& b);

    CBigNum& operator+=(const CBigNum& b)
    {
        if (negative == b.negative) {
            // Same sign: add magnitudes
            value += b.value;
        } else {
            if (value >= b.value) {
                value -= b.value;
            } else {
                value = b.value - value;
                negative = !negative;
                // Different signs: subtract smaller from larger
            }
        }
        Normalize();
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        *this += -b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        value *= b.value;
        // Sign: positive if same signs, negative if different
        negative = negative != b.negative;
        Normalize();
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        CheckDivisionByZero(b);
        value /= b.value;
        negative = negative != b.negative;
        Normalize();
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        CheckDivisionByZero(b);
        value %= b.value;
        negative = false;
        Normalize();
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        value <<= shift;
        Normalize();
        return *this;
        // Left shift preserves sign but may zero
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        value >>= shift;
        Normalize();
        return *this;
        // Right shift preserves sign but may zero
    }

    CBigNum& operator++()
    {
        if (negative) {
            if (value > 0) {
                --value;
            } else {
                value = 1;
                negative = false;
            }
        } else {
            ++value;
        }
        return *this;
    }

    const CBigNum operator++(int)
    {
        CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        if (negative) {
            ++value;
        } else {
            if (value > 0) {
                --value;
            } else {
                value = 1;
                negative = true;
            }
        }
        return *this;
    }

    const CBigNum operator--(int)
    {
        CBigNum ret = *this;
        --(*this);
        return ret;
    }

    CBigNum nthRoot(int n) const
    {
        assert(n > 1);
        // Validation: n must be between 2 and 256
        if (n <= 1 || n > 256) throw bignum_error("CBigNum::nthRoot invalid n");
        if (value == 0) return CBigNum(0);
        assert(!negative); // Assume positive for nth root

        // Binary search for nth root, with overflow check in multiplication
        arith_uint256 low = 0;
        arith_uint256 high = value;
        arith_uint256 mid;
        while (low < high) {
            mid = (low + high + 1) / 2;
            arith_uint256 pow = 1;
            for (int i = 0; i < n; ++i) {
                // Check for multiplication overflow
                if (mid != 0 && pow > std::numeric_limits<arith_uint256>::max() / mid) throw bignum_error("CBigNum::nthRoot overflow in power calculation");
                else pow *= mid;
                if (pow > value) break;
            }
            if (pow <= value) {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        return CBigNum(low);
    }
};

inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r = a;
    r += b;
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r = a;
    r -= b;
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r = a;
    r.negative = !r.negative;
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CBigNum r = a;
    r *= b;
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CBigNum r = a;
    r /= b;
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CBigNum r = a;
    r %= b;
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    r <<= shift;
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    r >>= shift;
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b)
{
    return a.negative == b.negative && a.value == b.value;
}

inline bool operator!=(const CBigNum& a, const CBigNum& b) { return !(a == b); }
inline bool operator<=(const CBigNum& a, const CBigNum& b)
{
    if (a.negative != b.negative) return a.negative;
    if (a.negative) return a.value >= b.value;
    return a.value <= b.value;
}

inline bool operator>=(const CBigNum& a, const CBigNum& b) { return b <= a; }
inline bool operator<(const CBigNum& a, const CBigNum& b) { return !(a >= b); }
inline bool operator>(const CBigNum& a, const CBigNum& b) { return !(a <= b); }

#endif
