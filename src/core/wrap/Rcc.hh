// Copyright (C) 2025  Niels Martignène <niels.martignene@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the “Software”), to deal in
// the Software without restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
// Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

#pragma once

#include "src/core/base/base.hh"

#include <Rcpp.h>

namespace RG {

extern BucketArray<const char *> rcc_log_messages;
extern bool rcc_log_missing_messages;

void rcc_DumpWarnings();
void rcc_StopWithLastError() __attribute__((noreturn));

void *rcc_GetPointerSafe(SEXP xp);

template <typename T, typename U>
U rcc_GetOptional(T &vec, Size idx, U default_value)
{
    if (idx >= vec.Len()) [[unlikely]]
        return default_value;
    auto value = vec[idx];
    if (vec.IsNA(value))
        return default_value;
    return value;
}

class rcc_AutoSexp {
    SEXP xp = nullptr;

public:
    rcc_AutoSexp() = default;
    rcc_AutoSexp(SEXP xp) : xp(PROTECT(xp)) {}

    ~rcc_AutoSexp()
    {
        if (xp) {
            UNPROTECT_PTR(xp);
        }
    }

    rcc_AutoSexp(const rcc_AutoSexp &other) : xp(other.xp ? PROTECT(other.xp) : nullptr) {}
    rcc_AutoSexp &operator=(const rcc_AutoSexp &other)
    {
        if (xp) {
            UNPROTECT_PTR(xp);
        }
        xp = other.xp ? PROTECT(other.xp) : nullptr;
        return *this;
    }

    operator bool() const { return xp; }
    operator SEXP() const { return xp; }
    rcc_AutoSexp &operator=(SEXP new_xp)
    {
        if (xp) {
            UNPROTECT_PTR(xp);
        }
        xp = PROTECT(new_xp);
        return *this;
    }
};

template <typename T>
class rcc_Vector {};

template <>
class rcc_Vector<double> {
    rcc_AutoSexp xp;
    Span<double> span = {};

public:
    rcc_Vector() = default;
    rcc_Vector(SEXP xp)
        : xp(xp)
    {
        if (TYPEOF(xp) == REALSXP) {
            span = MakeSpan(REAL(xp), Rf_xlength(xp));
        } else if (xp == R_NilValue) {
            span = {};
        } else {
            Rcpp::stop("Expected numeric vector");
        }
    }
    rcc_Vector(Size len)
    {
        xp = Rf_allocVector(REALSXP, len);
        span = MakeSpan(REAL(xp), Rf_xlength(xp));
    }

    operator SEXP() const { return xp; }

    double *begin() { return span.begin(); }
    const double *begin() const { return span.begin(); }
    double *end() { return span.end(); }
    const double *end() const { return span.end(); }

    Size Len() const { return span.len; }

    static bool IsNA(double value) { return ISNA(value); }

    double &operator[](Size idx) { return span[idx]; }
    const double &operator[](Size idx) const { return span[idx]; }

    void Set(Size idx, double value) { span[idx] = value; }
};

template <>
class rcc_Vector<int> {
    rcc_AutoSexp xp;
    Span<int> span = {};

public:
    rcc_Vector() = default;
    rcc_Vector(SEXP xp)
        : xp(xp)
    {
        if (TYPEOF(xp) == INTSXP) {
            span = MakeSpan(INTEGER(xp), Rf_xlength(xp));
        } else if (xp == R_NilValue) {
            span = {};
        } else {
            Rcpp::stop("Expected integer vector");
        }
    }
    rcc_Vector(Size len)
    {
        xp = Rf_allocVector(INTSXP, len);
        span = MakeSpan(INTEGER(xp), Rf_xlength(xp));
    }

    operator SEXP() const { return xp; }

    int *begin() { return span.begin(); }
    const int *begin() const { return span.begin(); }
    int *end() { return span.end(); }
    const int *end() const { return span.end(); }

    Size Len() const { return span.len; }

    static bool IsNA(int value) { return value == NA_INTEGER; }

    int &operator[](Size idx) { return span[idx]; }
    const int &operator[](Size idx) const { return span[idx]; }

    void Set(Size idx, int value) { span[idx] = value; }
};

template <>
class rcc_Vector<bool> {
    rcc_AutoSexp xp;
    Span<int> span = {};

public:
    class Iterator {
        const int *ptr;

    public:
        Iterator(const int *ptr) : ptr(ptr) {}

        bool operator*() { return *ptr; }

        Iterator &operator++() { ptr++; return *this; }
        Iterator operator++(int) { Iterator ret = *this; ++(*this); return ret; }
        Iterator &operator--() { ptr--; return *this; }
        Iterator operator--(int) { Iterator ret = *this; --(*this); return ret; }

        bool operator==(const Iterator &other) const { return ptr == other.ptr; }
        bool operator!=(const Iterator &other) const { return ptr != other.ptr; }
    };

    rcc_Vector() = default;
    rcc_Vector(SEXP xp)
        : xp(xp)
    {
        if (TYPEOF(xp) == LGLSXP) {
            span = MakeSpan(INTEGER(xp), Rf_xlength(xp));
        } else if (xp == R_NilValue) {
            span = {};
        } else {
            Rcpp::stop("Expected logical vector");
        }
    }
    rcc_Vector(Size len)
    {
        xp = Rf_allocVector(LGLSXP, len);
        span = MakeSpan(LOGICAL(xp), Rf_xlength(xp));
    }

    operator SEXP() const { return xp; }

    Iterator begin() const { return Iterator(span.begin()); }
    Iterator end() const { return Iterator(span.end()); }

    Size Len() const { return span.len; }

    static bool IsNA(int value) { return value == NA_LOGICAL; }

    // XXX: Assigning to bool will unexpectecdly turn NA_LOGICAL into true
    int operator[](Size idx) const { return span[idx]; }

    void Set(Size idx, bool value) { span[idx] = value; }
};

template <>
class rcc_Vector<const char *> {
    rcc_AutoSexp xp;
    Span<SEXP> span = {};

public:
    class Iterator {
        const SEXP *xp;

    public:
        Iterator(const SEXP *xp) : xp(xp) {}

        const char *operator*() { return CHAR(*xp); }

        Iterator &operator++() { xp++; return *this; }
        Iterator operator++(int) { Iterator ret = *this; ++(*this); return ret; }
        Iterator &operator--() { xp--; return *this; }
        Iterator operator--(int) { Iterator ret = *this; --(*this); return ret; }

        bool operator==(const Iterator &other) const { return xp == other.xp; }
        bool operator!=(const Iterator &other) const { return xp != other.xp; }
    };

    rcc_Vector() = default;
    rcc_Vector(SEXP xp)
        : xp(xp)
    {
        if (TYPEOF(xp) == STRSXP) {
            span = MakeSpan(STRING_PTR(xp), Rf_xlength(xp));
        } else if (xp == R_NilValue) {
            span = {};
        } else {
            Rcpp::stop("Expected character vector");
        }
    }
    rcc_Vector(Size len) : rcc_Vector(Rf_allocVector(STRSXP, len)) {}

    operator SEXP() const { return xp; }

    Iterator begin() const { return Iterator(span.begin()); }
    Iterator end() const { return Iterator(span.end()); }

    Size Len() const { return span.len; }

    static bool IsNA(Span<const char> value) { return value.ptr == CHAR(NA_STRING); }
    static bool IsNA(const char *value) { return value == CHAR(NA_STRING); }

    const Span<const char> operator[](Size idx) const
        { return MakeSpan(CHAR(span[idx]), Rf_xlength(span[idx])); }

    void Set(Size idx, const char *str)
    {
        RG_ASSERT(idx >= 0 && idx < span.len);
        if (str) {
            SET_STRING_ELT(xp, idx, Rf_mkChar(str));
        } else {
            SET_STRING_ELT(xp, idx, NA_STRING);
        }
    }
    void Set(Size idx, Span<const char> str)
    {
        RG_ASSERT(idx >= 0 && idx < span.len);
        RG_ASSERT(str.len < INT_MAX);
        SET_STRING_ELT(xp, idx, Rf_mkCharLen(str.ptr, (int)str.len));
    }
};

template <>
class rcc_Vector<LocalDate> {
    enum class Type {
        Character,
        Date
    };

    rcc_AutoSexp xp;
    Type type = Type::Date;
    union {
        Span<SEXP> chr;
        Span<double> num;
    } u;

public:
    rcc_Vector() : type(Type::Date) { u.chr = {}; }
    rcc_Vector(SEXP xp);
    rcc_Vector(Size len)
    {
        xp = Rf_allocVector(REALSXP, len);
        type = Type::Date;
        u.num = MakeSpan(REAL(xp), len);

        rcc_AutoSexp cls = Rf_mkString("Date");
        Rf_setAttrib(xp, R_ClassSymbol, cls);
    }

    operator SEXP() const { return xp; }

    Size Len() const { return u.chr.len; }

    static bool IsNA(LocalDate date) { return !date.value; }

    const LocalDate operator[](Size idx) const;
    LocalDate Value() const;

    void Set(Size idx, LocalDate date);
};

template <typename T>
class rcc_NumericVector {
    enum class Type {
        Int,
        Double
    };

    rcc_AutoSexp xp;
    Type type;
    union {
        Span<int> i;
        Span<double> d;
    } u;

public:
    rcc_NumericVector() : type(Type::Int) { u.i = {}; }
    rcc_NumericVector(SEXP xp)
        : xp(xp)
    {
        if (Rf_isInteger(xp)) {
            type = Type::Int;
            u.i = MakeSpan(INTEGER(xp), Rf_xlength(xp));
        } else if (Rf_isReal(xp)) {
            type = Type::Double;
            u.d = MakeSpan(REAL(xp), Rf_xlength(xp));
        } else {
            Rcpp::stop("Expected numeric or integer vector");
        }
    }

    operator SEXP() const { return xp; }

    Size Len() const { return u.i.len; }

    static bool IsNA(T value) { return rcc_Vector<T>::IsNA(value); }

    T operator[](Size idx) const
    {
        if constexpr(std::is_floating_point<T>::value) {
            switch (type) {
                case Type::Int: { return (u.i[idx] != NA_INTEGER) ? (T)u.i[idx] : (T)NA_REAL; } break;
                case Type::Double: { return !ISNA(u.d[idx]) ? (T)u.d[idx] : (T)NA_REAL; } break;
            }
        } else {
            switch (type) {
                case Type::Int: { return (u.i[idx] != NA_INTEGER) ? (T)u.i[idx] : (T)NA_INTEGER; } break;
                case Type::Double: { return !ISNA(u.d[idx]) ? (T)u.d[idx] : (T)NA_INTEGER; } break;
            }
        }

        RG_UNREACHABLE();
    }
};

class rcc_ListBuilder {
    RG_DELETE_COPY(rcc_ListBuilder)

    struct Variable {
        const char *name;
        SEXP vec;
    };

    LocalArray<Variable, 64> variables;
    BlockAllocator str_alloc;

public:
    rcc_ListBuilder() = default;

    SEXP Add(const char *name, SEXP vec)
    {
        name = DuplicateString(name, &str_alloc).ptr;
        variables.Append({ name, vec });
        return vec;
    }

    template <typename T>
    SEXP Set(const char *name, T value)
    {
        rcc_Vector<T> vec(1);
        vec.Set(0, value);
        return Add(name, vec);
    }

    SEXP BuildList()
    {
        rcc_AutoSexp list = Rf_allocVector(VECSXP, variables.len);

        {
            rcc_AutoSexp names = Rf_allocVector(STRSXP, variables.len);
            for (Size i = 0; i < variables.len; i++) {
                SET_STRING_ELT(names, i, Rf_mkChar(variables[i].name));
                SET_VECTOR_ELT(list, i, variables[i].vec);
            }
            Rf_setAttrib(list, R_NamesSymbol, names);
        }

        return list;
    }

    SEXP BuildDataFrame()
    {
        Size nrow;
        if (variables.len >= 2) {
            nrow = Rf_xlength(variables[0].vec);
            for (Size i = 1; i < variables.len; i++) {
                if (Rf_xlength(variables[i].vec) != nrow) {
                    Rcpp::stop("Cannot create data.frame from vectors of unequal length");
                }
            }
        } else {
            nrow = 0;
        }

        rcc_AutoSexp df = BuildList();

        // Class
        {
            rcc_AutoSexp cls = Rf_mkString("data.frame");
            Rf_setAttrib(df, R_ClassSymbol, cls);
        }

        // Compact row names
        {
            rcc_AutoSexp row_names = Rf_allocVector(INTSXP, 2);
            INTEGER(row_names)[0] = NA_INTEGER;
            INTEGER(row_names)[1] = (int)nrow;
            Rf_setAttrib(df, R_RowNamesSymbol, row_names);
        }

        return df;
    }
};

class rcc_DataFrameBuilder {
    RG_DELETE_COPY(rcc_DataFrameBuilder)

    rcc_ListBuilder list_builder;
    Size len;

public:
    rcc_DataFrameBuilder(Size len) : len(len) {}

    template <typename T>
    rcc_Vector<T> Add(const char *name) { return list_builder.Add(name, rcc_Vector<T>(len)); }

    SEXP Build() { return list_builder.BuildDataFrame(); }
};

}
