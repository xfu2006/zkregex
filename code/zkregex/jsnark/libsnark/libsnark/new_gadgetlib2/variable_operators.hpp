/** @file
 *****************************************************************************
 Holds all of the arithmetic operators for the classes declared in variable.hpp .

 This take clutter out of variable.hpp while leaving the * operators in a header file,
 thus allowing them to be inlined, for optimization purposes.
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLEOPERATORS_HPP_
#define LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLEOPERATORS_HPP_

#include <libsnark/new_gadgetlib2/variable.hpp>

namespace new_gadgetlib2 {

/*************************************************************************************************/
/*************************************************************************************************/
/*******************                                                            ******************/
/*******************                    lots o' operators                       ******************/
/*******************                                                            ******************/
/*************************************************************************************************/
/*************************************************************************************************/

/***********************************/
/***         operator+           ***/
/***********************************/

// Polynomial<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const Polynomial<Fp>& second)        {auto retval = first; return retval += second;}

// Monomial<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const Polynomial<Fp>& second)        {return Polynomial<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const Monomial<Fp>& second)          {return Polynomial<Fp>(first) + Polynomial<Fp>(second);}

// LinearCombination<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const LinearCombination<Fp>& first, const Polynomial<Fp>& second)        {return Polynomial<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const LinearCombination<Fp>& first, const Monomial<Fp>& second)          {return Polynomial<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearCombination<Fp>& first, const LinearCombination<Fp>& second) {auto retval = first; return retval += second;}

// LinearTerm<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const LinearTerm<Fp>& first,        const Polynomial<Fp>& second)        {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const LinearTerm<Fp>& first,        const Monomial<Fp>& second)          {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearTerm<Fp>& first,        const LinearCombination<Fp>& second) {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearTerm<Fp>& first,        const LinearTerm<Fp>& second)        {return LinearCombination<Fp>(first) + LinearCombination<Fp>(second);}

// Variable<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const Variable<Fp>& first,          const Polynomial<Fp>& second)        {return LinearTerm<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Variable<Fp>& first,          const Monomial<Fp>& second)          {return LinearTerm<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const Variable<Fp>& first,          const LinearCombination<Fp>& second) {return LinearTerm<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const Variable<Fp>& first,          const LinearTerm<Fp>& second)        {return LinearTerm<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const Variable<Fp>& first,          const Variable<Fp>& second)          {return LinearTerm<Fp>(first) + LinearTerm<Fp>(second);}

// FElem<Fp>
template <class Fp>
inline Polynomial<Fp>        operator+(const FElem<Fp>& first,             const Polynomial<Fp>& second)        {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const FElem<Fp>& first,             const Monomial<Fp>& second)          {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const FElem<Fp>& first,             const LinearCombination<Fp>& second) {return LinearCombination<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const FElem<Fp>& first,             const LinearTerm<Fp>& second)        {return LinearCombination<Fp>(first) + LinearCombination<Fp>(second);}
template <class Fp>
inline LinearCombination<Fp> operator+(const FElem<Fp>& first,             const Variable<Fp>& second)          {return LinearCombination<Fp>(first) + LinearCombination<Fp>(second);}
template <class Fp>
inline FElem<Fp>             operator+(const FElem<Fp>& first,             const FElem<Fp>& second)             {auto retval = first; return retval += second;}

// int
template <class Fp>
inline FElem<Fp>             operator+(const int first,                const FElem<Fp>& second)             {return FElem<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const int first,                const Variable<Fp>& second)          {return FElem<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const int first,                const LinearTerm<Fp>& second)        {return FElem<Fp>(first) + second;}
template <class Fp>
inline LinearCombination<Fp> operator+(const int first,                const LinearCombination<Fp>& second) {return FElem<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const int first,                const Monomial<Fp>& second)          {return FElem<Fp>(first) + second;}
template <class Fp>
inline Polynomial<Fp>        operator+(const int first,                const Polynomial<Fp>& second)        {return FElem<Fp>(first) + second;}

// symetrical operators
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const Monomial<Fp>& second)          {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const LinearCombination<Fp>& second) {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const LinearCombination<Fp>& second) {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearCombination<Fp>& first, const LinearTerm<Fp>& second)        {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const LinearTerm<Fp>& second)        {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const LinearTerm<Fp>& second)        {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearTerm<Fp>& first,        const Variable<Fp>& second)          {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearCombination<Fp>& first, const Variable<Fp>& second)          {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const Variable<Fp>& second)          {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const Variable<Fp>& second)          {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const Variable<Fp>& first,          const FElem<Fp>& second)             {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearTerm<Fp>& first,        const FElem<Fp>& second)             {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearCombination<Fp>& first, const FElem<Fp>& second)             {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const FElem<Fp>& second)             {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const FElem<Fp>& second)             {return second + first;}
template <class Fp>
inline FElem<Fp>             operator+(const FElem<Fp>& first,             const int second)                {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const Variable<Fp>& first,          const int second)                {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearTerm<Fp>& first,        const int second)                {return second + first;}
template <class Fp>
inline LinearCombination<Fp> operator+(const LinearCombination<Fp>& first, const int second)                {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Monomial<Fp>& first,          const int second)                {return second + first;}
template <class Fp>
inline Polynomial<Fp>        operator+(const Polynomial<Fp>& first,        const int second)                {return second + first;}

/***********************************/
/***           operator-         ***/
/***********************************/
template <class Fp>
inline LinearTerm<Fp>        operator-(const Variable<Fp>& src) {return LinearTerm<Fp>(src, -1);}

template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const LinearCombination<Fp>& first, const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const LinearCombination<Fp>& first, const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& first, const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const LinearTerm<Fp>& first,        const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const LinearTerm<Fp>& first,        const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearTerm<Fp>& first,        const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearTerm<Fp>& first,        const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Variable<Fp>& first,          const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Variable<Fp>& first,          const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const Variable<Fp>& first,          const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const Variable<Fp>& first,          const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const Variable<Fp>& first,          const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const FElem<Fp>& first,             const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const FElem<Fp>& first,             const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const FElem<Fp>& first,             const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const FElem<Fp>& first,             const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const FElem<Fp>& first,             const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline FElem<Fp>             operator-(const FElem<Fp>& first,             const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline FElem<Fp>             operator-(const int first,                const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const int first,                const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const int first,                const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const int first,                const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const int first,                const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const int first,                const Polynomial<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const Monomial<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const LinearCombination<Fp>& second) {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& first, const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const LinearTerm<Fp>& second)        {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearTerm<Fp>& first,        const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& first, const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const Variable<Fp>& second)          {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const Variable<Fp>& first,          const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearTerm<Fp>& first,        const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& first, const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const FElem<Fp>& second)             {return first + (-second);}
template <class Fp>
inline FElem<Fp>             operator-(const FElem<Fp>& first,             const int second)                {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const Variable<Fp>& first,          const int second)                {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearTerm<Fp>& first,        const int second)                {return first + (-second);}
template <class Fp>
inline LinearCombination<Fp> operator-(const LinearCombination<Fp>& first, const int second)                {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Monomial<Fp>& first,          const int second)                {return first + (-second);}
template <class Fp>
inline Polynomial<Fp>        operator-(const Polynomial<Fp>& first,        const int second)                {return first + (-second);}

/***********************************/
/***         operator*           ***/
/***********************************/

// Polynomial<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const Polynomial<Fp>& second)        {auto retval = first; return retval *= second;}

// Monomial<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const Monomial<Fp>& first,          const Polynomial<Fp>& second)        {return Polynomial<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const Monomial<Fp>& first,          const Monomial<Fp>& second)          {auto retval = first; return retval *= second;}

// LinearCombination<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearCombination<Fp>& first, const Polynomial<Fp>& second)        {return Polynomial<Fp>(first) * second;}
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearCombination<Fp>& first, const Monomial<Fp>& second)          {return first * Polynomial<Fp>(second);}
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearCombination<Fp>& first, const LinearCombination<Fp>& second) {return first * Polynomial<Fp>(second);}

// LinearTerm<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearTerm<Fp>& first,        const Polynomial<Fp>& second)        {return LinearCombination<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const LinearTerm<Fp>& first,        const Monomial<Fp>& second)          {return Monomial<Fp>(first) * second;}
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearTerm<Fp>& first,        const LinearCombination<Fp>& second) {return LinearCombination<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const LinearTerm<Fp>& first,        const LinearTerm<Fp>& second)        {return Monomial<Fp>(first) * Monomial<Fp>(second);}

// Variable<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const Variable<Fp>& first,          const Polynomial<Fp>& second)        {return LinearTerm<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const Variable<Fp>& first,          const Monomial<Fp>& second)          {return Monomial<Fp>(first) * second;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Variable<Fp>& first,          const LinearCombination<Fp>& second) {return LinearTerm<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const Variable<Fp>& first,          const LinearTerm<Fp>& second)        {return LinearTerm<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const Variable<Fp>& first,          const Variable<Fp>& second)          {return LinearTerm<Fp>(first) * LinearTerm<Fp>(second);}

// FElem<Fp>
template <class Fp>
inline Polynomial<Fp>        operator*(const FElem<Fp>& first,             const Polynomial<Fp>& second)        {return LinearCombination<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const FElem<Fp>& first,             const Monomial<Fp>& second)          {return Monomial<Fp>(first) * second;}
template <class Fp>
inline LinearCombination<Fp> operator*(const FElem<Fp>& first,             const LinearCombination<Fp>& second) {auto retval = second; return retval *= first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const FElem<Fp>& first,             const LinearTerm<Fp>& second)        {auto retval = second; return retval *= first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const FElem<Fp>& first,             const Variable<Fp>& second)          {return LinearTerm<Fp>(second) *= first;}
template <class Fp>
inline FElem<Fp>             operator*(const FElem<Fp>& first,             const FElem<Fp>& second)             {auto retval = first; return retval *= second;}

// int
template <class Fp>
inline FElem<Fp>             operator*(const int first,                const FElem<Fp>& second)             {return FElem<Fp>(first) * second;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const int first,                const Variable<Fp>& second)          {return FElem<Fp>(first) * second;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const int first,                const LinearTerm<Fp>& second)        {return FElem<Fp>(first) * second;}
template <class Fp>
inline LinearCombination<Fp> operator*(const int first,                const LinearCombination<Fp>& second) {return FElem<Fp>(first) * second;}
template <class Fp>
inline Monomial<Fp>          operator*(const int first,                const Monomial<Fp>& second)          {return FElem<Fp>(first) * second;}
template <class Fp>
inline Polynomial<Fp>        operator*(const int first,                const Polynomial<Fp>& second)        {return FElem<Fp>(first) * second;}

// symetrical operators
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const Monomial<Fp>& second)          {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Monomial<Fp>& first,          const LinearCombination<Fp>& second) {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const LinearCombination<Fp>& second) {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearCombination<Fp>& first, const LinearTerm<Fp>& second)        {return second * first;}
template <class Fp>
inline Monomial<Fp>          operator*(const Monomial<Fp>& first,          const LinearTerm<Fp>& second)        {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const LinearTerm<Fp>& second)        {return second * first;}
template <class Fp>
inline Monomial<Fp>          operator*(const LinearTerm<Fp>& first,        const Variable<Fp>& second)          {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const LinearCombination<Fp>& first, const Variable<Fp>& second)          {return second * first;}
template <class Fp>
inline Monomial<Fp>          operator*(const Monomial<Fp>& first,          const Variable<Fp>& second)          {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const Variable<Fp>& second)          {return second * first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const Variable<Fp>& first,          const FElem<Fp>& second)             {return second * first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const LinearTerm<Fp>& first,        const FElem<Fp>& second)             {return second * first;}
template <class Fp>
inline LinearCombination<Fp> operator*(const LinearCombination<Fp>& first, const FElem<Fp>& second)             {return second * first;}
template <class Fp>
inline Monomial<Fp>          operator*(const Monomial<Fp>& first,          const FElem<Fp>& second)             {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const FElem<Fp>& second)             {return second * first;}
template <class Fp>
inline FElem<Fp>             operator*(const FElem<Fp>& first,             const int second)                {return second * first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const Variable<Fp>& first,          const int second)                {return second * first;}
template <class Fp>
inline LinearTerm<Fp>        operator*(const LinearTerm<Fp>& first,        const int second)                {return second * first;}
template <class Fp>
inline LinearCombination<Fp> operator*(const LinearCombination<Fp>& first, const int second)                {return second * first;}
template <class Fp>
inline Monomial<Fp>          operator*(const Monomial<Fp>& first,          const int second)                {return second * first;}
template <class Fp>
inline Polynomial<Fp>        operator*(const Polynomial<Fp>& first,        const int second)                {return second * first;}


/***********************************/
/***      END OF OPERATORS       ***/
/***********************************/

} // namespace new_gadgetlib2

#endif // LIBSNARK_GADGETLIB2_INCLUDE_GADGETLIB2_VARIABLEOPERATORS_HPP_
