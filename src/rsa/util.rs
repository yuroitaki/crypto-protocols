use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{
    Zero,
    identities::One,
};

pub fn modular_inverse(number: &BigInt, modulus: &BigInt) -> BigInt {
    if modulus.is_one() {
        return BigInt::one();
    }

    let (mut num, mut modu, mut x, mut inv) = (
        number.clone(),
        modulus.clone(),
        BigInt::zero(),
        BigInt::one(),
    );

    while num > BigInt::one() {
        let (quotient, remainder) = num.div_rem(&modu);
        inv -= quotient * &x;
        num = remainder;
        std::mem::swap(&mut num, &mut modu);
        std::mem::swap(&mut x, &mut inv);
    }
 
    if inv < BigInt::zero() {
        inv += modulus;
    }

    inv
}
