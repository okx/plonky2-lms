use super::constants::*;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};

pub fn u8_to_f<F: RichField + Extendable<D>, const D: usize>(data: &[u8]) -> Vec<F> {
    data.chunks(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            F::from_canonical_u64(u64::from_be_bytes(bytes))
        })
        .collect::<Vec<F>>()
}

pub fn u8_to_1f<F: RichField + Extendable<D>, const D: usize>(data: &[u8]) -> F {
    let vec = u8_to_f(data);
    assert_eq!(vec.len(), 1);
    vec[0]
}

pub fn u8_to_hashout<F: RichField + Extendable<D>, const D: usize>(data: &[u8]) -> HashOut<F> {
    assert_eq!(data.len(), POSEIDON_HASH_OUTPUT_SIZE_BYTES);
    HashOut::from_vec(u8_to_f::<F, D>(data))
}

pub fn u8_to_hashout_array<F: RichField + Extendable<D>, const D: usize>(
    data: &[u8],
) -> Vec<HashOut<F>> {
    data.chunks(POSEIDON_HASH_OUTPUT_SIZE_BYTES)
        .map(u8_to_hashout)
        .collect::<Vec<HashOut<F>>>()
}

/// Assert x >= y
pub fn assert_greater<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) {
    let diff: Target = builder.sub(x, y);
    builder.range_check(diff, MAX_POSITIVE_AMOUNT_LOG);
}

#[cfg(test)]
pub(crate) mod test_util {
    use plonky2::{
        field::{extension::Extendable, goldilocks_field::GoldilocksField, types::PrimeField64},
        hash::hash_types::{HashOut, RichField},
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig,
        },
    };

    use crate::circuits::constants::C;
    use core::panic;

    /// Test runner
    pub fn run_circuit_test<T, F, const D: usize>(test: T) -> ()
    where
        T: FnOnce(&mut CircuitBuilder<F, D>, &mut PartialWitness<F>) -> () + panic::UnwindSafe,
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw: PartialWitness<F> = PartialWitness::<F>::new();
        test(&mut builder, &mut pw);
        let data = builder.build::<C>();
        let proof = data.prove(pw).expect("Prove fail");
        data.verify(proof).expect("Verify fail")
    }

    /// Big endian conversion
    ///
    /// HashOut.to_bytes() is small endian
    pub fn hashout_to_u8(hashout: &HashOut<GoldilocksField>) -> Vec<u8> {
        hashout
            .elements
            .into_iter()
            .map(|x| x.to_canonical_u64().to_be_bytes())
            .flatten()
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use tests::test_util::hashout_to_u8;

    #[test]
    fn test_u8_hashout_conversion() {
        let before = vec![1u8; 32];
        let after = hashout_to_u8(&u8_to_hashout::<F, D>(before.as_slice()));
        assert_eq!(before, after);
    }

    #[test]
    fn test_u8_to_1f() {
        let value: u64 = 0x1020304050607080;
        let before: [u8; 8] = value.to_be_bytes();
        let after = u8_to_1f::<F, D>(&before);
        let expected = F::from_canonical_u64(value);
        assert_eq!(after, expected);
    }

    #[test]
    fn test_u8_to_f() {
        let values = vec![0x2, 0x1];
        let before = values
            .iter()
            .map(|x: &u64| x.to_be_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let after = u8_to_f::<F, D>(&before);
        let expected = values
            .iter()
            .map(|x| F::from_canonical_u64(*x))
            .collect::<Vec<F>>();
        assert_eq!(after, expected);
    }
}
