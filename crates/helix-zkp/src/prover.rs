use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TracePolyTable, TraceTable,
};

use crate::air::{PersonhoodAir, PersonhoodInputs, TRACE_LEN};

pub struct PersonhoodProver {
    options: ProofOptions,
}

impl PersonhoodProver {
    pub fn new() -> Self {
        PersonhoodProver {
            options: ProofOptions::new(
                // num_queries — the query count is what carries the FRI soundness, and unlike
                // the grinding factor it is NOT weakened by Grover's algorithm, so security is
                // drawn from queries rather than proof-of-work. 48 queries × log2(blowup=8) = 144
                // bits before grinding, capped by the 128-bit f128 field — i.e. the proof now
                // reaches this field's ceiling (~128-bit conjectured) instead of the old ~95.
                48,
                8,                       // blowup factor
                16,                      // grinding factor (anti-DoS; deliberately not relied on for soundness)
                FieldExtension::None,    // base field is already f128 (128-bit) — no extension needed
                8,                       // FRI folding factor
                255,                     // FRI max remainder polynomial degree
                BatchingMethod::Linear,  // constraint batching
                BatchingMethod::Linear,  // DEEP poly batching
            ),
        }
    }

    /// Build the squaring trace and return `(proof, commitment)`.
    /// `commitment = secret^(2^63)` in the 128-bit prime field.
    pub fn prove(&self, secret: BaseElement) -> (Proof, BaseElement) {
        let mut trace = TraceTable::<BaseElement>::new(1, TRACE_LEN);
        trace.fill(
            |state| {
                state[0] = secret;
            },
            |_step, state| {
                state[0] = state[0].square();
            },
        );
        let commitment = trace.get(0, TRACE_LEN - 1);
        let proof = self.generate_proof::<BaseElement>(trace).expect("STARK proof generation failed");
        (proof, commitment)
    }
}

impl Default for PersonhoodProver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Prover trait impl ────────────────────────────────────────────────────────

type Blake3Hash = Blake3_256<BaseElement>;
type MerkleVC = MerkleTree<Blake3Hash>;

impl Prover for PersonhoodProver {
    type BaseField = BaseElement;
    type Air = PersonhoodAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3Hash;
    type VC = MerkleVC;
    type RandomCoin = DefaultRandomCoin<Blake3Hash>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Blake3Hash, MerkleVC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Blake3Hash, MerkleVC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, PersonhoodAir, E>;

    fn get_pub_inputs(&self, trace: &TraceTable<BaseElement>) -> PersonhoodInputs {
        PersonhoodInputs { commitment: trace.get(0, TRACE_LEN - 1) }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &winterfell::TraceInfo,
        main_trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<BaseElement>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a PersonhoodAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}
