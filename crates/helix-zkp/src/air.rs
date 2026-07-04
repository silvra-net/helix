use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

/// Trace length: 64 rows (2^6), yielding 63 squaring transitions.
/// Row 0 = secret (private), row 63 = commitment (public).
pub const TRACE_LEN: usize = 64;

/// Public inputs for the personhood proof: the commitment C = secret^(2^63)
/// in the 128-bit prime field (2^128 - 45·2^40 + 1).
#[derive(Clone, Debug)]
pub struct PersonhoodInputs {
    pub commitment: BaseElement,
}

impl ToElements<BaseElement> for PersonhoodInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.commitment]
    }
}

/// AIR for the personhood squaring circuit.
///
/// Single-column trace of length 64:
///   - Transition: `next = current²`  (degree 2, applied to rows 0..62)
///   - Boundary assertion: `row 63 = commitment`  (public)
///
/// The prover supplies `row 0 = secret` privately; the verifier only sees the
/// commitment.  Knowing `secret` such that `secret^(2^63) = commitment` serves
/// as proof that the validator holds a credential issued by the personhood
/// authority for that commitment.
pub struct PersonhoodAir {
    context: AirContext<BaseElement>,
    commitment: BaseElement,
}

impl Air for PersonhoodAir {
    type BaseField = BaseElement;
    type PublicInputs = PersonhoodInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PersonhoodInputs, options: ProofOptions) -> Self {
        // One transition constraint of degree 2: next - current^2 = 0
        let degrees = vec![TransitionConstraintDegree::new(2)];
        // One boundary assertion (the last row)
        let context = AirContext::new(trace_info, degrees, 1, options);
        PersonhoodAir { context, commitment: pub_inputs.commitment }
    }

    fn context(&self) -> &AirContext<BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];
        // Constraint: next == current^2  →  next - current^2 == 0
        result[0] = next - current.square();
    }

    fn get_assertions(&self) -> Vec<Assertion<BaseElement>> {
        // Assert the last row of column 0 equals the public commitment
        vec![Assertion::single(0, TRACE_LEN - 1, self.commitment)]
    }
}
