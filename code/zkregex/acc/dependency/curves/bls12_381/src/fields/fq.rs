use ark_ff::fields::{Fp384, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"]
#[generator = "2"]
pub struct FqConfig;
pub type Fq = Fp384<MontBackend<FqConfig, 6>>;

pub const FQ_ONE: Fq = MontFp!(Fq, "1");
pub const FQ_ZERO: Fq = MontFp!(Fq, "0");
