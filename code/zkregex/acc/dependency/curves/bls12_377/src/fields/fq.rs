use ark_ff::fields::{Fp384, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177"]
#[generator = "15"]
pub struct FqConfig;
pub type Fq = Fp384<MontBackend<FqConfig, 6>>;

pub const FQ_ONE: Fq = Fq::new(FqConfig::R);
pub const FQ_ZERO: Fq = MontFp!(Fq, "0");
