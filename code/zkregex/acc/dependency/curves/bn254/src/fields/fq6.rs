use ark_ff::{fields::*, MontFp, QuadExt};

use crate::*;

pub type Fq6 = Fp6<Fq6Config>;

#[derive(Clone, Copy)]
pub struct Fq6Config;

impl Fp6Config for Fq6Config {
    type Fp2Config = Fq2Config;

    /// NONRESIDUE = U+9
    const NONRESIDUE: Fq2 = QuadExt!(MontFp!(Fq, "9"), MontFp!(Fq, "1"));

    const FROBENIUS_COEFF_FP6_C1: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^(((q^0) - 1) / 3)
        QuadExt!(MontFp!(Fq, "1"), MontFp!(Fq, "0"),),
        // Fp2::NONRESIDUE^(((q^1) - 1) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "21575463638280843010398324269430826099269044274347216827212613867836435027261"
            ),
            MontFp!(
                Fq,
                "10307601595873709700152284273816112264069230130616436755625194854815875713954"
            ),
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "21888242871839275220042445260109153167277707414472061641714758635765020556616"
            ),
            MontFp!(Fq, "0"),
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "3772000881919853776433695186713858239009073593817195771773381919316419345261"
            ),
            MontFp!(
                Fq,
                "2236595495967245188281701248203181795121068902605861227855261137820944008926"
            ),
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "2203960485148121921418603742825762020974279258880205651966"
            ),
            MontFp!(Fq, "0"),
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "18429021223477853657660792034369865839114504446431234726392080002137598044644"
            ),
            MontFp!(
                Fq,
                "9344045779998320333812420223237981029506012124075525679208581902008406485703"
            ),
        ),
    ];

    const FROBENIUS_COEFF_FP6_C2: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^((2*(q^0) - 2) / 3)
        QuadExt!(MontFp!(Fq, "1"), MontFp!(Fq, "0"),),
        // Fp2::NONRESIDUE^((2*(q^1) - 2) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "2581911344467009335267311115468803099551665605076196740867805258568234346338"
            ),
            MontFp!(
                Fq,
                "19937756971775647987995932169929341994314640652964949448313374472400716661030"
            ),
        ),
        // Fp2::NONRESIDUE^((2*(q^2) - 2) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "2203960485148121921418603742825762020974279258880205651966"
            ),
            MontFp!(Fq, "0"),
        ),
        // Fp2::NONRESIDUE^((2*(q^3) - 2) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "5324479202449903542726783395506214481928257762400643279780343368557297135718"
            ),
            MontFp!(
                Fq,
                "16208900380737693084919495127334387981393726419856888799917914180988844123039"
            ),
        ),
        // Fp2::NONRESIDUE^((2*(q^4) - 2) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "21888242871839275220042445260109153167277707414472061641714758635765020556616"
            ),
            MontFp!(Fq, "0"),
        ),
        // Fp2::NONRESIDUE^((2*(q^5) - 2) / 3)
        QuadExt!(
            MontFp!(
                Fq,
                "13981852324922362344252311234282257507216387789820983642040889267519694726527"
            ),
            MontFp!(
                Fq,
                "7629828391165209371577384193250820201684255241773809077146787135900891633097"
            ),
        ),
    ];

    #[inline(always)]
    fn mul_fp2_by_nonresidue(fe: &Fq2) -> Fq2 {
        // (c0+u*c1)*(9+u) = (9*c0-c1)+u*(9*c1+c0)
        let mut f = *fe;
        f.double_in_place().double_in_place().double_in_place();
        let c0 = f.c0 + fe.c0 + Fq2Config::mul_fp_by_nonresidue(&fe.c1);
        let c1 = f.c1 + fe.c1 + fe.c0;
        QuadExt!(c0, c1)
    }
}