use anyhow::{ensure, Context};
use bellperson::{
    groth16::{
        self,
        aggregate::{
            aggregate_proofs, verify_aggregate_proof, AggregateProof, ProverSRS, VerifierSRS,
        },
        create_random_proof_batch, create_random_proof_batch_in_priority, verify_proofs_batch,
        PreparedVerifyingKey,
    },
    Circuit,
};
use blstrs::{Bls12, Scalar as Fr};
use log::info;
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::{
    error::Result,
    multi_proof::MultiProof,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    partitions::partition_count,
    proof::ProofScheme,
};

#[derive(Clone)]
pub struct SetupParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: <S as ProofScheme<'a>>::SetupParams,
    pub partitions: Option<usize>,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
}

#[derive(Clone)]
pub struct PublicParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub partitions: Option<usize>,
    pub priority: bool,
}

/// CircuitComponent exists so parent components can pass private inputs to their subcomponents
/// when calling CompoundProof::circuit directly. In general, there are no internal private inputs,
/// and a default value will be passed. CompoundProof::circuit implementations should exhibit
/// default behavior when passed a default ComponentPrivateinputs.
pub trait CircuitComponent {
    type ComponentPrivateInputs: Default + Clone;
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellperson::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, S: ProofScheme<'a>, C: Circuit<Fr> + CircuitComponent + Send>
where
    S::Proof: Sync + Send,
    S::PublicParams: ParameterSetMetadata + Sync + Send,
    S::PublicInputs: Clone + Sync,
    Self: CacheableParameters<C, S::PublicParams>,
{
    // setup is equivalent to ProofScheme::setup.
    fn setup(sp: &SetupParams<'a, S>) -> Result<PublicParams<'a, S>> {
        Ok(PublicParams {
            vanilla_params: S::setup(&sp.vanilla_params)?,
            partitions: sp.partitions,
            priority: sp.priority,
        })
    }

    fn partition_count(public_params: &PublicParams<'a, S>) -> usize {
        match public_params.partitions {
            None => 1,
            Some(0) => panic!("cannot specify zero partitions"),
            Some(k) => k,
        }
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        priv_in: &S::PrivateInputs,
        groth_params: &'b groth16::MappedParameters<Bls12>,
    ) -> Result<MultiProof<'b>> {
        let partition_count = Self::partition_count(pub_params);

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("vanilla_proofs:start");
        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, pub_in, priv_in, partition_count)?;

        info!("vanilla_proofs:finish");

        let sanity_check =
            S::verify_all_partitions(&pub_params.vanilla_params, pub_in, &vanilla_proofs)?;
        ensure!(sanity_check, "sanity check failed");

        info!("snark_proof:start");
        let groth_proofs = Self::circuit_proofs(
            pub_in,
            vanilla_proofs,
            &pub_params.vanilla_params,
            groth_params,
            pub_params.priority,
        )?;
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs, &groth_params.pvk))
    }

    fn prove_with_vanilla<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        vanilla_proofs: Vec<S::Proof>,
        groth_params: &'b groth16::MappedParameters<Bls12>,
    ) -> Result<MultiProof<'b>> {
        let partition_count = Self::partition_count(pub_params);

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("snark_proof:start");
        let groth_proofs = Self::circuit_proofs(
            pub_in,
            vanilla_proofs,
            &pub_params.vanilla_params,
            groth_params,
            pub_params.priority,
        )?;
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs, &groth_params.pvk))
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify<'b>(
        public_params: &PublicParams<'a, S>,
        inputs: &S::PublicInputs,
        multi_proof: &MultiProof<'b>,
        requirements: &S::Requirements,
    ) -> Result<bool> 
    where
        E: MultiMillerLoop,
        <E::Fr as PrimeField>::Repr: Sync + Copy,
        R: rand::RngCore,
    {
        ensure!(
            multi_proof.circuit_proofs.len() == Self::partition_count(public_params),
            "Inconsistent inputs"
        );

        let vanilla_public_params = &public_params.vanilla_params;
        let pvk = &multi_proof.verifying_key;

        if !<S as ProofScheme>::satisfies_requirements(
            &public_params.vanilla_params,
            requirements,
            multi_proof.circuit_proofs.len(),
        ) {
            return Ok(false);
        }

        let inputs: Vec<_> = (0..multi_proof.circuit_proofs.len())
            .into_par_iter()
            .map(|k| Self::generate_public_inputs(inputs, vanilla_public_params, Some(k)))
            .collect::<Result<_>>()?;

        let proofs: Vec<_> = multi_proof.circuit_proofs.iter().collect();
        debug_assert_eq!(proofs.len(), inputs.len());

    for pub_input in inputs {
        if (pub_input.len() + 1) != pvk.ic.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }
    }

    let num_inputs = inputs[0].len();
    let num_proofs = proofs.len();

    if num_proofs < 2 {
        return verify_proof(pvk, proofs[0], &inputs[0]);
    }

    let proof_num = proofs.len();

    // Choose random coefficients for combining the proofs.
    let mut rand_z_repr: Vec<_> = Vec::with_capacity(proof_num);
    let mut rand_z: Vec<_> = Vec::with_capacity(proof_num);
    let mut accum_y = E::Fr::zero();

    for _ in 0..proof_num {
        use rand::Rng;

        let t: u128 = rng.gen();

        let mut repr = E::Fr::zero().to_repr();
        let mut repr_u64s = le_bytes_to_u64s(repr.as_ref());
        assert!(repr_u64s.len() > 1);

        repr_u64s[0] = (t & (-1i64 as u128) >> 64) as u64;
        repr_u64s[1] = (t >> 64) as u64;

        for (i, limb) in repr_u64s.iter().enumerate() {
            let start = i * 8;
            let stop = start + 8;
            repr.as_mut()[start..stop].copy_from_slice(&limb.to_le_bytes());
        }

        let fr = E::Fr::from_repr(repr).unwrap();
        let repr = fr.to_repr();

        // calculate sum
        accum_y.add_assign(&fr);
        // store FrRepr
        rand_z_repr.push(repr);
        // store Fr
        rand_z.push(fr);
    }

    // MillerLoop(\sum Accum_Gamma)
    let mut ml_g = <E as MultiMillerLoop>::Result::default();
    // MillerLoop(Accum_Delta)
    let mut ml_d = <E as MultiMillerLoop>::Result::default();
    // MillerLoop(Accum_AB)
    let mut acc_ab = <E as MultiMillerLoop>::Result::default();
    // Y^-Accum_Y
    let mut y = <E as Engine>::Gt::identity();

    let accum_y = &accum_y;
    let rand_z_repr = &rand_z_repr;

    {
        // - Thread 1: Calculate MillerLoop(\sum Accum_Gamma)
        let ml_g = &mut ml_g;
        s.spawn(move |_| {
            let scalar_getter = |idx: usize| -> <E::Fr as ff::PrimeField>::Repr {
                if idx == 0 {
                    return accum_y.to_repr();
                }
                let idx = idx - 1;

                // \sum(z_j * aj,i)
                let mut cur_sum = rand_z[0];
                cur_sum.mul_assign(&inputs[0][idx]);

                for (pi_mont, mut rand_mont) in
                    inputs.iter().zip(rand_z.iter().copied()).skip(1)
                {
                    // z_j * a_j,i
                    let pi_mont = &pi_mont[idx];
                    rand_mont.mul_assign(pi_mont);
                    cur_sum.add_assign(&rand_mont);
                }

                cur_sum.to_repr()
            };

            // \sum Accum_Gamma
            let acc_g_psi = multiscalar::par_multiscalar::<_, E::G1Affine>(
                &multiscalar::ScalarList::Getter(scalar_getter, num_inputs + 1),
                &pvk.multiscalar,
                256,
            );

            // MillerLoop(acc_g_psi, vk.gamma)
            *ml_g = E::multi_miller_loop(&[(&acc_g_psi.to_affine(), &pvk.gamma_g2)]);
        });

        // - Thread 2: Calculate MillerLoop(Accum_Delta)
        let ml_d = &mut ml_d;
        s.spawn(move |_| {
            let points: Vec<_> = proofs.iter().map(|p| p.c).collect();

            // Accum_Delta
            let acc_d: E::G1 = {
                let pre = multiscalar::precompute_fixed_window::<E::G1Affine>(&points, 1);
                multiscalar::multiscalar::<E::G1Affine>(
                    rand_z_repr,
                    &pre,
                    std::mem::size_of::<<E::Fr as PrimeField>::Repr>() * 8,
                )
            };

            *ml_d = E::multi_miller_loop(&[(&acc_d.to_affine(), &pvk.delta_g2)]);
        });

        // - Thread 3: Calculate MillerLoop(Accum_AB)
        let acc_ab = &mut acc_ab;
        s.spawn(move |_| {
            let accum_ab_mls: Vec<_> = proofs
                .par_iter()
                .zip(rand_z_repr.par_iter())
                .map(|(proof, rand)| {
                    // [z_j] pi_j,A
                    let mul_a = proof.a.mul(E::Fr::from_repr(*rand).unwrap());

                    // -pi_j,B
                    let cur_neg_b = -proof.b.to_curve();

                    E::multi_miller_loop(&[(&mul_a.to_affine(), &cur_neg_b.to_affine().into())])
                })
                .collect();

            // Accum_AB = mul_j(ml((zj*proof_aj), -proof_bj))
            *acc_ab = accum_ab_mls[0];
            for accum in accum_ab_mls.iter().skip(1).take(num_proofs) {
                *acc_ab += accum;
            }
        });

        // Thread 4(current): Calculate Y^-Accum_Y
        // -Accum_Y
        let accum_y_neg = -*accum_y;

        // Y^-Accum_Y
        y = pvk.alpha_g1_beta_g2 * accum_y_neg;
    };

    let mut ml_all = acc_ab;
    ml_all += ml_d;
    ml_all += ml_g;

    let actual = ml_all.final_exponentiation();
    Ok(actual == y)
    }

    /// Efficiently verify multiple proofs.
    fn batch_verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &[S::PublicInputs],
        multi_proofs: &[MultiProof<'b>],
        requirements: &S::Requirements,
    ) -> Result<bool> {
        ensure!(
            public_inputs.len() == multi_proofs.len(),
            "Inconsistent inputs"
        );
        for proof in multi_proofs {
            ensure!(
                proof.circuit_proofs.len() == Self::partition_count(public_params),
                "Inconsistent inputs"
            );
        }
        ensure!(!public_inputs.is_empty(), "Cannot verify empty proofs");

        let vanilla_public_params = &public_params.vanilla_params;
        // just use the first one, the must be equal any way
        let pvk = &multi_proofs[0].verifying_key;

        for multi_proof in multi_proofs.iter() {
            if !<S as ProofScheme>::satisfies_requirements(
                &public_params.vanilla_params,
                requirements,
                multi_proof.circuit_proofs.len(),
            ) {
                return Ok(false);
            }
        }

        let inputs: Vec<_> = multi_proofs
            .par_iter()
            .zip(public_inputs.par_iter())
            .flat_map(|(multi_proof, pub_inputs)| {
                (0..multi_proof.circuit_proofs.len())
                    .into_par_iter()
                    .map(|k| {
                        Self::generate_public_inputs(pub_inputs, vanilla_public_params, Some(k))
                    })
                    .collect::<Result<Vec<_>>>()
                    .expect("Invalid public inputs") // TODO: improve error handling
            })
            .collect::<Vec<_>>();
        let circuit_proofs: Vec<_> = multi_proofs
            .iter()
            .flat_map(|m| m.circuit_proofs.iter())
            .collect();

        let res = verify_proofs_batch(pvk, &mut OsRng, &circuit_proofs[..], &inputs)?;

        Ok(res)
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a groth proof.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    fn circuit_proofs(
        pub_in: &S::PublicInputs,
        vanilla_proofs: Vec<S::Proof>,
        pub_params: &S::PublicParams,
        groth_params: &groth16::MappedParameters<Bls12>,
        priority: bool,
    ) -> Result<Vec<groth16::Proof<Bls12>>> {
        let mut rng = OsRng;
        ensure!(
            !vanilla_proofs.is_empty(),
            "cannot create a circuit proof over missing vanilla proofs"
        );

        let circuits = vanilla_proofs
            .into_par_iter()
            .enumerate()
            .map(|(k, vanilla_proof)| {
                Self::circuit(
                    pub_in,
                    C::ComponentPrivateInputs::default(),
                    &vanilla_proof,
                    pub_params,
                    Some(k),
                )
            })
            .collect::<Result<Vec<_>>>()?;

        let groth_proofs = if priority {
            create_random_proof_batch_in_priority(circuits, groth_params, &mut rng)?
        } else {
            create_random_proof_batch(circuits, groth_params, &mut rng)?
        };

        groth_proofs
            .into_iter()
            .map(|groth_proof| {
                let mut proof_vec = Vec::new();
                groth_proof.write(&mut proof_vec)?;
                let gp = groth16::Proof::<Bls12>::read(&proof_vec[..])?;
                Ok(gp)
            })
            .collect()
    }

    /// Given a prover_srs key, a list of groth16 proofs, and an ordered list of seeds
    /// (used to derive the PoRep challenges) hashed pair-wise with the comm_rs using sha256, aggregate them all into
    /// an AggregateProof type.
    fn aggregate_proofs(
        prover_srs: &ProverSRS<Bls12>,
        hashed_seeds_and_comm_rs: &[u8],
        proofs: &[groth16::Proof<Bls12>],
        version: groth16::aggregate::AggregateVersion,
    ) -> Result<AggregateProof<Bls12>> {
        Ok(aggregate_proofs::<Bls12>(
            prover_srs,
            hashed_seeds_and_comm_rs,
            proofs,
            version,
        )?)
    }

    /// Verifies the aggregate proof, with respect to the flattened input list.
    ///
    /// Note that this method internally instantiates an OSRng and passes it to the `verify_aggregate_proofs`
    /// method in bellperson.  While proofs would normally parameterize the type of rng used, we don't
    /// want it exposed past this level so as not to force the wrapper calls around this method in
    /// rust-filecoin-proofs-api to unroll this call outside of the tree parameterized `with_shape` macro
    /// usage.
    fn verify_aggregate_proofs(
        ip_verifier_srs: &VerifierSRS<Bls12>,
        pvk: &PreparedVerifyingKey<Bls12>,
        hashed_seeds_and_comm_rs: &[u8],
        public_inputs: &[Vec<Fr>],
        aggregate_proof: &groth16::aggregate::AggregateProof<Bls12>,
        version: groth16::aggregate::AggregateVersion,
    ) -> Result<bool> {
        let mut rng = OsRng;

        Ok(verify_aggregate_proof(
            ip_verifier_srs,
            pvk,
            &mut rng,
            public_inputs,
            aggregate_proof,
            hashed_seeds_and_comm_rs,
            version,
        )?)
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellperson::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(
        pub_in: &S::PublicInputs,
        pub_params: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<Fr>>;

    /// circuit constructs an instance of this CompoundProof's bellperson::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        component_private_inputs: C::ComponentPrivateInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<C>;

    fn blank_circuit(public_params: &S::PublicParams) -> C;

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn groth_params<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::MappedParameters<Bls12>> {
        Self::get_groth_params(rng, Self::blank_circuit(public_params), public_params)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn verifying_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::VerifyingKey<Bls12>> {
        Self::get_verifying_key(rng, Self::blank_circuit(public_params), public_params)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn srs_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
        num_proofs_to_aggregate: usize,
    ) -> Result<ProverSRS<Bls12>> {
        let generic_srs = Self::get_inner_product(
            rng,
            Self::blank_circuit(public_params),
            public_params,
            num_proofs_to_aggregate,
        )?;

        let (prover_srs, _verifier_srs) = generic_srs.specialize(num_proofs_to_aggregate);

        Ok(prover_srs)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn srs_verifier_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
        num_proofs_to_aggregate: usize,
    ) -> Result<VerifierSRS<Bls12>> {
        let generic_srs = Self::get_inner_product(
            rng,
            Self::blank_circuit(public_params),
            public_params,
            num_proofs_to_aggregate,
        )?;

        let (_prover_srs, verifier_srs) = generic_srs.specialize(num_proofs_to_aggregate);

        Ok(verifier_srs)
    }

    fn circuit_for_test(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<(C, Vec<Fr>)> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        // Some(0) because we only return a circuit and inputs for the first partition.
        // It would be more thorough to return all, though just checking one is probably
        // fine for verifying circuit construction.
        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0))?;

        let circuit = Self::circuit(
            &partition_pub_in,
            C::ComponentPrivateInputs::default(),
            &vanilla_proofs[0],
            vanilla_params,
            Some(0),
        )?;

        Ok((circuit, inputs))
    }

    /// Like circuit_for_test but returns values for all partitions.
    fn circuit_for_test_all(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<Vec<(C, Vec<Fr>)>> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        let mut res = Vec::with_capacity(partition_count);
        for (partition, vanilla_proof) in vanilla_proofs.iter().enumerate() {
            let partition_pub_in = S::with_partition(public_inputs.clone(), Some(partition));
            let inputs =
                Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(partition))?;

            let circuit = Self::circuit(
                &partition_pub_in,
                C::ComponentPrivateInputs::default(),
                vanilla_proof,
                vanilla_params,
                Some(partition),
            )?;
            res.push((circuit, inputs));
        }
        Ok(res)
    }
}
