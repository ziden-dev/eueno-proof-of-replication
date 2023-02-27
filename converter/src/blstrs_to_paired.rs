use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use paired::bls12_381::{G1Affine as PairedG1Affine, G2Affine as PairedG2Affine, Fr as PairedFr, 
    G2Compressed};

pub fn convert_paired_fr(scalar: Fr) -> PairedFr{  
    let scalar_be = scalar.to_bytes_be();
    let mut repr = FrRepr::default();
    repr.read_be(Cursor::new(&scalar_be[..]))
            .unwrap();
    PairedFr::from_repr(repr).unwrap()
}  

pub fn convert_fq(fp: [u8; 48]) -> Fq{  
    let mut repr = FqRepr([0; 6]);
    repr.read_be(Cursor::new(&fp))
            .unwrap();
    Fq::from_repr(repr).unwrap()
}

pub fn convert_paired_g1(point: G1Affine) -> Result<PairedG1Affine, GroupDecodingError> {
    let x = point.x();
    let y = point.y();

    let x_be = x.to_bytes_be();
    let y_be = y.to_bytes_be();

    let mut p_be = Vec::new();
    p_be.extend_from_slice(&x_be);
    p_be.extend_from_slice(&y_be);

    let mut compressed: <PairedG1Affine as CurveAffine>::Uncompressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(&p_be);
    compressed.into_affine()
}

pub fn convert_paired_g2(point: G2Affine) -> Result<PairedG2Affine, GroupDecodingError> {
    let ax = point.x();
    let ay = point.y();

    let ax_be_0 = ax.c0().to_bytes_be();
    let ax_be_1 = ax.c1().to_bytes_be();
    let ay_be_0 = ay.c0().to_bytes_be();
    let ay_be_1 = ay.c1().to_bytes_be();

    let mut pa_be = Vec::new();
    pa_be.extend_from_slice(&ax_be_1);
    pa_be.extend_from_slice(&ax_be_0);
    pa_be.extend_from_slice(&ay_be_1);
    pa_be.extend_from_slice(&ay_be_0);

    let mut compressed: <PairedG2Affine as CurveAffine>::Uncompressed = EncodedPoint::empty();
    compressed.as_mut().copy_from_slice(&pa_be);
    compressed.into_affine()
}

#[test]
fn test_convert_fr(){
    let rng = &mut rand::thread_rng();
    let a = Fr::random(&mut *rng);
    println!("a: {}", a.to_string());

    let b = convert_paired_fr(a);
    println!("b: {}", b.to_string());

}

#[test]
fn test_convert_fq(){
    let rng = &mut rand::thread_rng();
    let a = Fr::random(&mut *rng);
    println!("a: {}", a.to_string());

    let point_a = G1Affine::generator().mul(&a).to_affine();

    println!("a_x: {:?}", point_a.x().to_string());

    let a_be = point_a.x().to_bytes_be();

    let fq = convert_fq(a_be);

    print!("fq: {:?}", fq);
}

#[test]
fn test_convert_g1(){
    let rng = &mut rand::thread_rng();
    let a = Fr::random(&mut *rng);
    println!("a: {}", a.to_string());

    let point_a = G1Affine::generator().mul(&a).to_affine();
    
    println!("point_a: {:?}", point_a.x());

    let decode_a = convert_paired_g1(point_a).expect("failed to decode g2");

    println!("decode: {}", decode_a.to_string());
}

#[test]
fn test_convert_g2(){
    let rng = &mut rand::thread_rng();
    let a = Fr::random(&mut *rng);
    println!("a: {}", a.to_string());

    let point_a = G2Affine::generator().mul(&a).to_affine();
    
    println!("point_a: {:?}", point_a);

    let decode_a = convert_paired_g2(point_a).expect("failed to decode g2");

    println!("decode: {}", decode_a.to_string());

}