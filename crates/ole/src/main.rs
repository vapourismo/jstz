use http::{HeaderMap, Method, Uri};
use jstz_crypto::{
    public_key::PublicKey, public_key_hash::PublicKeyHash, signature::Signature,
};
use jstz_kernel::inbox::ExternalMessage;
use jstz_proto::{
    context::account::Nonce,
    operation::{DeployContract, Operation},
};
use tezos_crypto_rs::hash::{
    ContractTz1Hash, HashTrait, PublicKeyEd25519, SecretKeyEd25519, SeedEd25519,
};

fn sign_operation(
    sk: SecretKeyEd25519,
    pk: PublicKeyEd25519,
    op: Operation,
) -> ExternalMessage {
    let hash = op.hash();
    let sig = Signature::Ed25519(sk.sign(hash.as_ref()).unwrap());
    let pk = PublicKey::Ed25519(pk);
    ExternalMessage::new(pk, sig, op)
}

fn main() {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let (pk, sk) = SeedEd25519::try_from_bytes(&sk.to_bytes())
        .unwrap()
        .keypair()
        .unwrap();

    let addr: ContractTz1Hash = pk.clone().try_into().unwrap();
    println!("pk = {}", addr.to_base58_check());

    let em = sign_operation(
        sk.clone(),
        pk.clone(),
        Operation {
            source: PublicKeyHash::Tz1(
                tezos_crypto_rs::hash::ContractTz1Hash::from_base58_check(
                    "tz1XdRrrqrMfsFKA8iuw53xHzug9ipr6MuHq",
                )
                .unwrap(),
            ),
            nonce: Nonce::default(),
            content: jstz_proto::operation::Content::DeployContract(DeployContract {
                contract_code: include_str!("../../../examples/counter.js").to_string(),
                contract_credit: 10000000,
            }),
        },
    );

    println!("{:?}", bincode::serialize(&em).unwrap());

    let em = sign_operation(
        sk,
        pk,
        Operation {
            source: PublicKeyHash::Tz1(
                tezos_crypto_rs::hash::ContractTz1Hash::from_base58_check(
                    "tz1XdRrrqrMfsFKA8iuw53xHzug9ipr6MuHq",
                )
                .unwrap(),
            ),
            nonce: Nonce::default().next(),
            content: jstz_proto::operation::Content::RunContract(
                jstz_proto::operation::RunContract {
                    uri: Uri::from_static(
                        "tezos://tz1UiV2CioGUJrHmeRorav8XhYVpfhWheckv/",
                    ),
                    method: Method::POST,
                    headers: HeaderMap::new(),
                    body: None,
                },
            ),
        },
    );

    println!("{:?}", bincode::serialize(&em).unwrap());
}
