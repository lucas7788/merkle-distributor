use crate::{claim, concat3, get_merkle_root, get_token_address, init, is_claimed};
use crate::{sha256, Address, H256, U128};
use ostd::mock::build_runtime;

#[test]
fn test() {
    let token = Address::repeat_byte(1);
    let merkle_root = H256::repeat_byte(2);
    let admin = Address::repeat_byte(3);
    let mut mock = build_runtime();
    mock.witness(&[admin]);
    assert!(init(&token, &merkle_root, &admin));
    assert!(!init(&token, &merkle_root, &admin));

    assert_eq!(&get_token_address(), &token);
    assert_eq!(&get_merkle_root(), &merkle_root);

    let amount = U128::new(100);

    let mut users = (1..100)
        .into_iter()
        .map(|i| {
            let index = U128::new(i);
            assert!(!is_claimed(index));
            let a = i + 3;
            let account = Address::repeat_byte(a as u8);
            let proof = sha256(concat3(index, account, amount));
            TestS::new(U128::new(i), account, amount, proof)
        })
        .collect::<Vec<TestS>>();

    let merkle_proof = sha256(concat3(index, account, amount));

    assert!(claim(index, &account, amount, merkle_proof.as_ref()));
    assert!(is_claimed(index));
}

struct TestS {
    index: U128,
    account: Address,
    amount: U128,
    proof: H256,
}

impl TestS {
    fn new(index: U128, account: Address, amount: U128, proof: H256) -> Self {
        TestS {
            index,
            account,
            amount,
            proof,
        }
    }
}
