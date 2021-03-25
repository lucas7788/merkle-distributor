use crate::{claim, get_merkle_root, get_token_address, init, is_claimed};
use crate::{Address, H256, U128};
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

    let index = U128::new(1);
    assert!(!is_claimed(index));

    let account = Address::repeat_byte(4);
    let amount = U128::new(2);
    let merkle_proof = [H256::repeat_byte(1)];
    assert!(claim(index, &account, amount, merkle_proof.as_ref()));
    assert!(is_claimed(index));
}
