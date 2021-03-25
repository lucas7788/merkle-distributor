use crate::{claim, concat, concat3, get_merkle_root, get_token_address, init, is_claimed};
use crate::{sha256, Address, H256, U128};
use ostd::mock::build_runtime;

#[test]
fn test() {
    let amount = U128::new(100);
    let user_num = 9;
    let users:Vec<TestS> = (0..user_num)
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

    let mut proof1 = users
        .iter()
        .map(|item| item.proof.clone())
        .collect::<Vec<H256>>();
    if proof1.len() % 2 == 1 {
        proof1.push(H256::repeat_byte(0));
    }
    let layer_num = get_layer_num(proof1.len() as u32);
    let mut temp = proof1.clone();
    let mut all_layer: Vec<Vec<H256>> = vec![];
    all_layer.push(proof1);
    for i in (0..layer_num - 1) {
        temp = compute_proof(temp);
        if temp.len() % 2 == 1 && i != layer_num-1-1{
            temp.push(H256::repeat_byte(0));
        }
        all_layer.push(temp.clone());
    }

    let token = Address::repeat_byte(1);
    let merkle_root = all_layer.last().unwrap().last().unwrap();
    let admin = Address::repeat_byte(3);
    let mut mock = build_runtime();
    mock.witness(&[admin]);
    assert!(init(&token, merkle_root, &admin));
    assert!(!init(&token, &merkle_root, &admin));

    assert_eq!(&get_token_address(), &token);
    assert_eq!(&get_merkle_root(), merkle_root);

    for i in 0..user_num {
        let user:&TestS = users.get(i as usize).unwrap();
        let mut merkle_proof: Vec<H256> = vec![];
        let mut i_temp = i;
        let mut index = if i_temp % 2 == 1 {
            i_temp-1
        } else {
            i_temp+1
        };
        for j in 0..layer_num-1 {
            merkle_proof.push(all_layer.get(j as usize).unwrap().get(index as usize).unwrap().clone());
            i_temp = i_temp / 2;
            index = if i_temp % 2 == 1 {
                i_temp - 1
            } else {
                i_temp + 1
            };
        }
        assert!(claim(
            user.index,
            &user.account,
            user.amount,
            merkle_proof.as_ref()
        ));
        assert!(is_claimed(user.index));
    }
}

fn get_layer_num(num: u32) -> u32 {
    let r = (1..100)
        .into_iter()
        .find(|&i| 2u32.pow(i - 1) < num && num <= 2u32.pow(i));
    r.unwrap_or_default() + 1
}

fn compute_proof(mut proof1: Vec<H256>) -> Vec<H256> {
    let mut left = H256::new([0; 32]);
    let mut right = H256::new([0; 32]);
    let mut i = 0;
    let mut proof2: Vec<H256> = vec![];
    for proof in proof1.iter() {
        if i % 2 == 0 {
            left = proof.clone();
            i += 1;
        } else {
            i += 1;
            right = proof.clone();
            proof2.push(if &left < &right {
                sha256(concat(&left, &right))
            } else {
                sha256(concat(&right, &left))
            });
        }
    }
    proof2
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
