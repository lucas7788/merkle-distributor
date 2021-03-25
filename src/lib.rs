#![cfg_attr(not(feature = "mock"), no_std)]
#![feature(proc_macro_hygiene)]

#[cfg(test)]
mod test;

extern crate ontio_std as ostd;

use ostd::abi::{Encoder, EventBuilder, Sink, Source, VmValueBuilder, VmValueParser};
use ostd::contract::{ong, ont};
use ostd::database::{get, put};
use ostd::prelude::{str, Vec, U128};
use ostd::runtime;
use ostd::runtime::{address, check_witness, contract_delete, contract_migrate, input, sha256};
use ostd::types::{Address, H256};

const KEY_INIT: &[u8] = b"1";
const KEY_TOKEN: &[u8] = b"2";
const KEY_MERKLE_ROOT: &[u8] = b"3";
const KEY_CLAIMED_BIT: &[u8] = b"4";
const KEY_ADMIN: &[u8] = b"5";
const KEY_PENDING_ADMIN: &[u8] = b"6";

pub fn init(token: &Address, merkle_root: &H256, admin: &Address) -> bool {
    let has_init: bool = get(KEY_INIT).unwrap_or_default();
    if has_init {
        failure("init", "only can init once");
        return false;
    } else {
        assert!(!token.is_zero(), "token address is zero");
        assert!(!merkle_root.is_zero(), "merkle_root is zero");
        put(KEY_INIT, true);
        put(KEY_TOKEN, token);
        put(KEY_MERKLE_ROOT, merkle_root);
        put(KEY_ADMIN, admin);
        true
    }
}

fn get_admin() -> Address {
    get(KEY_ADMIN).unwrap()
}
fn get_pending_admin() -> Address {
    get(KEY_PENDING_ADMIN).unwrap_or_default()
}

pub fn is_claimed(index: U128) -> bool {
    let u128_ = U128::new(128);
    let claimed_word_index = index / u128_;
    let claimed_bit_index = index.raw() % 128;
    let claimed_word = get_claimed_word(claimed_word_index);
    let mask = 2u128.pow(claimed_bit_index as u32);
    return claimed_word.raw() & mask == mask;
}

pub fn claim(index: U128, account: &Address, amount: U128, merkle_proof: &[H256]) -> bool {
    if is_claimed(index) {
        return failure(
            "claim, is_claimed",
            "MerkleDistributor: Drop already claimed.",
        );
    }
    let node = sha256(concat3(index, account, amount));
    if !verify_merkle_proof(merkle_proof, &get_merkle_root(), &node) {
        return failure(
            "claim,verify_merkle_proof",
            "MerkleDistributor: Invalid proof.",
        );
    }
    set_claimed_inner(index);
    let res = transfer_neovm(&get_token_address(), &address(), account, amount);
    assert!(res, "transfer_neovm failed");
    claim_event(index, account, amount);
    true
}

fn verify_merkle_proof(proof: &[H256], root: &H256, leaf: &H256) -> bool {
    let mut computed_hash = leaf.clone();
    for proof_element in proof.iter() {
        computed_hash = if &computed_hash <= proof_element {
            sha256(concat(computed_hash, proof_element))
        } else {
            sha256(concat(proof_element, computed_hash))
        }
    }
    &computed_hash == root
}

#[no_mangle]
fn invoke() {
    let input = input();
    let mut source = Source::new(&input);
    let action: &[u8] = source.read().unwrap();
    let mut sink = Sink::new(32);
    match action {
        b"init" => {
            let (token, merkle_root, admin) = source.read().unwrap();
            sink.write(init(token, merkle_root, admin));
        }
        b"migrate" => {
            let (code, vm_type, name, version, author, email, desc) = source.read().unwrap();
            let vm_type: U128 = vm_type;
            let vm_type = vm_type.raw() as u32;
            assert!(check_witness(&get_admin()), "check witness failed");
            let new_addr = contract_migrate(code, vm_type, name, version, author, email, desc);
            sink.write(new_addr);
        }
        b"_setPendingAdmin" => {
            let new_pending_admin = source.read().unwrap();
            sink.write(_set_pending_admin(new_pending_admin));
        }
        b"_acceptAdmin" => {
            sink.write(_accept_admin());
        }
        b"getAdmin" => {
            sink.write(get_admin());
        }
        b"getPendingAdmin" => {
            sink.write(get_pending_admin());
        }
        b"getToken" => {
            sink.write(get_token_address());
        }
        b"getMerkleRoot" => {
            sink.write(get_merkle_root());
        }
        b"isClaimed" => {
            let index = source.read().unwrap();
            sink.write(is_claimed(index));
        }
        b"claim" => {
            let (index, account, amount, merkle_proof) = source.read().unwrap();
            let merkle_proof: Vec<H256> = merkle_proof;
            sink.write(claim(index, account, amount, merkle_proof.as_slice()));
        }
        b"contractDelete" => {
            contract_delete();
        }
        _ => {
            let method = str::from_utf8(action).ok().unwrap();
            panic!("not support method:{}", method)
        }
    }
    runtime::ret(b"success");
}

pub fn _set_pending_admin(pending_admin: &Address) -> bool {
    // Check caller = admin
    if !runtime::check_witness(&get_admin()) {
        return failure("_set_pending_admin", "check witness failed");
    }
    assert!(!pending_admin.is_zero(), "pending admin is zero");

    // Save current value, if any, for inclusion in log
    let old_pending_admin = get_pending_admin();

    // Store pendingAdmin with value new_pending_admin
    put(KEY_PENDING_ADMIN, pending_admin);

    // Emit new_pending_admin(old_pending_admin, new_pending_admin)
    new_pending_admin(&old_pending_admin, pending_admin);
    true
}

pub fn _accept_admin() -> bool {
    let pending_admin = &get_pending_admin();
    // Check caller is pending_admin and pending_admin ≠ address(0)
    if pending_admin.is_zero() || !runtime::check_witness(pending_admin) {
        return failure(
            "_accept_admin",
            "check witness failed or pending admin is zero",
        );
    }

    // Save current values for inclusion in log
    let old_admin = get_admin();

    // Store admin with value pending_admin
    put(KEY_ADMIN, pending_admin);
    // Clear the pending value
    let pending_admin = &Address::new([0u8; 20]);
    put(KEY_PENDING_ADMIN, pending_admin);

    new_admin(&old_admin, pending_admin);
    new_pending_admin(pending_admin, pending_admin);
    true
}

fn set_claimed_inner(index: U128) {
    let u128_ = U128::new(128);
    let claimed_word_index = index / u128_;
    let claimed_bit_index = index.raw() % 128;
    let old = get_claimed_word(claimed_word_index);
    let claimed_bit_index = 2u128.pow(claimed_bit_index as u32);
    put_claimed_word(claimed_word_index, U128::new(old.raw() | claimed_bit_index));
}

fn put_claimed_word(claimed_word_index: U128, word: U128) {
    put(concat(KEY_CLAIMED_BIT, claimed_word_index), word);
}

pub fn get_claimed_word(claimed_word_index: U128) -> U128 {
    get(concat(KEY_CLAIMED_BIT, claimed_word_index)).unwrap_or_default()
}

pub fn get_token_address() -> Address {
    get(KEY_TOKEN).unwrap()
}
pub fn get_merkle_root() -> H256 {
    get(KEY_MERKLE_ROOT).unwrap()
}

fn concat<K: Encoder, T: Encoder>(prefix: K, post: T) -> Vec<u8> {
    let mut sink = Sink::new(20);
    sink.write(prefix);
    sink.write(post);
    sink.bytes().to_vec()
}
fn concat3<K: Encoder, T: Encoder, V: Encoder>(prefix: K, post: T, post2: V) -> Vec<u8> {
    let mut sink = Sink::new(32);
    sink.write(prefix);
    sink.write(post);
    sink.write(post2);
    sink.bytes().to_vec()
}

fn failure(method: &str, detail: &str) -> bool {
    EventBuilder::new()
        .string("Failure")
        .string(method)
        .string(detail)
        .notify();
    false
}

fn claim_event(index: U128, account: &Address, amount: U128) {
    EventBuilder::new()
        .string("claim")
        .number(index)
        .address(account)
        .number(amount)
        .notify();
}

fn new_pending_admin(old_pending_admin: &Address, new_pending_admin: &Address) {
    EventBuilder::new()
        .string("NewPendingAdmin")
        .address(old_pending_admin)
        .address(new_pending_admin)
        .notify();
}

fn new_admin(old_admin: &Address, new_admin: &Address) {
    EventBuilder::new()
        .string("NewAdmin")
        .address(old_admin)
        .address(new_admin)
        .notify();
}

#[cfg(test)]
pub fn transfer_neovm(contract: &Address, from: &Address, to: &Address, amount: U128) -> bool {
    true
}

#[cfg(not(test))]
pub fn transfer_neovm(contract: &Address, from: &Address, to: &Address, amount: U128) -> bool {
    const ONT_CONTRACT_ADDRESS: Address =
        ostd::macros::base58!("AFmseVrdL9f9oyCzZefL9tG6UbvhUMqNMV");
    const ONG_CONTRACT_ADDRESS: Address =
        ostd::macros::base58!("AFmseVrdL9f9oyCzZefL9tG6UbvhfRZMHJ");

    if contract == &ONT_CONTRACT_ADDRESS {
        return ont::transfer(from, to, amount);
    }
    if contract == &ONG_CONTRACT_ADDRESS {
        return ong::transfer(from, to, amount);
    }
    let mut builder = VmValueBuilder::new();
    builder.string("transfer");
    let mut nested = builder.list();
    nested.address(from);
    nested.address(to);
    nested.number(amount);
    nested.finish();
    call_neovm_bool(contract, builder.bytes().as_slice())
}

#[track_caller]
pub fn call_neovm_bool(address: &Address, param: &[u8]) -> bool {
    let result = runtime::call_contract(address, param);
    let mut source = VmValueParser::new(result.as_slice());
    source.bool().unwrap()
}
