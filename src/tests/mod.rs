use std::str;

use exonum_testkit::{TestKit, TestKitBuilder, TestNode};
use exonum::blockchain::{Schema, StoredConfiguration, Transaction};
use exonum::helpers::{Height, ValidatorId};
use exonum::storage::StorageValue;
use exonum::crypto::{hash, Hash};

use {ConfigurationSchema, ConfigurationService, TxConfigPropose, TxConfigVote};

fn to_boxed<T: Transaction>(tx: T) -> Box<Transaction> {
    Box::new(tx) as Box<Transaction>
}

fn new_tx_config_propose(node: &TestNode, cfg_proposal: StoredConfiguration) -> TxConfigPropose {
    let keypair = node.service_keypair();
    TxConfigPropose::new(
        keypair.0,
        str::from_utf8(cfg_proposal.into_bytes().as_slice()).unwrap(),
        keypair.1,
    )
}

fn new_tx_config_vote(node: &TestNode, cfg_proposal_hash: Hash) -> TxConfigVote {
    let keypair = node.service_keypair();
    TxConfigVote::new(keypair.0, &cfg_proposal_hash, keypair.1)
}

trait ConfigurationTestKit {
    fn default() -> Self;

    fn apply_configuration(&mut self, proposer: ValidatorId, cfg_proposal: StoredConfiguration);

    fn votes_for_propose(&self, config_hash: Hash) -> Vec<Option<TxConfigVote>>;

    fn find_propose(&self, config_hash: Hash) -> Option<TxConfigPropose>;
}

impl ConfigurationTestKit for TestKit {
    fn default() -> Self {
        TestKitBuilder::validator()
            .with_validators(4)
            .with_service(ConfigurationService::new())
            .create()
    }

    fn apply_configuration(&mut self, proposer: ValidatorId, cfg_proposal: StoredConfiguration) {
        let cfg_change_height = cfg_proposal.actual_from;
        // Push cfg change propose.
        let txs =
            txvec![
            new_tx_config_propose(
                &self.network().validators()[proposer.0 as usize],
                cfg_proposal.clone()
            ),
        ];
        self.create_block_with_transactions(txs);
        // Push votes
        let cfg_proposal_hash = cfg_proposal.hash();
        let tx_votes = self.network()
            .validators()
            .iter()
            .map(|validator| new_tx_config_vote(validator, cfg_proposal_hash))
            .map(to_boxed)
            .collect::<Vec<_>>();
        self.create_block_with_transactions(tx_votes);
        // Fast forward to cfg_change_height
        self.create_blocks_until(cfg_change_height);
        // Check that configuration applied.
        assert_eq!(
            Schema::new(&self.snapshot()).actual_configuration(),
            cfg_proposal
        );
    }

    fn votes_for_propose(&self, config_hash: Hash) -> Vec<Option<TxConfigVote>> {
        let snapshot = self.snapshot();
        let schema = ConfigurationSchema::new(&snapshot);
        schema.get_votes(&config_hash)
    }

    fn find_propose(&self, config_hash: Hash) -> Option<TxConfigPropose> {
        let snapshot = self.snapshot();
        let schema = ConfigurationSchema::new(&snapshot);
        schema.get_propose(&config_hash)
    }
}

#[test]
fn test_full_node_to_validator() {
    let mut testkit = TestKitBuilder::auditor()
        .with_validators(3)
        .with_service(ConfigurationService::new())
        .create();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.push(testkit.network().us().clone());
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    testkit.apply_configuration(ValidatorId(1), new_cfg);
}

#[test]
fn test_add_validators_to_config() {
    let mut testkit = TestKitBuilder::validator()
        .with_validators(3)
        .with_service(ConfigurationService::new())
        .create();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.push(TestNode::new_validator(ValidatorId(3)));
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    testkit.apply_configuration(ValidatorId(0), new_cfg);
}

#[test]
fn test_exclude_sandbox_node_from_config() {
    let mut testkit = TestKitBuilder::validator()
        .with_validators(4)
        .with_service(ConfigurationService::new())
        .create();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.pop();
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    testkit.apply_configuration(ValidatorId(0), new_cfg);
}

#[test]
fn test_apply_second_configuration() {
    let mut testkit = TestKitBuilder::validator()
        .with_validators(3)
        .with_service(ConfigurationService::new())
        .create();
    // First configuration.
    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.push(TestNode::new_validator(ValidatorId(3)));
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    testkit.apply_configuration(ValidatorId(0), new_cfg);
    // Second configuration.
    let cfg_change_height = Height(10);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.pop();
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    testkit.apply_configuration(ValidatorId(0), new_cfg);
}

#[test]
fn test_discard_propose_for_same_cfg() {
    let mut testkit: TestKit = TestKit::default();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        cfg.set_actual_from(cfg_change_height);
        cfg.set_service_config("dummy", "First cfg change");
        cfg.stored_configuration().clone()
    };
    let (propose_tx, dublicated_propose_tx) = {
        let validators = testkit.network().validators();
        let propose_tx = new_tx_config_propose(&validators[1], new_cfg.clone());
        let dublicated_propose_tx = new_tx_config_propose(&validators[0], new_cfg.clone());
        (propose_tx, dublicated_propose_tx)
    };

    testkit.create_block_with_transactions(txvec![propose_tx.clone(), dublicated_propose_tx]);
    assert_eq!(Some(propose_tx), testkit.find_propose(new_cfg.hash()));
}

#[test]
fn test_discard_vote_for_absent_propose() {
    let mut testkit: TestKit = TestKit::default();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        cfg.set_service_config("dummy", "First cfg");
        cfg.set_actual_from(cfg_change_height);
        cfg.stored_configuration().clone()
    };
    let absent_cfg = {
        let mut cfg = testkit.actual_configuration();
        cfg.set_service_config("dummy", "Absent propose");
        cfg.set_actual_from(cfg_change_height);
        cfg.stored_configuration().clone()
    };

    let propose_tx = new_tx_config_propose(&testkit.network().validators()[1], new_cfg.clone());
    testkit.create_block_with_transactions(txvec![propose_tx]);

    let legal_vote = new_tx_config_vote(&testkit.network().validators()[3], new_cfg.hash());
    let illegal_vote = new_tx_config_vote(&testkit.network().validators()[3], absent_cfg.hash());
    testkit.create_block_with_transactions(txvec![legal_vote.clone(), illegal_vote.clone()]);

    let votes = testkit.votes_for_propose(new_cfg.hash());
    assert!(votes.contains(&Some(legal_vote)));
    assert!(!votes.contains(&Some(illegal_vote)));
}

#[test]
fn test_discard_proposes_with_expired_actual_from() {
    let mut testkit: TestKit = TestKit::default();

    testkit.create_blocks_until(Height(10));
    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        cfg.set_service_config("dummy", "First cfg");
        cfg.set_actual_from(cfg_change_height);
        cfg.stored_configuration().clone()
    };

    let propose_tx = new_tx_config_propose(&testkit.network().validators()[1], new_cfg.clone());
    testkit.create_block_with_transactions(txvec![propose_tx]);
    assert_eq!(None, testkit.find_propose(new_cfg.hash()));
}

#[test]
fn test_discard_votes_with_expired_actual_from() {
    let mut testkit: TestKit = TestKit::default();

    let cfg_change_height = Height(5);
    let new_cfg = {
        let mut cfg = testkit.actual_configuration();
        cfg.set_service_config("dummy", "First cfg");
        cfg.set_actual_from(cfg_change_height);
        cfg.stored_configuration().clone()
    };

    let propose_tx = new_tx_config_propose(&testkit.network().validators()[1], new_cfg.clone());
    testkit.create_block_with_transactions(txvec![propose_tx]);
    let legal_votes = {
        let validators = testkit.network().validators();
        txvec![
            new_tx_config_vote(&validators[1], new_cfg.hash()),
            new_tx_config_vote(&validators[3], new_cfg.hash()),
        ]
    };
    testkit.create_block_with_transactions(legal_votes);
    testkit.create_blocks_until(Height(10));
    let illegal_vote = new_tx_config_vote(&testkit.network().validators()[0], new_cfg.hash());
    testkit.create_block_with_transactions(txvec![illegal_vote.clone()]);
    assert!(!testkit.votes_for_propose(new_cfg.hash()).contains(&Some(
        illegal_vote,
    )));
}

#[test]
fn test_discard_invalid_config_json() {
    let mut testkit: TestKit = TestKit::default();

    let cfg_bytes = [70; 74];
    str::from_utf8(&cfg_bytes).unwrap(); // invalid json bytes

    let propose_tx = {
        let keypair = testkit.network().validators()[1].service_keypair();
        TxConfigPropose::new(&keypair.0, new_cfg, &keypair.1)
    };
    testkit.create_block_with_transactions(txvec![propose_tx]);
    assert_eq!(None, testkit.find_propose(hash(new_cfg.as_bytes())));
}

// #[test]
// fn test_discard_invalid_config_json() {
//     let (sandbox, sandbox_state, _) = configuration_sandbox();
//     sandbox.assert_state(Height(1), Round::first());
//     let cfg_bytes = [70; 74];
//     let new_cfg = str::from_utf8(&cfg_bytes).unwrap(); // invalid json bytes
//     {
//         let propose_tx = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             new_cfg,
//             sandbox.service_secret_key(ValidatorId(1)),
//         );
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &[propose_tx.raw().clone()]);
//         sandbox.assert_state(Height(2), Round::first());
//         assert_eq!(None, get_propose(&sandbox, hash(new_cfg.as_bytes())));
//     }
// }

// #[test]
// fn test_config_txs_discarded_when_following_config_present() {
//     let (sandbox, sandbox_state, initial_cfg) = configuration_sandbox();
//     sandbox.assert_state(Height(1), Round::first());

//     let following_config = generate_config_with_message(
//         initial_cfg.hash(),
//         Height(6),
//         "Following cfg at height 6",
//         &sandbox,
//     );

//     {
//         let propose_tx = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(following_config.clone().into_bytes().as_slice())
//                 .unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &[propose_tx.raw().clone()]);
//         sandbox.assert_state(Height(2), Round::first());
//         assert_eq!(
//             Some(propose_tx),
//             get_propose(&sandbox, following_config.hash())
//         );
//     }
//     {
//         let votes = (0..3)
//             .map(|validator| {
//                 let validator = ValidatorId(validator);
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &following_config.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone()
//             })
//             .collect::<Vec<_>>();
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &votes);
//         sandbox.assert_state(Height(3), Round::first());
//         assert_eq!(sandbox.cfg(), initial_cfg);
//         assert_eq!(sandbox.following_cfg(), Some(following_config.clone()));
//     }
//     let new_cfg =
//         generate_config_with_message(initial_cfg.hash(), Height(7), "New cfg", &sandbox);

//     {
//         let propose_tx_new = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(new_cfg.clone().into_bytes().as_slice()).unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[propose_tx_new.raw().clone()],
//         );
//         sandbox.assert_state(Height(4), Round::first());

//         assert_eq!(None, get_propose(&sandbox, new_cfg.hash()));
//     }
//     let vote_validator_0 = TxConfigVote::new(
//         &sandbox.service_public_key(ValidatorId::zero()),
//         &following_config.hash(),
//         sandbox.service_secret_key(ValidatorId::zero()),
//     );
//     let vote_validator_3 = TxConfigVote::new(
//         &sandbox.service_public_key(ValidatorId(3)),
//         &following_config.hash(),
//         sandbox.service_secret_key(ValidatorId(3)),
//     );
//     {
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[vote_validator_3.raw().clone()],
//         );
//         sandbox.assert_state(Height(5), Round::first());

//         let votes = get_votes_for_propose(&sandbox, following_config.hash());
//         assert!(votes.contains(&Some(vote_validator_0)));
//         assert!(!votes.contains(&Some(vote_validator_3)));
//         assert_eq!(initial_cfg, sandbox.cfg());
//     }
//     {
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &[]);
//         sandbox.assert_state(Height(6), Round::first());
//         assert_eq!(following_config, sandbox.cfg());
//     }
// }

// #[test]
// fn test_config_txs_discarded_when_not_referencing_actual_config_or_sent_by_illegal_validator() {
//     let (sandbox, sandbox_state, initial_cfg) = configuration_sandbox();
//     sandbox.assert_state(Height(1), Round::first());

//     let new_cfg_bad_previous_cfg = generate_config_with_message(
//         Hash::new([11; HASH_SIZE]),
//         Height(6),
//         "Following cfg at height 6",
//         &sandbox,
//     );
//     // not actual config hash

//     let new_cfg = generate_config_with_message(
//         initial_cfg.hash(),
//         Height(6),
//         "Following cfg at height 6",
//         &sandbox,
//     );
//     let discarded_votes_cfg = generate_config_with_message(
//         initial_cfg.hash(),
//         Height(8),
//         "discarded votes",
//         &sandbox,
//     );

//     let (illegal_pub, illegal_sec) = gen_keypair_from_seed(&Seed::new([66; 32]));

//     {
//         let illegal_propose1 = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(
//                 new_cfg_bad_previous_cfg.clone().into_bytes().as_slice(),
//             ).unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );
//         let illegal_propose2 = TxConfigPropose::new(
//             &illegal_pub,
//             // not a member of actual config
//             str::from_utf8(new_cfg.clone().into_bytes().as_slice()).unwrap(),
//             &illegal_sec,
//         );
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[
//                 illegal_propose1.raw().clone(),
//                 illegal_propose2.raw().clone(),
//             ],
//         );
//         sandbox.assert_state(Height(2), Round::first());
//         assert_eq!(None, get_propose(&sandbox, new_cfg_bad_previous_cfg.hash()));
//         assert_eq!(None, get_propose(&sandbox, new_cfg.hash()));
//     }
//     {
//         let legal_propose1 = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(new_cfg.clone().into_bytes().as_slice()).unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );
//         let legal_propose2 =
//             TxConfigPropose::new(
//                 &sandbox.service_public_key(ValidatorId(1)),
//                 str::from_utf8(discarded_votes_cfg.clone().into_bytes().as_slice()).unwrap(),
//                 sandbox.service_secret_key(ValidatorId(1)),
//             );
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[legal_propose1.raw().clone(), legal_propose2.raw().clone()],
//         );
//         sandbox.assert_state(Height(3), Round::first());
//         assert_eq!(Some(legal_propose1), get_propose(&sandbox, new_cfg.hash()));
//         assert_eq!(
//             Some(legal_propose2),
//             get_propose(&sandbox, discarded_votes_cfg.hash())
//         );
//     }
//     {
//         let illegal_validator_vote =
//             TxConfigVote::new(&illegal_pub, &discarded_votes_cfg.hash(), &illegal_sec);
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[illegal_validator_vote.raw().clone()],
//         );
//         sandbox.assert_state(Height(4), Round::first());
//         let votes = get_votes_for_propose(&sandbox, discarded_votes_cfg.hash());
//         assert!(!votes.contains(&Some(illegal_validator_vote)));
//     }
//     {
//         let votes = (0..3)
//             .map(|validator| {
//                 let validator = ValidatorId(validator);
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &new_cfg.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone()
//             })
//             .collect::<Vec<_>>();
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &votes);
//         sandbox.assert_state(Height(5), Round::first());
//         assert_eq!(initial_cfg, sandbox.cfg());
//         assert_eq!(Some(new_cfg.clone()), sandbox.following_cfg());
//     }
//     {
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &[]);
//         sandbox.assert_state(Height(6), Round::first());
//         assert_eq!(new_cfg, sandbox.cfg());
//         assert_eq!(None, sandbox.following_cfg());
//     }
//     {
//         let expected_votes = (0..3)
//             .map(|validator| {
//                 let validator = ValidatorId(validator);
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &discarded_votes_cfg.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone()
//             })
//             .collect::<Vec<_>>();
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &expected_votes);
//         sandbox.assert_state(Height(7), Round::first());
//         let actual_votes = get_votes_for_propose(&sandbox, discarded_votes_cfg.hash());
//         for raw_vote in expected_votes {
//             let exp_vote = TxConfigVote::from_raw(raw_vote).unwrap();
//             assert!(!actual_votes.contains(&Some(exp_vote)));
//         }
//     }
// }

// /// regression: votes' were summed for all proposes simultaneously, and not for the same propose
// #[test]
// fn test_regression_majority_votes_for_different_proposes() {
//     let (sandbox, sandbox_state, initial_cfg) = configuration_sandbox();
//     sandbox.assert_state(Height(1), Round::first());

//     let actual_from = Height(5);

//     let new_cfg1 =
//         generate_config_with_message(initial_cfg.hash(), actual_from, "First cfg", &sandbox);
//     let new_cfg2 =
//         generate_config_with_message(initial_cfg.hash(), actual_from, "Second cfg", &sandbox);
//     {
//         let mut proposes = Vec::new();
//         for cfg in &[new_cfg1.clone(), new_cfg2.clone()] {
//             proposes.push(
//                 TxConfigPropose::new(
//                     &sandbox.service_public_key(ValidatorId(1)),
//                     str::from_utf8(cfg.clone().into_bytes().as_slice()).unwrap(),
//                     sandbox.service_secret_key(ValidatorId(1)),
//                 ).raw()
//                     .clone(),
//             );
//         }

//         add_one_height_with_transactions(&sandbox, &sandbox_state, &proposes);
//         sandbox.assert_state(Height(2), Round::first());
//     }
//     {
//         let mut votes = Vec::new();
//         for validator in 0..2 {
//             let validator = ValidatorId(validator);
//             votes.push(
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &new_cfg1.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone(),
//             );
//         }

//         add_one_height_with_transactions(&sandbox, &sandbox_state, &votes);
//         sandbox.assert_state(Height(3), Round::first());
//         assert_eq!(initial_cfg, sandbox.cfg());
//     }
//     {
//         let validator_2 = ValidatorId(2);
//         let prop2_validator2 = TxConfigVote::new(
//             &sandbox.service_public_key(validator_2),
//             &new_cfg2.hash(),
//             sandbox.service_secret_key(validator_2),
//         );

//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[prop2_validator2.raw().clone()],
//         );
//         sandbox.assert_state(Height(4), Round::first());
//         assert_eq!(initial_cfg, sandbox.cfg());
//     }
//     {
//         let validator_2 = ValidatorId(2);
//         let prop1_validator2 = TxConfigVote::new(
//             &sandbox.service_public_key(validator_2),
//             &new_cfg1.hash(),
//             sandbox.service_secret_key(validator_2),
//         );

//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[prop1_validator2.raw().clone()],
//         );
//         sandbox.assert_state(Height(5), Round::first());
//         assert_eq!(new_cfg1, sandbox.cfg());
//     }
// }

// #[test]
// fn test_regression_new_vote_for_older_config_applies_old_config() {
//     let (sandbox, sandbox_state, initial_cfg) = configuration_sandbox();
//     sandbox.assert_state(Height(1), Round::first());

//     let new_cfg1 =
//         generate_config_with_message(initial_cfg.hash(), Height(3), "First cfg", &sandbox);
//     let new_cfg2 =
//         generate_config_with_message(new_cfg1.hash(), Height(5), "Second cfg", &sandbox);

//     {
//         let propose_tx1 = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(new_cfg1.clone().into_bytes().as_slice()).unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );

//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[propose_tx1.raw().clone()],
//         );
//         sandbox.assert_state(Height(2), Round::first());
//     }
//     {
//         let mut votes_for_new_cfg1 = Vec::new();
//         for validator in 0..3 {
//             let validator = ValidatorId(validator);
//             votes_for_new_cfg1.push(
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &new_cfg1.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone(),
//             );
//         }
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &votes_for_new_cfg1);
//         sandbox.assert_state(Height(3), Round::first());
//         assert_eq!(new_cfg1, sandbox.cfg());
//     }
//     {
//         let propose_tx2 = TxConfigPropose::new(
//             &sandbox.service_public_key(ValidatorId(1)),
//             str::from_utf8(new_cfg2.clone().into_bytes().as_slice()).unwrap(),
//             sandbox.service_secret_key(ValidatorId(1)),
//         );

//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[propose_tx2.raw().clone()],
//         );
//         sandbox.assert_state(Height(4), Round::first());
//     }
//     {
//         let mut votes_for_new_cfg2 = Vec::new();
//         for validator in 0..3 {
//             let validator = ValidatorId(validator);
//             votes_for_new_cfg2.push(
//                 TxConfigVote::new(
//                     &sandbox.service_public_key(validator),
//                     &new_cfg2.hash(),
//                     sandbox.service_secret_key(validator),
//                 ).raw()
//                     .clone(),
//             );
//         }
//         add_one_height_with_transactions(&sandbox, &sandbox_state, &votes_for_new_cfg2);
//         sandbox.assert_state(Height(5), Round::first());
//         assert_eq!(new_cfg2, sandbox.cfg());
//     }
//     {
//         let validator_3 = ValidatorId(3);
//         let prop1_validator3 = TxConfigVote::new(
//             &sandbox.service_public_key(validator_3),
//             &new_cfg1.hash(),
//             sandbox.service_secret_key(validator_3),
//         );
//         add_one_height_with_transactions(
//             &sandbox,
//             &sandbox_state,
//             &[prop1_validator3.raw().clone()],
//         );
//         sandbox.assert_state(Height(6), Round::first());
//         assert_eq!(new_cfg2, sandbox.cfg());
//     }
// }
