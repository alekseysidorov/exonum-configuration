use std::str;

use exonum_testkit::TestKitBuilder;
use exonum::blockchain::{Transaction, Schema};
use exonum::helpers::Height;
use exonum::storage::StorageValue;

use {ConfigurationService, TxConfigPropose, TxConfigVote};

#[test]
fn test_full_node_to_validator() {
    let cfg_change_height = Height(5);

    let mut testkit = TestKitBuilder::auditor()
        .with_validators(3)
        .with_service(ConfigurationService::new())
        .create();

    let cfg_proposal = {
        let mut cfg = testkit.actual_configuration();
        let mut validators = cfg.validators().to_vec();
        validators.push(testkit.network().us().clone());
        cfg.set_actual_from(cfg_change_height);
        cfg.set_validators(validators);
        cfg.stored_configuration().clone()
    };
    // Push cfg change propose.
    let tx_propose = {
        let keypair = testkit.network().validators()[1].service_keypair();
        Box::new(TxConfigPropose::new(
            keypair.0,
            str::from_utf8(cfg_proposal.clone().into_bytes().as_slice())
                .unwrap(),
            keypair.1,
        ))
    };
    testkit.create_block_with_transactions(vec![tx_propose]);
    // Push votes
    let tx_votes = testkit
        .network()
        .validators()
        .iter()
        .map(|validator| {
            let keypair = validator.service_keypair();
            Box::new(TxConfigVote::new(
                keypair.0,
                &cfg_proposal.hash(),
                keypair.1,
            )) as Box<Transaction>
        })
        .collect::<Vec<_>>();
    testkit.create_block_with_transactions(tx_votes);
    // Fast forward to cfg_change_height
    testkit.create_blocks_until(cfg_change_height);
    assert_eq!(
        Schema::new(&testkit.snapshot()).actual_configuration(),
        cfg_proposal
    );
}
