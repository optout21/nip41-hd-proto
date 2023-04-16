# NIP-41 "HD" Key Invalidation Prototype

NIP-41 is a proposal for a scheme whereby a Nostr identity key can be invalidated to a new one safely.
https://github.com/nostr-protocol/nips/pull/450

__WARNING:__ This is a prototype implementation, use it only with test keys!

Previous version of this NIP/proto with custom crypto scheme: https://github.com/catenocrypt/nip41-proto0


## Details

Terms:
- Key state: all predefined keys, plus the index of the currently valid keys
- Level: one element in the set of keys pre-generated iteratively
- Visible, denoted `vis`: the vis (public) part of a level, the key part, denoted e.g. `A`
- Hidden, denoted `hid`: the hid (secret) part of a level, the 'chain code' part, denoted e.g. `A'`

Operations:
- obtain current public key / secret key
- generate new set of keys
- generate next level key set from previous level keys
- invalidate: change current key and return keys needed for verification
- verify: verify validity of new key
- create invalidation Nostr event
- send invalidation event to relay
- listen for invalidation events, verify them

Details:
- As keys are for Nostr (using Schnorr sig), the type `XOnlyPublicKey` is used for pubkeys. This has the drawback that the parity is missing, and in verification both options have to be tried.


## Building and Running

- Prerequisite: `rust`

- Try following commands:

```
cargo build

cargo run generate
cargo run
cargo run inv
cargo run
```

## TODO

-


## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx


## Sample Output

Some (truncated) sample output

generate
```
$ cargo run generate
NIP-41 "HD" Proto

WARNING: This is a prototype implementation, use it only with test keys!

State saved
$ 
$ cargo run
KeyState loaded (256 levels)
Level: 0  (out of 256)
Current pubkey:     	 npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
Previous pubkey:    	 None
Current secret key: 	 nsec1tr2sd..k9xq8n  (58d506857d..f55920)
```

invalidate
```
$ cargo run inv
KeyState loaded (256 levels)
Level: 0  (out of 256)
Current pubkey:     	 npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
Previous pubkey:    	 None
Current secret key: 	 nsec1tr2sd..k9xq8n  (58d506857d..f55920)
Invalidation info:
Invalidated:       	 npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
        new:       	 npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls  (21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00)
     hidden:       	 3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0
Level: 1  (out of 256)
Current pubkey:     	 npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls  (21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00)
Previous pubkey:    	 npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
Current secret key: 	 nsec1p47ht..sddtvy  (0d7d75bea7..6e1bdc)
verify?         	 true
Invalidation event: 
{"content":"key invalidation","created_at":1681419110,"id":"bb57b01956bfab8c3eed5e78039d0b57d545c72c59e7ecb0fcc8450544561992","kind":13,"pubkey":"21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00","sig":"d462c1e62b544bb53eab3a5a35f9aa371fcf3d10cb2102507c8141d999d27b65977647812f5deeeee405e16c699afa4e10987b5506452a3395bec2fdc90a886b","tags":[["p","6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd"],["hidden-key","3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0"]]}

State saved
```

Verify
```
$ cargo run verify npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls 3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0
NIP-41 "HD" Proto

WARNING: This is a prototype implementation, use it only with test keys!

Invalid vis     	 npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
New vis         	 npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls  (21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00)
New hid         	 3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0
Verification result:  true
```

Listen
```
$ cargo run listen ws://umbrel.local:4848

Connected to relay ws://umbrel.local:4848
Subscribed to relay for invalidation events ...


Received event:  {"content":"key invalidation","created_at":1681419379,"id":"26f27fd9882c1b4120bc48e9eab0ab1a81416eb76bdbbe063f1b2c2e0e84c0ca","kind":13,"pubkey":"21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00","sig":"a414659c649071f4fb05e72e69850996d74eefbbd1adba48ef09841568f2e31429c40ab10f85bb02fd5e3907911ca9c238075f440c67631971ea46c5b4d9b1a3","tags":[["p","6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd"],["hidden-key","3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0"]]}
'P-tag' (invalidated):               npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
Pubkey (new):                        npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls  (21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00)
'Hidden-key-tag' (invalidated hid):  3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0

Invalidate  npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  in favor of  npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls !

Verification result: true 


Received event:  {"content":"key invalidation","created_at":1681419385,"id":"d7bd5a85094ea2c75629a795aca7abf617ee5675cb033f158181fff316c5a9ab","kind":13,"pubkey":"21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00","sig":"2f21af29d37456390bfcfd0c2eda66e3eefa29d37085f52d5aabeb603d7621c5ffa985cdfd193a8cc56515d29847a95128122313d8b67b87b58f5cc0ebf95dcb","tags":[["p","6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd"],["hidden-key","3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0"]]}
'P-tag' (invalidated):               npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  (6a123fef0f52b6bd6a188b93f0322f3c828a8815cf83a106816bc343d2e4e5dd)
Pubkey (new):                        npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls  (21fc3830dfe33b679456257c353e0b388a2ce323dfb7d19bc671bd31d0491b00)
'Hidden-key-tag' (invalidated hid):  3e5ea95edb1a94a3c75d822fffd8e3ffefac57a70e967bf3f01efd4222f288c0

Invalidate  npub1dgfrlmc022mt66sc3wflqv308jpg4zq4e7p6zp5pd0p585hyuhwsp75h9a  in favor of  npub1y87rsvxluvak09zky47r20st8z9zecerm7marx7xwx7nr5zfrvqqu4ddls !

Verification result: true
```
